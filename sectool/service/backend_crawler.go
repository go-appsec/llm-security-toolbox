package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gocolly/colly/v2"

	"github.com/go-harden/llm-security-toolbox/sectool/config"
	"github.com/go-harden/llm-security-toolbox/sectool/service/ids"
	"github.com/go-harden/llm-security-toolbox/sectool/service/store"
)

const (
	// captureIDHeader is used to correlate requests in RoundTrip with OnResponse callbacks
	captureIDHeader = "X-Sectool-Capture-ID"

	crawlStateRunning   = "running"
	crawlStateStopped   = "stopped"
	crawlStateCompleted = "completed"
)

// Compile-time check that CollyBackend implements CrawlerBackend
var _ CrawlerBackend = (*CollyBackend)(nil)

// CollyBackend implements CrawlerBackend using the Colly library.
type CollyBackend struct {
	mu        sync.RWMutex
	sessions  map[string]*crawlSession // by ID
	byLabel   map[string]string        // label -> session ID
	flowStore *store.CrawlFlowStore
	config    *config.CrawlerConfig
	closed    bool

	// For resolving seed flows from proxy history
	proxyFlowStore *store.FlowStore
	httpBackend    HttpBackend
}

// crawlSession holds the state for a single crawl session.
type crawlSession struct {
	info      CrawlSessionInfo
	opts      CrawlOptions
	collector *colly.Collector
	startedAt time.Time

	mu              sync.RWMutex
	flowsByID       map[string]*CrawlFlow // by flow ID for lookup
	flowsOrdered    []*CrawlFlow          // ordered by discovery time
	forms           []DiscoveredForm
	errors          []CrawlError
	urlsSeen        map[string]bool
	urlsQueued      int
	requestCount    int // for MaxRequests enforcement
	lastActivity    time.Time
	lastReturnedIdx int // for --since last feature

	// seedHeaders from resolved seed flows (auth cookies, tokens, etc.)
	// Applied to all requests; can be extended via AddSeeds
	seedHeaders map[string]string

	// Parent URL tracking for FoundOn field
	parentURLs sync.Map // url -> parent_url

	// Capture store for correlating RoundTrip with OnResponse
	captureStore sync.Map // captureID -> *capturedData

	// Precompiled regexes for path filtering
	disallowedRegexes []*regexp.Regexp
	allowedRegexes    []*regexp.Regexp

	ctx    context.Context
	cancel context.CancelFunc
}

// capturedData holds request/response bytes captured in RoundTrip.
type capturedData struct {
	Request      []byte
	RespHeaders  []byte // Response headers (always complete)
	RespBody     []byte // Response body (may be truncated)
	RespBodySize int    // Actual response body size (before truncation)
	Duration     time.Duration
	Truncated    bool
	Error        error
}

// capturingTransport wraps http.RoundTripper to capture raw request/response bytes.
type capturingTransport struct {
	base         http.RoundTripper
	session      *crawlSession
	maxBodyBytes int // 0 or negative = unlimited
}

func (t *capturingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	captureID := req.Header.Get(captureIDHeader)
	req.Header.Del(captureIDHeader) // Remove before sending

	// Capture request bytes
	reqBytes, _ := httputil.DumpRequestOut(req, true)

	start := time.Now()
	resp, err := t.base.RoundTrip(req)
	duration := time.Since(start)

	if err != nil {
		if captureID != "" {
			t.session.captureStore.Store(captureID, &capturedData{
				Request:  reqBytes,
				Error:    err,
				Duration: duration,
			})
		}
		return nil, err
	}

	// Capture response with optional body limit
	respHeaders, respBody, bodySize, truncated := t.captureResponse(resp)

	if captureID != "" {
		t.session.captureStore.Store(captureID, &capturedData{
			Request:      reqBytes,
			RespHeaders:  respHeaders,
			RespBody:     respBody,
			RespBodySize: bodySize,
			Duration:     duration,
			Truncated:    truncated,
		})
	}

	return resp, nil
}

// captureResponse captures response headers and body with optional size limit.
// Returns headers bytes, body bytes (possibly truncated), actual body size, and truncated flag.
func (t *capturingTransport) captureResponse(resp *http.Response) (headers, body []byte, bodySize int, truncated bool) {
	// Capture headers only (body=false)
	headers, _ = httputil.DumpResponse(resp, false)

	// Read body with optional limit
	if resp.Body == nil {
		return headers, nil, 0, false
	}

	if t.maxBodyBytes <= 0 {
		// Unlimited: read entire body
		body, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		bodySize = len(body)
	} else {
		// Limited: read up to limit, count total
		body, bodySize, truncated = readBodyLimited(resp.Body, t.maxBodyBytes)
		_ = resp.Body.Close()
	}

	// Replace body so Colly can read it
	resp.Body = io.NopCloser(bytes.NewReader(body))

	return headers, body, bodySize, truncated
}

// readBodyLimited reads up to limit bytes but counts total size.
// Returns the limited body, actual total size, and whether truncation occurred.
func readBodyLimited(r io.Reader, limit int) ([]byte, int, bool) {
	var buf bytes.Buffer
	buf.Grow(limit)

	// Read up to limit into buffer
	limited := io.LimitReader(r, int64(limit))
	n, _ := buf.ReadFrom(limited)

	// Count remaining bytes by reading and discarding
	remaining, _ := io.Copy(io.Discard, r)
	totalSize := int(n) + int(remaining)
	truncated := remaining > 0

	return buf.Bytes(), totalSize, truncated
}

// NewCollyBackend creates a new Colly-backed CrawlerBackend.
func NewCollyBackend(cfg *config.CrawlerConfig, flowStore *store.CrawlFlowStore, proxyFlowStore *store.FlowStore, httpBackend HttpBackend) *CollyBackend {
	return &CollyBackend{
		sessions:       make(map[string]*crawlSession),
		byLabel:        make(map[string]string),
		flowStore:      flowStore,
		config:         cfg,
		proxyFlowStore: proxyFlowStore,
		httpBackend:    httpBackend,
	}
}

func (b *CollyBackend) CreateSession(ctx context.Context, opts CrawlOptions) (*CrawlSessionInfo, error) {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil, errors.New("backend is closed")
	}

	// Check concurrent session limit
	activeCount := 0
	for _, s := range b.sessions {
		if s.info.State == crawlStateRunning {
			activeCount++
		}
	}
	if activeCount >= b.config.MaxConcurrentSessions {
		b.mu.Unlock()
		return nil, fmt.Errorf("max concurrent sessions (%d) reached; stop an existing session first", b.config.MaxConcurrentSessions)
	}

	// Check label uniqueness
	if opts.Label != "" {
		if existingID, exists := b.byLabel[opts.Label]; exists {
			b.mu.Unlock()
			return nil, fmt.Errorf("%w: label %q already in use by session %s", ErrLabelExists, opts.Label, existingID)
		}
	}
	b.mu.Unlock()

	// Compute allowed domains from seeds
	allowedDomains, seedURLs, seedHeaders, err := b.resolveSeeds(ctx, opts.Seeds, opts.ExplicitDomains)
	if err != nil {
		return nil, err
	}

	if len(allowedDomains) == 0 {
		return nil, errors.New("no valid domains: provide seed URLs, seed flows, or explicit domains")
	}

	// Apply defaults from config
	if len(opts.DisallowedPaths) == 0 {
		opts.DisallowedPaths = b.config.DefaultDisallowedPaths
	}

	sessionCtx, cancel := context.WithCancel(context.Background())

	sessionID := ids.Generate(ids.DefaultLength)

	// Precompile path filter regexes
	disallowedRegexes := globsToRegexes(opts.DisallowedPaths)
	allowedRegexes := globsToRegexes(opts.AllowedPaths)

	sess := &crawlSession{
		info: CrawlSessionInfo{
			ID:        sessionID,
			Label:     opts.Label,
			CreatedAt: time.Now(),
			State:     crawlStateRunning,
		},
		opts:              opts,
		startedAt:         time.Now(),
		flowsByID:         make(map[string]*CrawlFlow),
		urlsSeen:          make(map[string]bool),
		lastActivity:      time.Now(),
		seedHeaders:       seedHeaders,
		disallowedRegexes: disallowedRegexes,
		allowedRegexes:    allowedRegexes,
		ctx:               sessionCtx,
		cancel:            cancel,
	}

	// Create Colly collector
	c := colly.NewCollector(
		colly.Async(true),
		colly.StdlibContext(sessionCtx),
	)

	// Configure allowed domains with subdomain support
	if *b.config.IncludeSubdomains && opts.IncludeSubdomains {
		c.URLFilters = buildDomainFilters(allowedDomains)
	} else {
		c.AllowedDomains = allowedDomains
	}

	if opts.MaxDepth > 0 {
		c.MaxDepth = opts.MaxDepth
	}
	c.DisallowedURLFilters = sess.disallowedRegexes

	if opts.IgnoreRobotsTxt {
		c.IgnoreRobotsTxt = true
	}
	c.UserAgent = config.UserAgent()

	// Rate limiting
	delay := opts.Delay
	if delay == 0 {
		delay = time.Duration(b.config.DefaultDelayMS) * time.Millisecond
	}
	parallelism := opts.Parallelism
	if parallelism == 0 {
		parallelism = b.config.DefaultParallelism
	}
	_ = c.Limit(&colly.LimitRule{
		DomainGlob:  "*",
		Delay:       delay,
		RandomDelay: opts.RandomDelay,
		Parallelism: parallelism,
	})

	// Install capturing transport with body size limit
	transport := &capturingTransport{
		base:         http.DefaultTransport,
		session:      sess,
		maxBodyBytes: b.config.MaxResponseBodyBytes,
	}
	c.WithTransport(transport)

	// Set up request callback for headers and capture ID
	c.OnRequest(func(r *colly.Request) {
		// Check AllowedPaths filter first (before counting)
		if len(sess.allowedRegexes) > 0 {
			path := r.URL.Path
			allowed := false
			for _, re := range sess.allowedRegexes {
				if re.MatchString(path) {
					allowed = true
					break
				}
			}
			if !allowed {
				r.Abort()
				return
			}
		}

		// Check MaxRequests limit and increment counters atomically
		sess.mu.Lock()
		if opts.MaxRequests > 0 && sess.requestCount >= opts.MaxRequests {
			sess.mu.Unlock()
			r.Abort()
			return
		}
		sess.requestCount++
		sess.urlsQueued++
		sess.lastActivity = time.Now()
		sess.mu.Unlock()

		// Generate capture ID for correlation
		captureID := ids.Generate(ids.DefaultLength)
		r.Ctx.Put("capture_id", captureID)
		r.Headers.Set(captureIDHeader, captureID)

		// Get parent URL from stored map, or use "seed" for initial seeds
		parentURL := "seed"
		if p, ok := sess.parentURLs.LoadAndDelete(r.URL.String()); ok {
			parentURL = p.(string)
		}
		r.Ctx.Put("parent_url", parentURL)

		// Apply seed headers first (auth context from resolved flows)
		// These are set before custom headers so user headers can override if needed
		sess.mu.RLock()
		for k, v := range sess.seedHeaders {
			r.Headers.Set(k, v)
		}
		sess.mu.RUnlock()

		// Apply custom headers from options (override seed headers if specified)
		for k, v := range opts.Headers {
			r.Headers.Set(k, v)
		}
	})

	// Response callback for capturing flows
	c.OnResponse(func(r *colly.Response) {
		ct := r.Headers.Get("Content-Type")
		// Filter by content-type (empty is allowed for HTML pages without explicit type)
		if ct != "" && !isAllowedContentType(ct) {
			sess.mu.Lock()
			sess.urlsQueued--
			sess.mu.Unlock()
			return
		}

		captureID := r.Ctx.Get("capture_id")
		if captureID == "" {
			sess.mu.Lock()
			sess.urlsQueued--
			sess.mu.Unlock()
			return
		}

		// Retrieve captured bytes
		captured, ok := sess.captureStore.LoadAndDelete(captureID)
		if !ok {
			sess.mu.Lock()
			sess.urlsQueued--
			sess.mu.Unlock()
			return
		}
		data := captured.(*capturedData)

		// Reassemble response from pre-split headers and body
		respBytes := append(data.RespHeaders, data.RespBody...)

		// Extract host and path from URL
		flowHost := r.Request.URL.Host
		flowPath := r.Request.URL.Path
		if r.Request.URL.RawQuery != "" {
			flowPath += "?" + r.Request.URL.RawQuery
		}

		flowID := ids.Generate(ids.DefaultLength)
		flow := &CrawlFlow{
			ID:             flowID,
			SessionID:      sess.info.ID,
			URL:            r.Request.URL.String(),
			Host:           flowHost,
			Path:           flowPath,
			Method:         r.Request.Method,
			FoundOn:        r.Ctx.Get("parent_url"),
			Depth:          r.Request.Depth,
			StatusCode:     r.StatusCode,
			ContentType:    ct,
			ResponseLength: data.RespBodySize,
			Request:        data.Request,
			Response:       respBytes,
			Truncated:      data.Truncated,
			Duration:       data.Duration,
			DiscoveredAt:   time.Now(),
		}

		sess.mu.Lock()
		sess.flowsByID[flowID] = flow
		sess.flowsOrdered = append(sess.flowsOrdered, flow)
		sess.urlsQueued--
		sess.lastActivity = time.Now()
		sess.mu.Unlock()

		b.flowStore.Register(flowID, sess.info.ID)
	})

	// URL discovery from links
	c.OnHTML("a[href]", func(e *colly.HTMLElement) {
		link := e.Request.AbsoluteURL(e.Attr("href"))
		if link == "" {
			return
		}

		sess.mu.Lock()
		seen := sess.urlsSeen[link]
		if !seen {
			sess.urlsSeen[link] = true
		}
		sess.mu.Unlock()

		if !seen {
			// Store parent URL for this link (will be retrieved in OnRequest)
			sess.parentURLs.Store(link, e.Request.URL.String())
			_ = e.Request.Visit(link)
		}
	})

	// Form extraction - config default, then explicit option override
	extractForms := true
	if b.config.DefaultExtractForms != nil {
		extractForms = *b.config.DefaultExtractForms
	}
	if opts.ExtractForms != nil {
		extractForms = *opts.ExtractForms
	}
	if extractForms {
		c.OnHTML("form", func(e *colly.HTMLElement) {
			form := extractForm(e, sess.info.ID)

			sess.mu.Lock()
			sess.forms = append(sess.forms, form)
			sess.mu.Unlock()

			// Optionally submit form (check against precompiled disallowed regexes)
			if opts.SubmitForms && !matchesAnyRegex(form.Action, sess.disallowedRegexes) {
				formData := extractFormData(e)
				_ = e.Request.Post(form.Action, formData)
			}
		})
	}

	// Error callback
	c.OnError(func(r *colly.Response, err error) {
		// Clean up capture store to prevent memory leak
		if captureID := r.Ctx.Get("capture_id"); captureID != "" {
			sess.captureStore.LoadAndDelete(captureID)
		}

		crawlErr := CrawlError{
			URL:    r.Request.URL.String(),
			Error:  err.Error(),
			Status: r.StatusCode,
		}

		sess.mu.Lock()
		sess.errors = append(sess.errors, crawlErr)
		sess.urlsQueued--
		sess.lastActivity = time.Now()
		sess.mu.Unlock()
	})

	sess.collector = c

	// Register session
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		cancel()
		return nil, errors.New("backend is closed")
	}

	// Ensure ID uniqueness
	for b.sessions[sessionID] != nil {
		sessionID = ids.Generate(ids.DefaultLength)
		sess.info.ID = sessionID
	}

	b.sessions[sessionID] = sess
	if opts.Label != "" {
		b.byLabel[opts.Label] = sessionID
	}
	b.mu.Unlock()

	log.Printf("crawler: created session %s (label=%q) with %d domains", sessionID, opts.Label, len(allowedDomains))

	// Start crawling seeds in background
	go func() {
		for _, seedURL := range seedURLs {
			sess.mu.Lock()
			sess.urlsSeen[seedURL] = true
			sess.mu.Unlock()
			_ = c.Visit(seedURL)
		}

		// Wait for completion
		c.Wait()

		sess.mu.Lock()
		if sess.info.State == crawlStateRunning {
			sess.info.State = crawlStateCompleted
		}
		sess.mu.Unlock()

		log.Printf("crawler: session %s completed", sessionID)
	}()

	return &sess.info, nil
}

func (b *CollyBackend) AddSeeds(ctx context.Context, sessionID string, seeds []CrawlSeed) error {
	sess, err := b.resolveSession(sessionID)
	if err != nil {
		return err
	}

	sess.mu.RLock()
	state := sess.info.State
	sess.mu.RUnlock()

	if state != crawlStateRunning {
		return fmt.Errorf("session %s is not running (state: %s); create a new session instead", sessionID, state)
	}

	_, seedURLs, newHeaders, err := b.resolveSeeds(ctx, seeds, nil)
	if err != nil {
		return err
	}

	// Merge new seed headers into session (new headers don't override existing)
	if len(newHeaders) > 0 {
		sess.mu.Lock()
		if sess.seedHeaders == nil {
			sess.seedHeaders = make(map[string]string)
		}
		for k, v := range newHeaders {
			if _, exists := sess.seedHeaders[k]; !exists {
				sess.seedHeaders[k] = v
			}
		}
		sess.mu.Unlock()
	}

	for _, seedURL := range seedURLs {
		sess.mu.Lock()
		seen := sess.urlsSeen[seedURL]
		if !seen {
			sess.urlsSeen[seedURL] = true
		}
		sess.mu.Unlock()

		if !seen {
			_ = sess.collector.Visit(seedURL)
		}
	}

	log.Printf("crawler: added %d seeds to session %s", len(seedURLs), sessionID)
	return nil
}

func (b *CollyBackend) GetStatus(ctx context.Context, sessionID string) (*CrawlStatus, error) {
	sess, err := b.resolveSession(sessionID)
	if err != nil {
		return nil, err
	}

	sess.mu.RLock()
	defer sess.mu.RUnlock()

	return &CrawlStatus{
		State:           sess.info.State,
		URLsQueued:      sess.urlsQueued,
		URLsVisited:     len(sess.flowsOrdered),
		URLsErrored:     len(sess.errors),
		FormsDiscovered: len(sess.forms),
		Duration:        time.Since(sess.startedAt),
		LastActivity:    sess.lastActivity,
	}, nil
}

func (b *CollyBackend) GetSummary(ctx context.Context, sessionID string) (*CrawlSummary, error) {
	sess, err := b.resolveSession(sessionID)
	if err != nil {
		return nil, err
	}

	sess.mu.RLock()
	defer sess.mu.RUnlock()

	// Aggregate by (host, path, method, status) - same as proxy summary
	type aggregateKey struct {
		Host   string
		Path   string
		Method string
		Status int
	}
	counts := make(map[aggregateKey]int)

	for _, flow := range sess.flowsOrdered {
		key := aggregateKey{
			Host:   flow.Host,
			Path:   normalizePath(flow.Path),
			Method: flow.Method,
			Status: flow.StatusCode,
		}
		counts[key]++
	}

	// Convert to slice and sort by count descending
	aggregates := make([]AggregateEntry, 0, len(counts))
	for key, count := range counts {
		aggregates = append(aggregates, AggregateEntry{
			Host:   key.Host,
			Path:   truncatePath(key.Path, maxPathLength),
			Method: key.Method,
			Status: key.Status,
			Count:  count,
		})
	}

	// Sort by count descending
	slices.SortFunc(aggregates, func(a, b AggregateEntry) int {
		return b.Count - a.Count
	})

	return &CrawlSummary{
		SessionID:  sess.info.ID,
		State:      sess.info.State,
		Duration:   time.Since(sess.startedAt),
		Aggregates: aggregates,
	}, nil
}

func (b *CollyBackend) ListFlows(ctx context.Context, sessionID string, opts CrawlListOptions) ([]CrawlFlow, error) {
	sess, err := b.resolveSession(sessionID)
	if err != nil {
		return nil, err
	}

	sess.mu.Lock()
	defer sess.mu.Unlock()

	// Determine start index based on "since" filter
	startIdx := 0
	if opts.Since != "" {
		if opts.Since == "last" {
			// Use the last returned index (exclusive - start after it)
			startIdx = sess.lastReturnedIdx
		} else {
			// Find flow by ID and start after it
			for i, flow := range sess.flowsOrdered {
				if flow.ID == opts.Since {
					startIdx = i + 1 // exclusive - start after found flow
					break
				}
			}
		}
	}

	// Filter and collect matching flows with their original indices
	type indexedFlow struct {
		flow *CrawlFlow
		idx  int // original index in flowsOrdered
	}
	var filtered []indexedFlow
	for i := startIdx; i < len(sess.flowsOrdered); i++ {
		flow := sess.flowsOrdered[i]
		if matchesFlowFilters(flow, opts) {
			filtered = append(filtered, indexedFlow{flow: flow, idx: i})
		}
	}

	// Apply offset (after filtering)
	if opts.Offset > 0 {
		if opts.Offset >= len(filtered) {
			return []CrawlFlow{}, nil
		}
		filtered = filtered[opts.Offset:]
	}

	// Apply limit
	if opts.Limit > 0 && opts.Limit < len(filtered) {
		filtered = filtered[:opts.Limit]
	}

	// Update lastReturnedIdx based on flows actually returned
	if len(filtered) > 0 {
		// Use the highest original index from flows being returned (+1 for next iteration)
		maxIdx := filtered[len(filtered)-1].idx + 1
		if maxIdx > sess.lastReturnedIdx {
			sess.lastReturnedIdx = maxIdx
		}
	}

	// Copy to result slice
	result := make([]CrawlFlow, len(filtered))
	for i, f := range filtered {
		result[i] = *f.flow
	}

	return result, nil
}

func (b *CollyBackend) ListForms(ctx context.Context, sessionID string, limit int) ([]DiscoveredForm, error) {
	sess, err := b.resolveSession(sessionID)
	if err != nil {
		return nil, err
	}

	sess.mu.RLock()
	defer sess.mu.RUnlock()

	if limit <= 0 || limit > len(sess.forms) {
		result := make([]DiscoveredForm, len(sess.forms))
		copy(result, sess.forms)
		return result, nil
	}
	result := make([]DiscoveredForm, limit)
	copy(result, sess.forms[:limit])
	return result, nil
}

func (b *CollyBackend) ListErrors(ctx context.Context, sessionID string, limit int) ([]CrawlError, error) {
	sess, err := b.resolveSession(sessionID)
	if err != nil {
		return nil, err
	}

	sess.mu.RLock()
	defer sess.mu.RUnlock()

	if limit <= 0 || limit > len(sess.errors) {
		result := make([]CrawlError, len(sess.errors))
		copy(result, sess.errors)
		return result, nil
	}
	result := make([]CrawlError, limit)
	copy(result, sess.errors[:limit])
	return result, nil
}

func (b *CollyBackend) GetFlow(ctx context.Context, flowID string) (*CrawlFlow, error) {
	entry, ok := b.flowStore.Lookup(flowID)
	if !ok {
		return nil, fmt.Errorf("%w: flow %s", ErrNotFound, flowID)
	}

	b.mu.RLock()
	sess, ok := b.sessions[entry.SessionID]
	b.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("%w: flow %s (session expired)", ErrNotFound, flowID)
	}

	sess.mu.RLock()
	flow, ok := sess.flowsByID[flowID]
	sess.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("%w: flow %s", ErrNotFound, flowID)
	}

	flowCopy := *flow
	return &flowCopy, nil
}

func (b *CollyBackend) ExportFlow(ctx context.Context, flowID string, bundleDir string) (*ExportResult, error) {
	flow, err := b.GetFlow(ctx, flowID)
	if err != nil {
		return nil, err
	}

	// Parse URL for metadata
	u, err := url.Parse(flow.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid flow URL: %w", err)
	}

	// Split request into headers and body
	reqHeaders, reqBody := splitHeadersBody(flow.Request)

	// Write bundle
	meta := &bundleMeta{
		BundleID:     flowID,
		SourceFlowID: flowID,
		CapturedAt:   flow.DiscoveredAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
		URL:          flow.URL,
		Method:       flow.Method,
		BodyIsUTF8:   true, // Crawler only stores text content types
		BodySize:     len(reqBody),
	}

	dir := bundleDir + "/" + flowID
	if err := writeBundle(dir, reqHeaders, reqBody, meta); err != nil {
		return nil, fmt.Errorf("failed to write bundle: %w", err)
	}

	// Also write response
	respHeaders, respBody := splitHeadersBody(flow.Response)
	if err := writeResponseToBundle(dir, respHeaders, respBody); err != nil {
		return nil, fmt.Errorf("failed to write response: %w", err)
	}

	files := []string{
		"request.http",
		"body",
		"request.meta.json",
		"response.http",
		"response.body",
	}

	log.Printf("crawler: exported flow %s to %s (url=%s)", flowID, dir, u.String())

	return &ExportResult{
		BundleID:   flowID,
		BundlePath: dir,
		Files:      files,
	}, nil
}

func (b *CollyBackend) StopSession(ctx context.Context, sessionID string) error {
	sess, err := b.resolveSession(sessionID)
	if err != nil {
		return err
	}

	sess.mu.Lock()
	if sess.info.State != crawlStateRunning {
		sess.mu.Unlock()
		return nil // Already stopped
	}
	sess.info.State = crawlStateStopped
	sess.mu.Unlock()

	sess.cancel()
	log.Printf("crawler: stopped session %s", sessionID)
	return nil
}

func (b *CollyBackend) ListSessions(ctx context.Context, limit int) ([]CrawlSessionInfo, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	sessions := make([]CrawlSessionInfo, 0, len(b.sessions))
	for _, sess := range b.sessions {
		sess.mu.RLock()
		sessions = append(sessions, sess.info)
		sess.mu.RUnlock()
	}

	// Sort by creation time descending
	slices.SortFunc(sessions, func(a, b CrawlSessionInfo) int {
		return b.CreatedAt.Compare(a.CreatedAt)
	})

	if limit > 0 && len(sessions) > limit {
		sessions = sessions[:limit]
	}

	return sessions, nil
}

func (b *CollyBackend) Close() error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	b.closed = true

	// Collect all sessions
	sessions := make([]*crawlSession, 0, len(b.sessions))
	for _, sess := range b.sessions {
		sessions = append(sessions, sess)
	}
	b.mu.Unlock()

	// Stop all sessions
	for _, sess := range sessions {
		sess.cancel()
	}

	log.Printf("crawler: closed backend with %d sessions", len(sessions))
	return nil
}

// resolveSession finds a session by ID or label.
func (b *CollyBackend) resolveSession(identifier string) (*crawlSession, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	// Try as ID first
	if sess, ok := b.sessions[identifier]; ok {
		return sess, nil
	}

	// Try as label
	if sessID, ok := b.byLabel[identifier]; ok {
		if sess, ok := b.sessions[sessID]; ok {
			return sess, nil
		}
	}

	return nil, fmt.Errorf("%w: session %s", ErrNotFound, identifier)
}

// resolveSeeds processes seed options and returns allowed domains, seed URLs, and headers.
func (b *CollyBackend) resolveSeeds(ctx context.Context, seeds []CrawlSeed, explicitDomains []string) ([]string, []string, map[string]string, error) {
	domainSet := make(map[string]bool)
	var seedURLs []string
	seedHeaders := make(map[string]string)

	// Add explicit domains
	for _, d := range explicitDomains {
		domainSet[strings.ToLower(d)] = true
	}

	// Process seeds
	for _, seed := range seeds {
		if seed.URL != "" {
			u, err := parseURLWithDefaultHTTPS(seed.URL)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("invalid seed URL %q: %w", seed.URL, err)
			}
			domainSet[strings.ToLower(u.Hostname())] = true
			seedURLs = append(seedURLs, u.String())
		}

		if seed.FlowID != "" {
			entry, ok := b.proxyFlowStore.Lookup(seed.FlowID)
			if !ok {
				return nil, nil, nil, fmt.Errorf("seed flow %q not found in proxy history", seed.FlowID)
			}

			// Fetch the proxy entry to get headers
			proxyEntries, err := b.httpBackend.GetProxyHistory(ctx, 1, entry.Offset)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("failed to fetch seed flow %q: %w", seed.FlowID, err)
			}
			if len(proxyEntries) == 0 {
				return nil, nil, nil, fmt.Errorf("seed flow %q not found in proxy history", seed.FlowID)
			}

			// Extract URL and headers from the request
			method, host, path := extractRequestMeta(proxyEntries[0].Request)
			if host == "" {
				return nil, nil, nil, fmt.Errorf("seed flow %q has no host header", seed.FlowID)
			}

			scheme, _, _ := inferSchemeAndPort(host)
			seedURL := scheme + "://" + host + path
			seedURLs = append(seedURLs, seedURL)
			domainSet[strings.ToLower(strings.Split(host, ":")[0])] = true

			// Extract headers for authenticated context
			headerLines := extractHeaderLines(proxyEntries[0].Request)
			for _, line := range headerLines {
				if idx := strings.Index(line, ":"); idx > 0 {
					name := strings.TrimSpace(line[:idx])
					value := strings.TrimSpace(line[idx+1:])
					// Skip Host header (will be set by Colly) and our internal headers
					nameLower := strings.ToLower(name)
					if nameLower != "host" && nameLower != "content-length" {
						seedHeaders[name] = value
					}
				}
			}

			log.Printf("crawler: resolved seed flow %s -> %s %s", seed.FlowID, method, seedURL)
		}
	}

	// Convert domain set to slice
	domains := make([]string, 0, len(domainSet))
	for d := range domainSet {
		domains = append(domains, d)
	}

	return domains, seedURLs, seedHeaders, nil
}

// Helper functions

func matchesFlowFilters(flow *CrawlFlow, opts CrawlListOptions) bool {
	// Host filter
	if opts.Host != "" && !matchesGlob(flow.Host, opts.Host) {
		return false
	}

	// Path filter
	if opts.PathPattern != "" {
		pathOnly := flow.Path
		if idx := strings.Index(pathOnly, "?"); idx != -1 {
			pathOnly = pathOnly[:idx]
		}
		if !matchesGlob(flow.Path, opts.PathPattern) && !matchesGlob(pathOnly, opts.PathPattern) {
			return false
		}
	}

	// Status filter
	if len(opts.StatusCodes) > 0 {
		found := false
		for _, code := range opts.StatusCodes {
			if flow.StatusCode == code {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Method filter
	if len(opts.Methods) > 0 {
		found := false
		for _, method := range opts.Methods {
			if strings.EqualFold(flow.Method, method) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Exclude host filter
	if opts.ExcludeHost != "" && matchesGlob(flow.Host, opts.ExcludeHost) {
		return false
	}

	// Exclude path filter
	if opts.ExcludePath != "" && matchesGlob(flow.Path, opts.ExcludePath) {
		return false
	}

	// Contains filter (search URL and headers)
	if opts.Contains != "" {
		reqHeaders, _ := splitHeadersBody(flow.Request)
		respHeaders, _ := splitHeadersBody(flow.Response)
		combined := flow.URL + string(reqHeaders) + string(respHeaders)
		if !strings.Contains(combined, opts.Contains) {
			return false
		}
	}

	// Contains body filter (search request/response body)
	if opts.ContainsBody != "" {
		_, reqBody := splitHeadersBody(flow.Request)
		_, respBody := splitHeadersBody(flow.Response)
		combined := string(reqBody) + string(respBody)
		if !strings.Contains(combined, opts.ContainsBody) {
			return false
		}
	}

	return true
}

// Content type filtering
var allowedContentTypes = []string{
	"text/",
	"application/json",
	"application/xml",
	"application/javascript",
	"application/x-javascript",
}

func isAllowedContentType(ct string) bool {
	if ct == "" {
		return true // Allow empty content type (will be filtered later if needed)
	}
	ct = strings.ToLower(ct)
	for _, allowed := range allowedContentTypes {
		if strings.HasPrefix(ct, allowed) {
			return true
		}
	}
	return false
}

// globsToRegexes converts glob patterns to compiled regexes.
func globsToRegexes(patterns []string) []*regexp.Regexp {
	var result []*regexp.Regexp
	for _, p := range patterns {
		escaped := regexp.QuoteMeta(p)
		escaped = strings.ReplaceAll(escaped, `\*`, ".*")
		escaped = strings.ReplaceAll(escaped, `\?`, ".")
		if re, err := regexp.Compile(escaped); err == nil {
			result = append(result, re)
		}
	}
	return result
}

// matchesAnyRegex checks if s matches any of the precompiled regexes.
func matchesAnyRegex(s string, regexes []*regexp.Regexp) bool {
	for _, re := range regexes {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

// buildDomainFilters creates URL filters that match a domain and any subdomains.
// For example, "example.com" matches example.com, sub.example.com, a.b.example.com.
func buildDomainFilters(domains []string) []*regexp.Regexp {
	var filters []*regexp.Regexp
	for _, d := range domains {
		escaped := regexp.QuoteMeta(d)
		// Use ([^/]+\.)* to match zero or more subdomain levels
		pattern := `^https?://(([^/]+\.)*` + escaped + `)(:[0-9]+)?(/|$)`
		if re, err := regexp.Compile(pattern); err == nil {
			filters = append(filters, re)
		}
	}
	return filters
}

// Form extraction helpers
func extractForm(e *colly.HTMLElement, sessionID string) DiscoveredForm {
	action := e.Request.AbsoluteURL(e.Attr("action"))
	if action == "" {
		action = e.Request.URL.String()
	}

	method := strings.ToUpper(e.Attr("method"))
	if method == "" {
		method = "GET"
	}

	form := DiscoveredForm{
		ID:        ids.Generate(ids.DefaultLength),
		SessionID: sessionID,
		URL:       e.Request.URL.String(),
		Action:    action,
		Method:    method,
	}

	e.ForEach("input, select, textarea", func(_ int, el *colly.HTMLElement) {
		name := el.Attr("name")
		if name == "" {
			return
		}

		input := FormInput{
			Name:     name,
			Type:     el.Attr("type"),
			Value:    el.Attr("value"),
			Required: el.Attr("required") != "",
		}

		switch el.Name {
		case "select":
			input.Type = "select"
		case "textarea":
			input.Type = "textarea"
		}

		// Detect CSRF tokens
		nameLower := strings.ToLower(name)
		if strings.Contains(nameLower, "csrf") || strings.Contains(nameLower, "token") ||
			strings.Contains(nameLower, "_token") {
			form.HasCSRF = true
		}

		form.Inputs = append(form.Inputs, input)
	})

	return form
}

func extractFormData(e *colly.HTMLElement) map[string]string {
	data := make(map[string]string)

	e.ForEach("input, select, textarea", func(_ int, el *colly.HTMLElement) {
		name := el.Attr("name")
		if name == "" {
			return
		}

		value := el.Attr("value")
		if el.Name == "textarea" {
			value = el.Text
		}
		// TODO - FUTURE - Handle select elements (get selected option value)

		data[name] = value
	})

	return data
}
