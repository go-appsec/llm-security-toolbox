package service

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/go-harden/llm-security-toolbox/sectool/service/ids"
)

// =============================================================================
// Crawl Request/Response Types
// =============================================================================

// CrawlCreateRequest is the request for POST /crawl/create.
type CrawlCreateRequest struct {
	Label             string            `json:"label,omitempty"`
	SeedURLs          []string          `json:"seed_urls,omitempty"`
	SeedFlows         []string          `json:"seed_flows,omitempty"`
	Domains           []string          `json:"domains,omitempty"`
	Headers           map[string]string `json:"headers,omitempty"`
	MaxDepth          int               `json:"max_depth,omitempty"`
	MaxRequests       int               `json:"max_requests,omitempty"`
	Delay             string            `json:"delay,omitempty"`
	Parallelism       int               `json:"parallelism,omitempty"`
	IncludeSubdomains *bool             `json:"include_subdomains,omitempty"`
	SubmitForms       bool              `json:"submit_forms,omitempty"`
	IgnoreRobots      bool              `json:"ignore_robots,omitempty"`
}

// CrawlCreateResponse is the response for POST /crawl/create.
type CrawlCreateResponse struct {
	SessionID string `json:"session_id"`
	Label     string `json:"label,omitempty"`
	State     string `json:"state"`
	CreatedAt string `json:"created_at"`
}

// CrawlSeedRequest is the request for POST /crawl/seed.
type CrawlSeedRequest struct {
	SessionID string   `json:"session_id"`
	SeedURLs  []string `json:"seed_urls,omitempty"`
	SeedFlows []string `json:"seed_flows,omitempty"`
}

// CrawlSeedResponse is the response for POST /crawl/seed.
type CrawlSeedResponse struct {
	AddedCount int `json:"added_count"`
}

// CrawlStatusRequest is the request for POST /crawl/status.
type CrawlStatusRequest struct {
	SessionID string `json:"session_id"`
}

// CrawlStatusResponse is the response for POST /crawl/status.
type CrawlStatusResponse struct {
	State           string `json:"state"`
	URLsQueued      int    `json:"urls_queued"`
	URLsVisited     int    `json:"urls_visited"`
	URLsErrored     int    `json:"urls_errored"`
	FormsDiscovered int    `json:"forms_discovered"`
	Duration        string `json:"duration"`
	LastActivity    string `json:"last_activity"`
	ErrorMessage    string `json:"error_message,omitempty"`
}

// CrawlSummaryRequest is the request for POST /crawl/summary.
type CrawlSummaryRequest struct {
	SessionID string `json:"session_id"`
}

// CrawlSummaryResponse is the response for POST /crawl/summary.
// Uses same AggregateEntry format as proxy_summary for consistency.
type CrawlSummaryResponse struct {
	SessionID  string           `json:"session_id"`
	State      string           `json:"state"`
	Duration   string           `json:"duration"`
	Aggregates []AggregateEntry `json:"aggregates"`
}

// CrawlListRequest is the request for POST /crawl/list.
// Mirrors ProxyListRequest filters for consistency.
type CrawlListRequest struct {
	SessionID    string `json:"session_id"`
	Type         string `json:"type,omitempty"` // "urls", "forms", "errors"
	Host         string `json:"host,omitempty"`
	Path         string `json:"path,omitempty"`
	Status       string `json:"status,omitempty"`
	Method       string `json:"method,omitempty"`
	Contains     string `json:"contains,omitempty"`
	ContainsBody string `json:"contains_body,omitempty"`
	ExcludeHost  string `json:"exclude_host,omitempty"`
	ExcludePath  string `json:"exclude_path,omitempty"`
	Since        string `json:"since,omitempty"`
	Limit        int    `json:"limit,omitempty"`
	Offset       int    `json:"offset,omitempty"`
}

// CrawlListResponse is the response for POST /crawl/list.
type CrawlListResponse struct {
	Flows  []CrawlFlowAPI  `json:"flows,omitempty"`
	Forms  []CrawlFormAPI  `json:"forms,omitempty"`
	Errors []CrawlErrorAPI `json:"errors,omitempty"`
}

// CrawlFlowAPI is the API representation of CrawlFlow (summary).
// Mirrors FlowSummary fields for consistency with proxy_list, plus crawler-specific FoundOn.
type CrawlFlowAPI struct {
	FlowID         string `json:"flow_id"`
	Method         string `json:"method"`
	Host           string `json:"host"`
	Path           string `json:"path"`
	Status         int    `json:"status"`
	ResponseLength int    `json:"response_length"`
	Duration       string `json:"duration"`
	FoundOn        string `json:"found_on,omitempty"` // Crawler-specific: parent URL where discovered
}

// CrawlFormAPI is the API representation of DiscoveredForm.
type CrawlFormAPI struct {
	FormID  string         `json:"form_id"`
	URL     string         `json:"url"`
	Action  string         `json:"action"`
	Method  string         `json:"method"`
	HasCSRF bool           `json:"has_csrf"`
	Inputs  []FormInputAPI `json:"inputs"`
}

// FormInputAPI is the API representation of FormInput.
type FormInputAPI struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Value    string `json:"value,omitempty"`
	Required bool   `json:"required,omitempty"`
}

// CrawlErrorAPI is the API representation of CrawlError.
type CrawlErrorAPI struct {
	URL    string `json:"url"`
	Status int    `json:"status,omitempty"`
	Error  string `json:"error"`
}

// formsToAPI converts DiscoveredForm slice to API format.
func formsToAPI(forms []DiscoveredForm) []CrawlFormAPI {
	result := make([]CrawlFormAPI, 0, len(forms))
	for _, f := range forms {
		inputs := make([]FormInputAPI, 0, len(f.Inputs))
		for _, inp := range f.Inputs {
			inputs = append(inputs, FormInputAPI(inp))
		}
		result = append(result, CrawlFormAPI{
			FormID:  f.ID,
			URL:     f.URL,
			Action:  f.Action,
			Method:  f.Method,
			HasCSRF: f.HasCSRF,
			Inputs:  inputs,
		})
	}
	return result
}

// CrawlSessionsRequest is the request for POST /crawl/sessions.
type CrawlSessionsRequest struct {
	Limit int `json:"limit,omitempty"`
}

// CrawlSessionsResponse is the response for POST /crawl/sessions.
type CrawlSessionsResponse struct {
	Sessions []CrawlSessionAPI `json:"sessions"`
}

// CrawlSessionAPI is the API representation of CrawlSessionInfo.
type CrawlSessionAPI struct {
	SessionID string `json:"session_id"`
	Label     string `json:"label,omitempty"`
	State     string `json:"state"`
	CreatedAt string `json:"created_at"`
}

// CrawlStopRequest is the request for POST /crawl/stop.
type CrawlStopRequest struct {
	SessionID string `json:"session_id"`
}

// CrawlStopResponse is the response for POST /crawl/stop.
type CrawlStopResponse struct {
	Stopped bool `json:"stopped"`
}

// =============================================================================
// HTTP Handlers
// =============================================================================

// handleCrawlCreate handles POST /crawl/create
func (s *Server) handleCrawlCreate(w http.ResponseWriter, r *http.Request) {
	var req CrawlCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "invalid request body", err.Error())
		return
	}

	// Validate seed flow IDs (alphanumeric only)
	for _, f := range req.SeedFlows {
		if !ids.IsValid(f) {
			s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest,
				"invalid seed_flow", "seed_flows must contain only alphanumeric characters")
			return
		}
	}

	// Build seeds
	seeds := make([]CrawlSeed, 0, len(req.SeedURLs)+len(req.SeedFlows))
	for _, u := range req.SeedURLs {
		seeds = append(seeds, CrawlSeed{URL: u})
	}
	for _, f := range req.SeedFlows {
		seeds = append(seeds, CrawlSeed{FlowID: f})
	}

	// Parse delay
	var delay time.Duration
	if req.Delay != "" {
		var err error
		delay, err = time.ParseDuration(req.Delay)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "invalid delay format", err.Error())
			return
		}
	}

	includeSubdomains := true
	if req.IncludeSubdomains != nil {
		includeSubdomains = *req.IncludeSubdomains
	}

	opts := CrawlOptions{
		Label:             req.Label,
		Seeds:             seeds,
		ExplicitDomains:   req.Domains,
		IncludeSubdomains: includeSubdomains,
		MaxDepth:          req.MaxDepth,
		MaxRequests:       req.MaxRequests,
		Delay:             delay,
		Parallelism:       req.Parallelism,
		IgnoreRobotsTxt:   req.IgnoreRobots,
		SubmitForms:       req.SubmitForms,
		Headers:           req.Headers,
		// ExtractForms left nil to use config default
	}

	log.Printf("crawl/create: creating session (label=%q, seeds=%d, domains=%d)",
		req.Label, len(seeds), len(req.Domains))

	sess, err := s.crawlerBackend.CreateSession(r.Context(), opts)
	if err != nil {
		if errors.Is(err, ErrLabelExists) {
			s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest,
				"failed to create crawl session", err.Error())
		} else {
			s.writeError(w, http.StatusInternalServerError, ErrCodeBackendError,
				"failed to create crawl session", err.Error())
		}
		return
	}

	s.writeJSON(w, http.StatusOK, CrawlCreateResponse{
		SessionID: sess.ID,
		Label:     sess.Label,
		State:     sess.State,
		CreatedAt: sess.CreatedAt.UTC().Format(time.RFC3339),
	})
}

// handleCrawlSeed handles POST /crawl/seed
func (s *Server) handleCrawlSeed(w http.ResponseWriter, r *http.Request) {
	var req CrawlSeedRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "invalid request body", err.Error())
		return
	}

	if req.SessionID == "" {
		s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "session_id is required", "")
		return
	}

	// Validate seed flow IDs (alphanumeric only)
	for _, f := range req.SeedFlows {
		if !ids.IsValid(f) {
			s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest,
				"invalid seed_flow", "seed_flows must contain only alphanumeric characters")
			return
		}
	}

	seeds := make([]CrawlSeed, 0, len(req.SeedURLs)+len(req.SeedFlows))
	for _, u := range req.SeedURLs {
		seeds = append(seeds, CrawlSeed{URL: u})
	}
	for _, f := range req.SeedFlows {
		seeds = append(seeds, CrawlSeed{FlowID: f})
	}

	if len(seeds) == 0 {
		s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest,
			"at least one seed_url or seed_flow is required", "")
		return
	}

	log.Printf("crawl/seed: adding %d seeds to session %s", len(seeds), req.SessionID)

	if err := s.crawlerBackend.AddSeeds(r.Context(), req.SessionID, seeds); err != nil {
		if errors.Is(err, ErrNotFound) {
			s.writeError(w, http.StatusNotFound, ErrCodeNotFound, "session not found", err.Error())
		} else {
			s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest,
				"failed to add seeds", err.Error())
		}
		return
	}

	s.writeJSON(w, http.StatusOK, CrawlSeedResponse{AddedCount: len(seeds)})
}

// handleCrawlStatus handles POST /crawl/status
func (s *Server) handleCrawlStatus(w http.ResponseWriter, r *http.Request) {
	var req CrawlStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "invalid request body", err.Error())
		return
	}

	if req.SessionID == "" {
		s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "session_id is required", "")
		return
	}

	log.Printf("crawl/status: getting status for session %s", req.SessionID)

	status, err := s.crawlerBackend.GetStatus(r.Context(), req.SessionID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			s.writeError(w, http.StatusNotFound, ErrCodeNotFound, "session not found", err.Error())
		} else {
			s.writeError(w, http.StatusInternalServerError, ErrCodeBackendError,
				"failed to get status", err.Error())
		}
		return
	}

	s.writeJSON(w, http.StatusOK, CrawlStatusResponse{
		State:           status.State,
		URLsQueued:      status.URLsQueued,
		URLsVisited:     status.URLsVisited,
		URLsErrored:     status.URLsErrored,
		FormsDiscovered: status.FormsDiscovered,
		Duration:        status.Duration.Round(time.Millisecond).String(),
		LastActivity:    status.LastActivity.UTC().Format(time.RFC3339),
		ErrorMessage:    status.ErrorMessage,
	})
}

// handleCrawlSummary handles POST /crawl/summary
func (s *Server) handleCrawlSummary(w http.ResponseWriter, r *http.Request) {
	var req CrawlSummaryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "invalid request body", err.Error())
		return
	}

	if req.SessionID == "" {
		s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "session_id is required", "")
		return
	}

	log.Printf("crawl/summary: getting summary for session %s", req.SessionID)

	summary, err := s.crawlerBackend.GetSummary(r.Context(), req.SessionID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			s.writeError(w, http.StatusNotFound, ErrCodeNotFound, "session not found", err.Error())
		} else {
			s.writeError(w, http.StatusInternalServerError, ErrCodeBackendError,
				"failed to get summary", err.Error())
		}
		return
	}

	s.writeJSON(w, http.StatusOK, CrawlSummaryResponse{
		SessionID:  summary.SessionID,
		State:      summary.State,
		Duration:   summary.Duration.Round(time.Millisecond).String(),
		Aggregates: summary.Aggregates,
	})
}

// handleCrawlList handles POST /crawl/list
func (s *Server) handleCrawlList(w http.ResponseWriter, r *http.Request) {
	var req CrawlListRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "invalid request body", err.Error())
		return
	}

	if req.SessionID == "" {
		s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "session_id is required", "")
		return
	}

	log.Printf("crawl/list: listing %s for session %s (limit=%d)", req.Type, req.SessionID, req.Limit)

	ctx := r.Context()

	switch req.Type {
	case "forms":
		forms, err := s.crawlerBackend.ListForms(ctx, req.SessionID, req.Limit)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				s.writeError(w, http.StatusNotFound, ErrCodeNotFound, "session not found", err.Error())
			} else {
				s.writeError(w, http.StatusInternalServerError, ErrCodeBackendError, "failed to list forms", err.Error())
			}
			return
		}

		s.writeJSON(w, http.StatusOK, CrawlListResponse{Forms: formsToAPI(forms)})

	case "errors":
		errs, err := s.crawlerBackend.ListErrors(ctx, req.SessionID, req.Limit)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				s.writeError(w, http.StatusNotFound, ErrCodeNotFound, "session not found", err.Error())
			} else {
				s.writeError(w, http.StatusInternalServerError, ErrCodeBackendError, "failed to list errors", err.Error())
			}
			return
		}

		apiErrors := make([]CrawlErrorAPI, 0, len(errs))
		for _, e := range errs {
			apiErrors = append(apiErrors, CrawlErrorAPI{
				URL:    e.URL,
				Status: e.Status,
				Error:  e.Error,
			})
		}
		s.writeJSON(w, http.StatusOK, CrawlListResponse{Errors: apiErrors})

	default: // "urls" or empty
		opts := CrawlListOptions{
			Host:         req.Host,
			PathPattern:  req.Path,
			StatusCodes:  parseStatusCodes(req.Status),
			Methods:      parseCommaSeparated(req.Method),
			Contains:     req.Contains,
			ContainsBody: req.ContainsBody,
			ExcludeHost:  req.ExcludeHost,
			ExcludePath:  req.ExcludePath,
			Since:        req.Since,
			Limit:        req.Limit,
			Offset:       req.Offset,
		}

		flows, err := s.crawlerBackend.ListFlows(ctx, req.SessionID, opts)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				s.writeError(w, http.StatusNotFound, ErrCodeNotFound, "session not found", err.Error())
			} else {
				s.writeError(w, http.StatusInternalServerError, ErrCodeBackendError, "failed to list flows", err.Error())
			}
			return
		}

		var apiFlows []CrawlFlowAPI
		for _, f := range flows {
			apiFlows = append(apiFlows, CrawlFlowAPI{
				FlowID:         f.ID,
				Method:         f.Method,
				Host:           f.Host,
				Path:           f.Path,
				Status:         f.StatusCode,
				ResponseLength: f.ResponseLength,
				Duration:       f.Duration.Round(time.Millisecond).String(),
				FoundOn:        f.FoundOn,
			})
		}
		s.writeJSON(w, http.StatusOK, CrawlListResponse{Flows: apiFlows})
	}
}

// handleCrawlSessions handles POST /crawl/sessions
func (s *Server) handleCrawlSessions(w http.ResponseWriter, r *http.Request) {
	var req CrawlSessionsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "invalid request body", err.Error())
		return
	}

	log.Printf("crawl/sessions: listing sessions (limit=%d)", req.Limit)

	sessions, err := s.crawlerBackend.ListSessions(r.Context(), req.Limit)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, ErrCodeBackendError,
			"failed to list sessions", err.Error())
		return
	}

	apiSessions := make([]CrawlSessionAPI, 0, len(sessions))
	for _, sess := range sessions {
		apiSessions = append(apiSessions, CrawlSessionAPI{
			SessionID: sess.ID,
			Label:     sess.Label,
			State:     sess.State,
			CreatedAt: sess.CreatedAt.UTC().Format(time.RFC3339),
		})
	}

	s.writeJSON(w, http.StatusOK, CrawlSessionsResponse{Sessions: apiSessions})
}

// handleCrawlStop handles POST /crawl/stop
func (s *Server) handleCrawlStop(w http.ResponseWriter, r *http.Request) {
	var req CrawlStopRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "invalid request body", err.Error())
		return
	}

	if req.SessionID == "" {
		s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "session_id is required", "")
		return
	}

	log.Printf("crawl/stop: stopping session %s", req.SessionID)

	if err := s.crawlerBackend.StopSession(r.Context(), req.SessionID); err != nil {
		if errors.Is(err, ErrNotFound) {
			s.writeError(w, http.StatusNotFound, ErrCodeNotFound, "session not found", err.Error())
		} else {
			s.writeError(w, http.StatusInternalServerError, ErrCodeBackendError,
				"failed to stop session", err.Error())
		}
		return
	}

	s.writeJSON(w, http.StatusOK, CrawlStopResponse{Stopped: true})
}
