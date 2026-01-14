package crawl

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jentfoo/llm-security-toolbox/sectool/service"
)

func create(timeout time.Duration, urls, flows, domains, headers []string, label string, maxDepth, maxRequests int, delay time.Duration, parallelism int, includeSubdomains, submitForms, ignoreRobots bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	workDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %w", err)
	}

	client := service.NewClient(workDir, service.WithTimeout(timeout))
	if err := client.EnsureService(ctx); err != nil {
		return fmt.Errorf("failed to start service: %w (check %s)", err, client.LogPath())
	}

	var includeSubdomainsPtr *bool
	if !includeSubdomains {
		includeSubdomainsPtr = &includeSubdomains
	}

	var delayStr string
	if delay > 0 {
		delayStr = delay.String()
	}

	// Convert headers slice to map
	var headersMap map[string]string
	if len(headers) > 0 {
		headersMap = make(map[string]string)
		for _, h := range headers {
			if idx := strings.Index(h, ":"); idx > 0 {
				name := strings.TrimSpace(h[:idx])
				value := strings.TrimSpace(h[idx+1:])
				headersMap[name] = value
			}
		}
	}

	resp, err := client.CrawlCreate(ctx, &service.CrawlCreateRequest{
		Label:             label,
		SeedURLs:          urls,
		SeedFlows:         flows,
		Domains:           domains,
		Headers:           headersMap,
		MaxDepth:          maxDepth,
		MaxRequests:       maxRequests,
		Delay:             delayStr,
		Parallelism:       parallelism,
		IncludeSubdomains: includeSubdomainsPtr,
		SubmitForms:       submitForms,
		IgnoreRobots:      ignoreRobots,
	})
	if err != nil {
		return fmt.Errorf("crawl create failed: %w", err)
	}

	fmt.Println("## Crawl Session Created")
	fmt.Println()
	fmt.Printf("Session ID: `%s`\n", resp.SessionID)
	if resp.Label != "" {
		fmt.Printf("Label: `%s`\n", resp.Label)
	}
	fmt.Printf("State: %s\n", resp.State)
	fmt.Printf("Created: %s\n", resp.CreatedAt)
	fmt.Println()

	// Prefer label for status command hint if available
	statusRef := resp.SessionID
	if resp.Label != "" {
		statusRef = resp.Label
	}
	fmt.Printf("To check status: `sectool crawl status %s`\n", statusRef)
	fmt.Printf("To view results: `sectool crawl list %s`\n", statusRef)
	fmt.Printf("To stop: `sectool crawl stop %s`\n", statusRef)

	return nil
}

func seed(timeout time.Duration, sessionID string, urls, flows []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	workDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %w", err)
	}

	client := service.NewClient(workDir, service.WithTimeout(timeout))
	if err := client.EnsureService(ctx); err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}

	resp, err := client.CrawlSeed(ctx, &service.CrawlSeedRequest{
		SessionID: sessionID,
		SeedURLs:  urls,
		SeedFlows: flows,
	})
	if err != nil {
		return fmt.Errorf("crawl seed failed: %w", err)
	}

	fmt.Printf("Added %d seed(s) to session `%s`\n", resp.AddedCount, sessionID)

	return nil
}

func status(timeout time.Duration, sessionID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	workDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %w", err)
	}

	client := service.NewClient(workDir, service.WithTimeout(timeout))
	if err := client.EnsureService(ctx); err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}

	resp, err := client.CrawlStatus(ctx, &service.CrawlStatusRequest{
		SessionID: sessionID,
	})
	if err != nil {
		return fmt.Errorf("crawl status failed: %w", err)
	}

	fmt.Println("## Crawl Status")
	fmt.Println()
	fmt.Printf("- State: **%s**\n", resp.State)
	fmt.Printf("- URLs Queued: %d\n", resp.URLsQueued)
	fmt.Printf("- URLs Visited: %d\n", resp.URLsVisited)
	fmt.Printf("- URLs Errored: %d\n", resp.URLsErrored)
	fmt.Printf("- Forms Discovered: %d\n", resp.FormsDiscovered)
	fmt.Printf("- Duration: %s\n", resp.Duration)
	fmt.Printf("- Last Activity: %s\n", resp.LastActivity)
	if resp.ErrorMessage != "" {
		fmt.Printf("- Error: %s\n", resp.ErrorMessage)
	}

	return nil
}

func summary(timeout time.Duration, sessionID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	workDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %w", err)
	}

	client := service.NewClient(workDir, service.WithTimeout(timeout))
	if err := client.EnsureService(ctx); err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}

	resp, err := client.CrawlSummary(ctx, &service.CrawlSummaryRequest{
		SessionID: sessionID,
	})
	if err != nil {
		return fmt.Errorf("crawl summary failed: %w", err)
	}

	fmt.Println("## Crawl Summary")
	fmt.Println()
	fmt.Printf("Session: `%s` | State: **%s** | Duration: %s\n", resp.SessionID, resp.State, resp.Duration)
	fmt.Println()

	if len(resp.Aggregates) == 0 {
		fmt.Println("No traffic captured.")
		return nil
	}

	fmt.Println("| host | path | method | status | count |")
	fmt.Println("|------|------|--------|--------|-------|")
	for _, agg := range resp.Aggregates {
		fmt.Printf("| %s | %s | %s | %d | %d |\n",
			escapeMarkdown(agg.Host), escapeMarkdown(agg.Path), agg.Method, agg.Status, agg.Count)
	}
	fmt.Printf("\n*%d unique request patterns*\n", len(resp.Aggregates))

	return nil
}

func list(timeout time.Duration, sessionID, listType, host, path, method, status, contains, containsBody, excludeHost, excludePath, since string, limit, offset int) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	workDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %w", err)
	}

	client := service.NewClient(workDir, service.WithTimeout(timeout))
	if err := client.EnsureService(ctx); err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}

	resp, err := client.CrawlList(ctx, &service.CrawlListRequest{
		SessionID:    sessionID,
		Type:         listType,
		Host:         host,
		Path:         path,
		Method:       method,
		Status:       status,
		Contains:     contains,
		ContainsBody: containsBody,
		ExcludeHost:  excludeHost,
		ExcludePath:  excludePath,
		Since:        since,
		Limit:        limit,
		Offset:       offset,
	})
	if err != nil {
		return fmt.Errorf("crawl list failed: %w", err)
	}

	switch listType {
	case "forms":
		if len(resp.Forms) == 0 {
			fmt.Println("No forms discovered.")
			return nil
		}
		for i, form := range resp.Forms {
			if i > 0 {
				fmt.Println()
			}
			fmt.Printf("### Form `%s`\n\n", form.FormID)
			fmt.Printf("- URL: %s\n", form.URL)
			fmt.Printf("- Action: %s\n", form.Action)
			fmt.Printf("- Method: %s\n", form.Method)
			if form.HasCSRF {
				fmt.Println("- CSRF Token: **detected**")
			}
			if len(form.Inputs) > 0 {
				fmt.Println()
				fmt.Println("| Name | Type | Value | Required |")
				fmt.Println("|------|------|-------|----------|")
				for _, inp := range form.Inputs {
					required := ""
					if inp.Required {
						required = "yes"
					}
					fmt.Printf("| %s | %s | %s | %s |\n",
						escapeMarkdown(inp.Name), inp.Type, escapeMarkdown(inp.Value), required)
				}
			}
		}
		fmt.Printf("\n*%d form(s)*\n", len(resp.Forms))

	case "errors":
		if len(resp.Errors) == 0 {
			fmt.Println("No errors encountered.")
			return nil
		}
		fmt.Println("| url | status | error |")
		fmt.Println("|-----|--------|-------|")
		for _, e := range resp.Errors {
			statusStr := ""
			if e.Status > 0 {
				statusStr = strconv.Itoa(e.Status)
			}
			fmt.Printf("| %s | %s | %s |\n",
				escapeMarkdown(e.URL), statusStr, escapeMarkdown(e.Error))
		}
		fmt.Printf("\n*%d error(s)*\n", len(resp.Errors))

	default: // urls
		if len(resp.Flows) == 0 {
			fmt.Println("No flows found.")
			return nil
		}
		fmt.Println("| flow_id | method | host | path | status | size |")
		fmt.Println("|---------|--------|------|------|--------|------|")
		for _, flow := range resp.Flows {
			fmt.Printf("| %s | %s | %s | %s | %d | %d |\n",
				flow.FlowID, flow.Method, escapeMarkdown(flow.Host), escapeMarkdown(flow.Path), flow.Status, flow.ResponseLength)
		}
		fmt.Printf("\n*%d flow(s)*\n", len(resp.Flows))
		if len(resp.Flows) == limit {
			fmt.Printf("\nMore results may be available. Use `--offset %d` to paginate.\n", offset+limit)
		}
		fmt.Printf("\nTo list new flows: `sectool crawl list %s --since last`\n", sessionID)
		fmt.Printf("To export for editing/replay: `sectool crawl export <flow_id>`\n")
	}

	return nil
}

func sessions(timeout time.Duration, limit int) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	workDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %w", err)
	}

	client := service.NewClient(workDir, service.WithTimeout(timeout))
	if err := client.EnsureService(ctx); err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}

	resp, err := client.CrawlSessions(ctx, &service.CrawlSessionsRequest{
		Limit: limit,
	})
	if err != nil {
		return fmt.Errorf("crawl sessions failed: %w", err)
	}

	if len(resp.Sessions) == 0 {
		fmt.Println("No crawl sessions.")
		fmt.Println("\nTo create one: `sectool crawl create --url <url>`")
		return nil
	}

	// Check if any session has a label
	hasLabels := slices.ContainsFunc(resp.Sessions, func(s service.CrawlSessionAPI) bool {
		return s.Label != ""
	})

	if hasLabels {
		fmt.Println("| session_id | label | state | created_at |")
		fmt.Println("|------------|-------|-------|------------|")
		for _, sess := range resp.Sessions {
			fmt.Printf("| %s | %s | %s | %s |\n",
				sess.SessionID, sess.Label, sess.State, sess.CreatedAt)
		}
	} else {
		fmt.Println("| session_id | state | created_at |")
		fmt.Println("|------------|-------|------------|")
		for _, sess := range resp.Sessions {
			fmt.Printf("| %s | %s | %s |\n",
				sess.SessionID, sess.State, sess.CreatedAt)
		}
	}
	fmt.Printf("\n*%d session(s)*\n", len(resp.Sessions))

	return nil
}

func stop(timeout time.Duration, sessionID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	workDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %w", err)
	}

	client := service.NewClient(workDir, service.WithTimeout(timeout))
	if err := client.EnsureService(ctx); err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}

	_, err = client.CrawlStop(ctx, &service.CrawlStopRequest{
		SessionID: sessionID,
	})
	if err != nil {
		return fmt.Errorf("crawl stop failed: %w", err)
	}

	fmt.Printf("Crawl session `%s` stopped.\n", sessionID)

	return nil
}

func escapeMarkdown(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", "")
	return s
}

func export(timeout time.Duration, flowID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	workDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %w", err)
	}

	client := service.NewClient(workDir, service.WithTimeout(timeout))
	if err := client.EnsureService(ctx); err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}

	resp, err := client.FlowExport(ctx, &service.FlowExportRequest{
		FlowID: flowID,
	})
	if err != nil {
		return fmt.Errorf("export failed: %w", err)
	}

	fmt.Printf("## Exported Flow `%s`\n\n", resp.BundleID)
	fmt.Printf("Bundle: `%s`\n\n", resp.BundlePath)
	fmt.Println("Files:")
	for _, f := range resp.Files {
		fmt.Printf("- %s\n", f)
	}
	fmt.Println()
	fmt.Println("To edit and replay:")
	fmt.Printf("  1. Edit `%s/request.http` and `%s/body`\n", resp.BundlePath, resp.BundlePath)
	fmt.Printf("  2. Run: `sectool replay send --bundle %s`\n", resp.BundleID)

	return nil
}
