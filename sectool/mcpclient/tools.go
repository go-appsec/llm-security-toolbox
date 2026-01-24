package mcpclient

import (
	"context"
	"time"
)

// ProxySummary calls proxy_summary and returns aggregated traffic summary.
func (c *Client) ProxySummary(ctx context.Context, opts ProxySummaryOpts) (*ProxySummaryResponse, error) {
	args := make(map[string]interface{})
	if opts.Host != "" {
		args["host"] = opts.Host
	}
	if opts.Path != "" {
		args["path"] = opts.Path
	}
	if opts.Method != "" {
		args["method"] = opts.Method
	}
	if opts.Status != "" {
		args["status"] = opts.Status
	}
	if opts.Contains != "" {
		args["contains"] = opts.Contains
	}
	if opts.ContainsBody != "" {
		args["contains_body"] = opts.ContainsBody
	}
	if opts.ExcludeHost != "" {
		args["exclude_host"] = opts.ExcludeHost
	}
	if opts.ExcludePath != "" {
		args["exclude_path"] = opts.ExcludePath
	}

	var resp ProxySummaryResponse
	if err := c.CallToolJSON(ctx, "proxy_summary", args, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ProxyList calls proxy_list and returns individual flows.
func (c *Client) ProxyList(ctx context.Context, opts ProxyListOpts) (*ProxyListResponse, error) {
	args := make(map[string]interface{})
	if opts.Host != "" {
		args["host"] = opts.Host
	}
	if opts.Path != "" {
		args["path"] = opts.Path
	}
	if opts.Method != "" {
		args["method"] = opts.Method
	}
	if opts.Status != "" {
		args["status"] = opts.Status
	}
	if opts.Contains != "" {
		args["contains"] = opts.Contains
	}
	if opts.ContainsBody != "" {
		args["contains_body"] = opts.ContainsBody
	}
	if opts.Since != "" {
		args["since"] = opts.Since
	}
	if opts.ExcludeHost != "" {
		args["exclude_host"] = opts.ExcludeHost
	}
	if opts.ExcludePath != "" {
		args["exclude_path"] = opts.ExcludePath
	}
	if opts.Limit > 0 {
		args["limit"] = opts.Limit
	}
	if opts.Offset > 0 {
		args["offset"] = opts.Offset
	}

	var resp ProxyListResponse
	if err := c.CallToolJSON(ctx, "proxy_list", args, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ProxyGet calls proxy_get and returns full request/response data.
func (c *Client) ProxyGet(ctx context.Context, flowID string) (*ProxyGetResponse, error) {
	args := map[string]interface{}{"flow_id": flowID, "full_body": true}
	var resp ProxyGetResponse
	if err := c.CallToolJSON(ctx, "proxy_get", args, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ProxyRuleList calls proxy_rule_list and returns rules.
func (c *Client) ProxyRuleList(ctx context.Context, typeFilter string, limit int) (*RuleListResponse, error) {
	args := make(map[string]interface{})
	if typeFilter != "" {
		args["type_filter"] = typeFilter
	}
	if limit > 0 {
		args["limit"] = limit
	}

	var resp RuleListResponse
	if err := c.CallToolJSON(ctx, "proxy_rule_list", args, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ProxyRuleAdd calls proxy_rule_add and returns the created rule.
func (c *Client) ProxyRuleAdd(ctx context.Context, opts RuleAddOpts) (*RuleEntry, error) {
	args := map[string]interface{}{
		"type": opts.Type,
	}
	if opts.Match != "" {
		args["match"] = opts.Match
	}
	if opts.Replace != "" {
		args["replace"] = opts.Replace
	}
	if opts.Label != "" {
		args["label"] = opts.Label
	}
	if opts.IsRegex {
		args["is_regex"] = opts.IsRegex
	}

	var resp RuleEntry
	if err := c.CallToolJSON(ctx, "proxy_rule_add", args, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ProxyRuleUpdate calls proxy_rule_update and returns the updated rule.
func (c *Client) ProxyRuleUpdate(ctx context.Context, ruleID string, opts RuleUpdateOpts) (*RuleEntry, error) {
	args := map[string]interface{}{
		"rule_id": ruleID,
		"type":    opts.Type,
	}
	if opts.Match != "" {
		args["match"] = opts.Match
	}
	if opts.Replace != "" {
		args["replace"] = opts.Replace
	}
	if opts.Label != "" {
		args["label"] = opts.Label
	}
	if opts.IsRegex != nil {
		args["is_regex"] = *opts.IsRegex
	}

	var resp RuleEntry
	if err := c.CallToolJSON(ctx, "proxy_rule_update", args, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ProxyRuleDelete calls proxy_rule_delete.
func (c *Client) ProxyRuleDelete(ctx context.Context, ruleID string) error {
	_, err := c.CallTool(ctx, "proxy_rule_delete", map[string]interface{}{"rule_id": ruleID})
	return err
}

// ReplaySend calls replay_send and returns the result.
func (c *Client) ReplaySend(ctx context.Context, opts ReplaySendOpts) (*ReplaySendResponse, error) {
	args := map[string]interface{}{
		"flow_id": opts.FlowID,
	}
	if opts.Body != "" {
		args["body"] = opts.Body
	}
	if opts.Target != "" {
		args["target"] = opts.Target
	}
	if len(opts.AddHeaders) > 0 {
		args["add_headers"] = opts.AddHeaders
	}
	if len(opts.RemoveHeaders) > 0 {
		args["remove_headers"] = opts.RemoveHeaders
	}
	if opts.Path != "" {
		args["path"] = opts.Path
	}
	if opts.Query != "" {
		args["query"] = opts.Query
	}
	if len(opts.SetQuery) > 0 {
		args["set_query"] = opts.SetQuery
	}
	if len(opts.RemoveQuery) > 0 {
		args["remove_query"] = opts.RemoveQuery
	}
	if len(opts.SetJSON) > 0 {
		args["set_json"] = opts.SetJSON
	}
	if len(opts.RemoveJSON) > 0 {
		args["remove_json"] = opts.RemoveJSON
	}
	if opts.FollowRedirects {
		args["follow_redirects"] = opts.FollowRedirects
	}
	if opts.Timeout != "" {
		args["timeout"] = opts.Timeout
	}
	if opts.Force {
		args["force"] = opts.Force
	}

	var resp ReplaySendResponse
	if err := c.CallToolJSON(ctx, "replay_send", args, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ReplayGet calls replay_get and returns full response data.
func (c *Client) ReplayGet(ctx context.Context, replayID string) (*ReplayGetResponse, error) {
	args := map[string]interface{}{"replay_id": replayID, "full_body": true}
	var resp ReplayGetResponse
	if err := c.CallToolJSON(ctx, "replay_get", args, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// RequestSend calls request_send and returns the result.
func (c *Client) RequestSend(ctx context.Context, opts RequestSendOpts) (*ReplaySendResponse, error) {
	args := map[string]interface{}{
		"url": opts.URL,
	}
	if opts.Method != "" {
		args["method"] = opts.Method
	}
	if len(opts.Headers) > 0 {
		args["headers"] = opts.Headers
	}
	if opts.Body != "" {
		args["body"] = opts.Body
	}
	if opts.FollowRedirects {
		args["follow_redirects"] = opts.FollowRedirects
	}
	if opts.Timeout != "" {
		args["timeout"] = opts.Timeout
	}

	var resp ReplaySendResponse
	if err := c.CallToolJSON(ctx, "request_send", args, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// OastCreate calls oast_create and returns the session.
func (c *Client) OastCreate(ctx context.Context, label string) (*OastCreateResponse, error) {
	args := make(map[string]interface{})
	if label != "" {
		args["label"] = label
	}

	var resp OastCreateResponse
	if err := c.CallToolJSON(ctx, "oast_create", args, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// OastPoll calls oast_poll and returns events.
// since: empty returns all, "last" returns since last poll, or an event ID
// eventType: filter by type (dns, http, smtp, ftp, ldap, smb, responder), empty returns all
// wait: how long to block waiting for events (0 = return immediately)
// limit: max events to return (0 = no limit)
func (c *Client) OastPoll(ctx context.Context, oastID, since, eventType string, wait time.Duration, limit int) (*OastPollResponse, error) {
	args := map[string]interface{}{
		"oast_id": oastID,
	}
	if since != "" {
		args["since"] = since
	}
	if eventType != "" {
		args["type"] = eventType
	}
	if wait != 0 {
		args["wait"] = wait.String()
	}
	if limit > 0 {
		args["limit"] = limit
	}

	var resp OastPollResponse
	if err := c.CallToolJSON(ctx, "oast_poll", args, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// OastGet calls oast_get and returns full event data.
func (c *Client) OastGet(ctx context.Context, oastID, eventID string) (*OastGetResponse, error) {
	args := map[string]interface{}{
		"oast_id":  oastID,
		"event_id": eventID,
	}

	var resp OastGetResponse
	if err := c.CallToolJSON(ctx, "oast_get", args, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// OastList calls oast_list and returns sessions.
func (c *Client) OastList(ctx context.Context, limit int) (*OastListResponse, error) {
	args := make(map[string]interface{})
	if limit > 0 {
		args["limit"] = limit
	}

	var resp OastListResponse
	if err := c.CallToolJSON(ctx, "oast_list", args, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// OastDelete calls oast_delete.
func (c *Client) OastDelete(ctx context.Context, oastID string) error {
	_, err := c.CallTool(ctx, "oast_delete", map[string]interface{}{"oast_id": oastID})
	return err
}

// CrawlCreate calls crawl_create and returns the session.
func (c *Client) CrawlCreate(ctx context.Context, opts CrawlCreateOpts) (*CrawlCreateResponse, error) {
	args := make(map[string]interface{})
	if opts.Label != "" {
		args["label"] = opts.Label
	}
	if opts.SeedURLs != "" {
		args["seed_urls"] = opts.SeedURLs
	}
	if opts.SeedFlows != "" {
		args["seed_flows"] = opts.SeedFlows
	}
	if opts.Domains != "" {
		args["domains"] = opts.Domains
	}
	if len(opts.Headers) > 0 {
		args["headers"] = opts.Headers
	}
	if opts.MaxDepth > 0 {
		args["max_depth"] = opts.MaxDepth
	}
	if opts.MaxRequests > 0 {
		args["max_requests"] = opts.MaxRequests
	}
	if opts.Delay != "" {
		args["delay"] = opts.Delay
	}
	if opts.Parallelism > 0 {
		args["parallelism"] = opts.Parallelism
	}
	if opts.IncludeSubdomains != nil {
		args["include_subdomains"] = *opts.IncludeSubdomains
	}
	if opts.SubmitForms {
		args["submit_forms"] = opts.SubmitForms
	}
	if opts.IgnoreRobots {
		args["ignore_robots"] = opts.IgnoreRobots
	}

	var resp CrawlCreateResponse
	if err := c.CallToolJSON(ctx, "crawl_create", args, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// CrawlSeed calls crawl_seed to add seeds to a session.
func (c *Client) CrawlSeed(ctx context.Context, sessionID string, seedURLs, seedFlows string) (*CrawlSeedResponse, error) {
	args := map[string]interface{}{
		"session_id": sessionID,
	}
	if seedURLs != "" {
		args["seed_urls"] = seedURLs
	}
	if seedFlows != "" {
		args["seed_flows"] = seedFlows
	}

	var resp CrawlSeedResponse
	if err := c.CallToolJSON(ctx, "crawl_seed", args, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// CrawlStatus calls crawl_status and returns session status.
func (c *Client) CrawlStatus(ctx context.Context, sessionID string) (*CrawlStatusResponse, error) {
	var resp CrawlStatusResponse
	if err := c.CallToolJSON(ctx, "crawl_status", map[string]interface{}{"session_id": sessionID}, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// CrawlSummary calls crawl_summary and returns aggregated results.
func (c *Client) CrawlSummary(ctx context.Context, sessionID string) (*CrawlSummaryResponse, error) {
	var resp CrawlSummaryResponse
	if err := c.CallToolJSON(ctx, "crawl_summary", map[string]interface{}{"session_id": sessionID}, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// CrawlList calls crawl_list and returns flows, forms, or errors.
func (c *Client) CrawlList(ctx context.Context, sessionID string, opts CrawlListOpts) (*CrawlListResponse, error) {
	args := map[string]interface{}{
		"session_id": sessionID,
	}
	if opts.Type != "" {
		args["type"] = opts.Type
	}
	if opts.Host != "" {
		args["host"] = opts.Host
	}
	if opts.Path != "" {
		args["path"] = opts.Path
	}
	if opts.Method != "" {
		args["method"] = opts.Method
	}
	if opts.Status != "" {
		args["status"] = opts.Status
	}
	if opts.Contains != "" {
		args["contains"] = opts.Contains
	}
	if opts.ContainsBody != "" {
		args["contains_body"] = opts.ContainsBody
	}
	if opts.ExcludeHost != "" {
		args["exclude_host"] = opts.ExcludeHost
	}
	if opts.ExcludePath != "" {
		args["exclude_path"] = opts.ExcludePath
	}
	if opts.Since != "" {
		args["since"] = opts.Since
	}
	if opts.Limit > 0 {
		args["limit"] = opts.Limit
	}
	if opts.Offset > 0 {
		args["offset"] = opts.Offset
	}

	var resp CrawlListResponse
	if err := c.CallToolJSON(ctx, "crawl_list", args, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// CrawlSessions calls crawl_sessions and returns all sessions.
func (c *Client) CrawlSessions(ctx context.Context, limit int) (*CrawlSessionsResponse, error) {
	args := make(map[string]interface{})
	if limit > 0 {
		args["limit"] = limit
	}

	var resp CrawlSessionsResponse
	if err := c.CallToolJSON(ctx, "crawl_sessions", args, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// CrawlStop calls crawl_stop to stop a session.
func (c *Client) CrawlStop(ctx context.Context, sessionID string) error {
	_, err := c.CallTool(ctx, "crawl_stop", map[string]interface{}{"session_id": sessionID})
	return err
}

// CrawlGet calls crawl_get and returns full flow data.
func (c *Client) CrawlGet(ctx context.Context, flowID string) (*CrawlGetResponse, error) {
	args := map[string]interface{}{"flow_id": flowID, "full_body": true}
	var resp CrawlGetResponse
	if err := c.CallToolJSON(ctx, "crawl_get", args, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
