package service

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"path/filepath"
	"time"
	"unicode/utf8"

	"github.com/go-harden/llm-security-toolbox/sectool/service/ids"
)

// FlowGetRequest is the request for POST /flow/get.
type FlowGetRequest struct {
	FlowID string `json:"flow_id"`
}

// FlowGetResponse is the unified response for GET /flow/get.
// Supports both proxy and crawler flows.
type FlowGetResponse struct {
	FlowID            string              `json:"flow_id"`
	Source            string              `json:"source"` // "proxy" or "crawler"
	Method            string              `json:"method"`
	URL               string              `json:"url"`
	ReqHeaders        string              `json:"request_headers"`
	ReqHeadersParsed  map[string][]string `json:"request_headers_parsed,omitempty"`
	ReqBody           string              `json:"request_body"`
	ReqSize           int                 `json:"request_size"`
	Status            int                 `json:"status"`
	StatusLine        string              `json:"status_line"`
	RespHeaders       string              `json:"response_headers"`
	RespHeadersParsed map[string][]string `json:"response_headers_parsed,omitempty"`
	RespBody          string              `json:"response_body"`
	RespSize          int                 `json:"response_size"`
	Truncated         bool                `json:"truncated,omitempty"`
	Duration          string              `json:"duration,omitempty"`
	// Crawler-specific fields
	FoundOn string `json:"found_on,omitempty"`
	Depth   int    `json:"depth,omitempty"`
}

// handleFlowGet handles POST /flow/get - unified lookup for proxy and crawler flows
func (s *Server) handleFlowGet(w http.ResponseWriter, r *http.Request) {
	var req FlowGetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "invalid request body", err.Error())
		return
	}

	if req.FlowID == "" {
		s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "flow_id is required", "")
		return
	}
	if !ids.IsValid(req.FlowID) {
		s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest,
			"invalid flow_id", "flow_id must contain only alphanumeric characters")
		return
	}

	log.Printf("flow/get: looking up flow %s", req.FlowID)

	// Try proxy flowStore first
	if entry, ok := s.flowStore.Lookup(req.FlowID); ok {
		proxyEntries, err := s.httpBackend.GetProxyHistory(r.Context(), 1, entry.Offset)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, ErrCodeBackendError,
				"failed to fetch flow from proxy", err.Error())
			return
		}
		if len(proxyEntries) == 0 {
			s.writeError(w, http.StatusNotFound, ErrCodeNotFound,
				"flow not found in proxy history", "")
			return
		}

		rawReq := []byte(proxyEntries[0].Request)
		rawResp := []byte(proxyEntries[0].Response)
		method, host, path := extractRequestMeta(proxyEntries[0].Request)
		reqHeaders, reqBody := splitHeadersBody(rawReq)
		respHeaders, respBody := splitHeadersBody(rawResp)
		respCode, respStatusLine := parseResponseStatus(respHeaders)
		scheme, _, _ := inferSchemeAndPort(host)
		fullURL := scheme + "://" + host + path

		s.writeJSON(w, http.StatusOK, FlowGetResponse{
			FlowID:            req.FlowID,
			Source:            "proxy",
			Method:            method,
			URL:               fullURL,
			ReqHeaders:        string(reqHeaders),
			ReqHeadersParsed:  parseHeadersToMap(string(reqHeaders)),
			ReqBody:           previewBody(reqBody, fullBodyMaxSize),
			ReqSize:           len(reqBody),
			Status:            respCode,
			StatusLine:        respStatusLine,
			RespHeaders:       string(respHeaders),
			RespHeadersParsed: parseHeadersToMap(string(respHeaders)),
			RespBody:          previewBody(respBody, fullBodyMaxSize),
			RespSize:          len(respBody),
		})
		return
	}

	// Try crawler flowStore
	flow, err := s.crawlerBackend.GetFlow(r.Context(), req.FlowID)
	if err != nil && !errors.Is(err, ErrNotFound) {
		s.writeError(w, http.StatusInternalServerError, ErrCodeBackendError,
			"failed to get flow", err.Error())
		return
	}

	if flow != nil && err == nil {
		reqHeaders, reqBody := splitHeadersBody(flow.Request)
		respHeaders, respBody := splitHeadersBody(flow.Response)
		statusCode, statusLine := parseResponseStatus(respHeaders)

		s.writeJSON(w, http.StatusOK, FlowGetResponse{
			FlowID:            flow.ID,
			Source:            "crawler",
			Method:            flow.Method,
			URL:               flow.URL,
			ReqHeaders:        string(reqHeaders),
			ReqHeadersParsed:  parseHeadersToMap(string(reqHeaders)),
			ReqBody:           previewBody(reqBody, fullBodyMaxSize),
			ReqSize:           len(reqBody),
			Status:            statusCode,
			StatusLine:        statusLine,
			RespHeaders:       string(respHeaders),
			RespHeadersParsed: parseHeadersToMap(string(respHeaders)),
			RespBody:          previewBody(respBody, fullBodyMaxSize),
			RespSize:          len(respBody),
			Truncated:         flow.Truncated,
			Duration:          flow.Duration.Round(time.Millisecond).String(),
			FoundOn:           flow.FoundOn,
			Depth:             flow.Depth,
		})
		return
	}

	s.writeError(w, http.StatusNotFound, ErrCodeNotFound,
		"flow not found", "run 'sectool proxy list' or 'sectool crawl list' to see available flows")
}

// FlowExportRequest is the request for POST /flow/export.
type FlowExportRequest struct {
	FlowID string `json:"flow_id"`
}

// FlowExportResponse is the response for POST /flow/export.
type FlowExportResponse struct {
	BundleID   string   `json:"bundle_id"`
	BundlePath string   `json:"bundle_path"`
	Files      []string `json:"files,omitempty"`
}

// handleFlowExport handles POST /flow/export - unified export for proxy and crawler flows
func (s *Server) handleFlowExport(w http.ResponseWriter, r *http.Request) {
	var req FlowExportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "invalid request body", err.Error())
		return
	}

	if req.FlowID == "" {
		s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "flow_id is required", "")
		return
	}
	if !ids.IsValid(req.FlowID) {
		s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest,
			"invalid flow_id", "flow_id must contain only alphanumeric characters")
		return
	}

	log.Printf("flow/export: exporting flow %s", req.FlowID)
	ctx := r.Context()

	// Try proxy flowStore first
	if entry, ok := s.flowStore.Lookup(req.FlowID); ok {
		proxyEntries, err := s.httpBackend.GetProxyHistory(ctx, 1, entry.Offset)
		if err != nil {
			if IsTimeoutError(err) {
				s.writeError(w, http.StatusGatewayTimeout, ErrCodeTimeout,
					"request timed out fetching flow", err.Error())
			} else {
				s.writeError(w, http.StatusBadGateway, ErrCodeBackendError,
					"failed to fetch flow from proxy", err.Error())
			}
			return
		}
		if len(proxyEntries) == 0 {
			s.writeError(w, http.StatusNotFound, ErrCodeNotFound,
				"flow not found in proxy history", "the flow may have been cleared")
			return
		}

		// Parse request
		method, host, path := extractRequestMeta(proxyEntries[0].Request)
		headers, body := splitHeadersBody([]byte(proxyEntries[0].Request))

		// Use flow_id as bundle_id for simpler mental model (one ID per request)
		// Re-exporting the same flow overwrites, restoring original state
		bundleID := req.FlowID
		bundlePath := filepath.Join(s.paths.RequestsDir, bundleID)

		// Determine scheme from host port
		scheme, _, _ := inferSchemeAndPort(host)
		url := scheme + "://" + host + path

		meta := &bundleMeta{
			BundleID:   bundleID,
			CapturedAt: "",
			URL:        url,
			Method:     method,
			BodyIsUTF8: utf8.Valid(body),
			BodySize:   len(body),
			Notes:      proxyEntries[0].Notes,
		}

		if err := writeBundle(bundlePath, headers, body, meta); err != nil {
			s.writeError(w, http.StatusInternalServerError, ErrCodeInternal, "failed to write bundle", err.Error())
			return
		}

		log.Printf("flow/export: exported proxy flow %s to bundle %s", req.FlowID, bundleID)
		s.writeJSON(w, http.StatusOK, FlowExportResponse{
			BundleID:   bundleID,
			BundlePath: bundlePath,
			Files:      []string{"request.http", "body", "request.meta.json"},
		})
		return
	}

	// Try crawler backend
	result, err := s.crawlerBackend.ExportFlow(ctx, req.FlowID, s.paths.RequestsDir)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			s.writeError(w, http.StatusNotFound, ErrCodeNotFound,
				"flow not found", "run 'sectool proxy list' or 'sectool crawl list' to see available flows")
		} else {
			s.writeError(w, http.StatusInternalServerError, ErrCodeBackendError,
				"failed to export flow", err.Error())
		}
		return
	}

	log.Printf("flow/export: exported crawler flow %s to bundle %s", req.FlowID, result.BundleID)
	s.writeJSON(w, http.StatusOK, FlowExportResponse{
		BundleID:   result.BundleID,
		BundlePath: result.BundlePath,
		Files:      result.Files,
	})
}
