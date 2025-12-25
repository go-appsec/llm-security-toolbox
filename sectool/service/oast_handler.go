package service

import (
	"encoding/json"
	"net/http"
	"time"
)

// handleOastCreate handles POST /oast/create
func (s *Server) handleOastCreate(w http.ResponseWriter, r *http.Request) {
	sess, err := s.oastBackend.CreateSession(r.Context())
	if err != nil {
		if IsTimeoutError(err) {
			s.writeError(w, http.StatusGatewayTimeout, ErrCodeTimeout,
				"OAST session creation timed out", err.Error())
		} else {
			s.writeError(w, http.StatusInternalServerError, ErrCodeBackendError,
				"failed to create OAST session", err.Error())
		}
		return
	}

	resp := OastCreateResponse{
		OastID:   sess.ID,
		Domain:   sess.Domain,
		Examples: sess.Examples,
	}
	s.writeJSON(w, http.StatusOK, resp)
}

// handleOastPoll handles POST /oast/poll
func (s *Server) handleOastPoll(w http.ResponseWriter, r *http.Request) {
	var req OastPollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "invalid request body", err.Error())
		return
	} else if req.OastID == "" {
		s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "oast_id is required", "")
		return
	}

	// Parse wait duration
	var wait time.Duration
	var err error
	if req.Wait != "" {
		wait, err = time.ParseDuration(req.Wait)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "invalid wait duration", err.Error())
			return
		}
		// Cap at 120 seconds
		if wait > 120*time.Second {
			wait = 120 * time.Second
		}
	}

	result, err := s.oastBackend.PollSession(r.Context(), req.OastID, req.Since, wait)
	if err != nil {
		s.writeError(w, http.StatusNotFound, ErrCodeNotFound, "session not found or deleted", err.Error())
		return
	}

	// Convert internal events to API response
	events := make([]OastEvent, len(result.Events))
	for i, e := range result.Events {
		events[i] = OastEvent{
			EventID:   e.ID,
			Time:      e.Time.UTC().Format(time.RFC3339),
			Type:      e.Type,
			SourceIP:  e.SourceIP,
			Subdomain: e.Subdomain,
			Details:   e.Details,
		}
	}

	resp := OastPollResponse{
		Events:       events,
		DroppedCount: result.DroppedCount,
	}
	s.writeJSON(w, http.StatusOK, resp)
}

// handleOastList handles POST /oast/list
func (s *Server) handleOastList(w http.ResponseWriter, r *http.Request) {
	sessions, err := s.oastBackend.ListSessions(r.Context())
	if err != nil {
		if IsTimeoutError(err) {
			s.writeError(w, http.StatusGatewayTimeout, ErrCodeTimeout,
				"OAST session list timed out", err.Error())
		} else {
			s.writeError(w, http.StatusInternalServerError, ErrCodeBackendError,
				"failed to list OAST sessions", err.Error())
		}
		return
	}

	// Convert internal sessions to API response
	apiSessions := make([]OastSession, len(sessions))
	for i, sess := range sessions {
		apiSessions[i] = OastSession{
			OastID:    sess.ID,
			Domain:    sess.Domain,
			CreatedAt: sess.CreatedAt.UTC().Format(time.RFC3339),
		}
	}

	resp := OastListResponse{
		Sessions: apiSessions,
	}
	s.writeJSON(w, http.StatusOK, resp)
}

// handleOastDelete handles POST /oast/delete
func (s *Server) handleOastDelete(w http.ResponseWriter, r *http.Request) {
	var req OastDeleteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "invalid request body", err.Error())
		return
	} else if req.OastID == "" {
		s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "oast_id is required", "")
		return
	} else if err := s.oastBackend.DeleteSession(r.Context(), req.OastID); err != nil {
		s.writeError(w, http.StatusNotFound, ErrCodeNotFound, "session not found", err.Error())
		return
	}

	s.writeJSON(w, http.StatusOK, OastDeleteResponse{})
}
