package service

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Integration tests for replay handler that require a running Burp Suite instance.
// These tests will skip automatically if Burp is not available.

func TestBurp_ReplayFromFlowID(t *testing.T) {
	srv, cleanup := setupBurpServer(t)
	t.Cleanup(cleanup)

	// Get a flow ID
	w := doTestRequest(t, srv, "POST", "/proxy/list", ProxyListRequest{Method: "GET"})
	require.Equal(t, http.StatusOK, w.Code)

	var listAPIResp APIResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &listAPIResp))

	var listResp ProxyListResponse
	require.NoError(t, json.Unmarshal(listAPIResp.Data, &listResp))

	if len(listResp.Flows) == 0 {
		t.Skip("no proxy history entries available")
	}

	flowID := listResp.Flows[0].FlowID

	// Replay directly from flow ID
	w = doTestRequest(t, srv, "POST", "/replay/send", ReplaySendRequest{FlowID: flowID})

	require.Equal(t, http.StatusOK, w.Code)

	var replayAPIResp APIResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &replayAPIResp))
	require.True(t, replayAPIResp.OK, "replay failed: %v", replayAPIResp.Error)

	var replayResp ReplaySendResponse
	require.NoError(t, json.Unmarshal(replayAPIResp.Data, &replayResp))

	t.Logf("Replay from flow %s: Status=%d, Duration=%s",
		flowID, replayResp.Status, replayResp.Duration)
}

func TestBurp_ReplayWithModifications(t *testing.T) {
	srv, cleanup := setupBurpServer(t)
	t.Cleanup(cleanup)

	// Get a flow ID
	w := doTestRequest(t, srv, "POST", "/proxy/list", ProxyListRequest{Method: "GET"})
	require.Equal(t, http.StatusOK, w.Code)

	var listAPIResp APIResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &listAPIResp))

	var listResp ProxyListResponse
	require.NoError(t, json.Unmarshal(listAPIResp.Data, &listResp))

	if len(listResp.Flows) == 0 {
		t.Skip("no proxy history entries available")
	}

	flowID := listResp.Flows[0].FlowID

	// Replay with header modifications
	w = doTestRequest(t, srv, "POST", "/replay/send", ReplaySendRequest{
		FlowID:        flowID,
		AddHeaders:    []string{"X-Test-Header: sectool-integration-test"},
		RemoveHeaders: []string{"Accept-Encoding"}, // Often present, safe to remove
	})

	require.Equal(t, http.StatusOK, w.Code)

	var replayAPIResp APIResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &replayAPIResp))
	require.True(t, replayAPIResp.OK, "replay with modifications failed: %v", replayAPIResp.Error)

	var replayResp ReplaySendResponse
	require.NoError(t, json.Unmarshal(replayAPIResp.Data, &replayResp))

	t.Logf("Replay with modifications: Status=%d", replayResp.Status)

	assert.NotEmpty(t, replayResp.ReplayID)
}
