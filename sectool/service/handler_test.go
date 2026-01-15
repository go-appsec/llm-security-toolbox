package service

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// testServerWithMCP creates a test server with mock MCP and returns cleanup func.
// Returns server, mock MCP, and the workDir for creating test files within bounds.
func testServerWithMCP(t *testing.T) (*Server, *TestMCPServer, string) {
	t.Helper()

	mockMCP := NewTestMCPServer(t)
	workDir := t.TempDir()

	srv, err := NewServer(DaemonFlags{
		WorkDir:    workDir,
		BurpMCPURL: mockMCP.URL(),
	})
	require.NoError(t, err)

	// Start server in background
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- srv.Run(t.Context())
	}()
	srv.WaitTillStarted()

	t.Cleanup(func() {
		srv.RequestShutdown()
		<-serverErr
	})

	return srv, mockMCP, workDir
}
