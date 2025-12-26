package service

import (
	"bufio"
	"bytes"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"
)

// extractRequestMeta extracts method, host, path from raw HTTP request.
// Returns empty strings on parse failure.
func extractRequestMeta(raw string) (method, host, path string) {
	lines := strings.SplitN(raw, "\r\n", 2)
	if len(lines) == 0 {
		return "", "", ""
	}

	// Request line: "GET /path HTTP/1.1"
	parts := strings.SplitN(lines[0], " ", 3)
	if len(parts) >= 2 {
		method, path = parts[0], parts[1]
	}

	// Host header (case-insensitive search)
	for _, line := range strings.Split(raw, "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), "host:") {
			host = strings.TrimSpace(line[5:])
			break
		}
	}

	return method, host, path
}

// splitHeadersBody splits raw HTTP at the \r\n\r\n boundary.
func splitHeadersBody(raw []byte) (headers, body []byte) {
	idx := bytes.Index(raw, []byte("\r\n\r\n"))
	if idx < 0 {
		return raw, nil
	}
	return raw[:idx+4], raw[idx+4:] // Include blank line in headers
}

// inferSchemeAndPort determines scheme and port from host string.
// Returns scheme, port, and host without port suffix.
func inferSchemeAndPort(host string) (scheme string, port int, hostOnly string) {
	scheme = "https"
	port = 443
	hostOnly = host

	if idx := strings.LastIndex(host, ":"); idx > 0 {
		portStr := host[idx+1:]
		if p, err := strconv.Atoi(portStr); err == nil {
			port = p
			hostOnly = host[:idx]
			if port == 80 {
				scheme = "http"
			}
		}
	}
	return scheme, port, hostOnly
}

// previewBody returns a UTF-8 safe preview of the body.
// Returns "<BINARY>" for non-UTF-8 content.
func previewBody(body []byte, maxLen int) string {
	if len(body) == 0 {
		return ""
	}
	if !utf8.Valid(body) {
		return "<BINARY>"
	}
	if len(body) <= maxLen {
		return string(body)
	}
	return string(body[:maxLen]) + "..."
}

func readResponseBytes(resp []byte) (*http.Response, error) {
	// Converts "HTTP/2 " to "HTTP/2.0 " since Go's parser requires major.minor format.
	if bytes.HasPrefix(resp, []byte("HTTP/2 ")) {
		resp = append([]byte("HTTP/2.0 "), resp[7:]...)
	}
	return http.ReadResponse(bufio.NewReader(bytes.NewReader(resp)), nil)
}

// extractHeaderLines extracts header lines from raw HTTP request.
// Skips the request line and returns each header as "Name: Value".
func extractHeaderLines(raw string) []string {
	lines := strings.Split(raw, "\r\n")
	if len(lines) <= 1 {
		return nil
	}

	var result []string
	for _, line := range lines[1:] { // skip request line
		if line == "" {
			break // end of headers
		}
		if strings.Contains(line, ":") {
			result = append(result, line)
		}
	}
	return result
}
