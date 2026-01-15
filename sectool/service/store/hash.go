package store

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"slices"
	"sort"
	"strings"
)

// ComputeFlowHash creates a stable identity hash for a request.
// Enables re-identification when Burp history offsets shift.
func ComputeFlowHash(method, host, path string, headers http.Header, body []byte) string {
	// Convert http.Header to sorted header lines for consistent hashing
	headerLines := make([]string, 0, len(headers)*2) // estimate on size
	for key, values := range headers {
		for _, value := range values {
			headerLines = append(headerLines, key+": "+value)
		}
	}
	return computeHash(method, host, path, headerLines, body)
}

// ComputeFlowHashSimple creates a hash from raw request components.
// Useful when headers aren't parsed into http.Header yet.
func ComputeFlowHashSimple(method, host, path string, headerLines []string, body []byte) string {
	return computeHash(method, host, path, headerLines, body)
}

func computeHash(method, host, path string, headerLines []string, body []byte) string {
	h := sha256.New()

	separator := []byte{0}
	h.Write([]byte(strings.ToUpper(method)))
	h.Write(separator)

	h.Write([]byte(strings.ToLower(host)))
	h.Write(separator)

	h.Write([]byte(path)) // Path (as-is, preserving case for path sensitivity)
	h.Write(separator)

	sorted := slices.Clone(headerLines)
	sort.Strings(sorted)
	for _, line := range sorted {
		h.Write([]byte(line))
		h.Write([]byte{'\n'})
	}
	h.Write(separator)

	if len(body) > 0 {
		bodyHash := sha256.Sum256(body)
		h.Write(bodyHash[:])
	}

	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}
