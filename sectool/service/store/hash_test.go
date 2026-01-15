package store

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestComputeFlowHash(t *testing.T) {
	t.Parallel()

	t.Run("same_request_same_hash", func(t *testing.T) {
		headers := http.Header{
			"Content-Type": []string{"application/json"},
			"Accept":       []string{"*/*"},
		}
		body := []byte(`{"key": "value"}`)

		hash1 := ComputeFlowHash("GET", "example.com", "/api/users", headers, body)
		hash2 := ComputeFlowHash("GET", "example.com", "/api/users", headers, body)

		assert.Equal(t, hash1, hash2)
		assert.Contains(t, hash1, "sha256:")
	})

	t.Run("different_method_different_hash", func(t *testing.T) {
		headers := http.Header{}
		hash1 := ComputeFlowHash("GET", "example.com", "/api", headers, nil)
		hash2 := ComputeFlowHash("POST", "example.com", "/api", headers, nil)

		assert.NotEqual(t, hash1, hash2)
	})

	t.Run("different_host_different_hash", func(t *testing.T) {
		headers := http.Header{}
		hash1 := ComputeFlowHash("GET", "example.com", "/api", headers, nil)
		hash2 := ComputeFlowHash("GET", "other.com", "/api", headers, nil)

		assert.NotEqual(t, hash1, hash2)
	})

	t.Run("different_path_different_hash", func(t *testing.T) {
		headers := http.Header{}
		hash1 := ComputeFlowHash("GET", "example.com", "/api/v1", headers, nil)
		hash2 := ComputeFlowHash("GET", "example.com", "/api/v2", headers, nil)

		assert.NotEqual(t, hash1, hash2)
	})

	t.Run("different_headers_different_hash", func(t *testing.T) {
		headers1 := http.Header{"X-Custom": []string{"value1"}}
		headers2 := http.Header{"X-Custom": []string{"value2"}}

		hash1 := ComputeFlowHash("GET", "example.com", "/api", headers1, nil)
		hash2 := ComputeFlowHash("GET", "example.com", "/api", headers2, nil)

		assert.NotEqual(t, hash1, hash2)
	})

	t.Run("different_body_different_hash", func(t *testing.T) {
		headers := http.Header{}
		hash1 := ComputeFlowHash("POST", "example.com", "/api", headers, []byte("body1"))
		hash2 := ComputeFlowHash("POST", "example.com", "/api", headers, []byte("body2"))

		assert.NotEqual(t, hash1, hash2)
	})

	t.Run("method_case_insensitive", func(t *testing.T) {
		headers := http.Header{}
		hash1 := ComputeFlowHash("GET", "example.com", "/api", headers, nil)
		hash2 := ComputeFlowHash("get", "example.com", "/api", headers, nil)

		assert.Equal(t, hash1, hash2)
	})

	t.Run("host_case_insensitive", func(t *testing.T) {
		headers := http.Header{}
		hash1 := ComputeFlowHash("GET", "Example.COM", "/api", headers, nil)
		hash2 := ComputeFlowHash("GET", "example.com", "/api", headers, nil)

		assert.Equal(t, hash1, hash2)
	})

	t.Run("path_case_sensitive", func(t *testing.T) {
		headers := http.Header{}
		hash1 := ComputeFlowHash("GET", "example.com", "/API", headers, nil)
		hash2 := ComputeFlowHash("GET", "example.com", "/api", headers, nil)

		assert.NotEqual(t, hash1, hash2)
	})

	t.Run("header_order_independent", func(t *testing.T) {
		headers1 := http.Header{
			"A-Header": []string{"first"},
			"B-Header": []string{"second"},
		}
		headers2 := http.Header{
			"B-Header": []string{"second"},
			"A-Header": []string{"first"},
		}

		hash1 := ComputeFlowHash("GET", "example.com", "/api", headers1, nil)
		hash2 := ComputeFlowHash("GET", "example.com", "/api", headers2, nil)

		assert.Equal(t, hash1, hash2)
	})

	t.Run("empty_body_vs_no_body", func(t *testing.T) {
		headers := http.Header{}
		hash1 := ComputeFlowHash("GET", "example.com", "/api", headers, nil)
		hash2 := ComputeFlowHash("GET", "example.com", "/api", headers, []byte{})

		// Both should be the same since empty body is treated as empty
		assert.Equal(t, hash1, hash2)
	})
}

func TestComputeFlowHashSimple(t *testing.T) {
	t.Parallel()

	t.Run("same_request_same_hash", func(t *testing.T) {
		headers := []string{"Content-Type: application/json", "Accept: */*"}
		body := []byte(`{"key": "value"}`)

		hash1 := ComputeFlowHashSimple("GET", "example.com", "/api/users", headers, body)
		hash2 := ComputeFlowHashSimple("GET", "example.com", "/api/users", headers, body)

		assert.Equal(t, hash1, hash2)
	})

	t.Run("header_order_independent", func(t *testing.T) {
		headers1 := []string{"A-Header: first", "B-Header: second"}
		headers2 := []string{"B-Header: second", "A-Header: first"}

		hash1 := ComputeFlowHashSimple("GET", "example.com", "/api", headers1, nil)
		hash2 := ComputeFlowHashSimple("GET", "example.com", "/api", headers2, nil)

		assert.Equal(t, hash1, hash2)
	})
}

func TestHashFunctionsEquivalent(t *testing.T) {
	t.Parallel()

	// ComputeFlowHash and ComputeFlowHashSimple must produce identical hashes
	// for equivalent input to ensure consistent flow identification.
	headers := http.Header{
		"Content-Type": []string{"application/json"},
		"Accept":       []string{"*/*"},
	}
	headerLines := []string{"Content-Type: application/json", "Accept: */*"}
	body := []byte(`{"key": "value"}`)

	hashFromHeader := ComputeFlowHash("POST", "example.com", "/api/users", headers, body)
	hashFromSimple := ComputeFlowHashSimple("POST", "example.com", "/api/users", headerLines, body)

	assert.Equal(t, hashFromHeader, hashFromSimple)
}
