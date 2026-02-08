package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMCP_EncodeURL(t *testing.T) {
	t.Parallel()

	_, mcpClient, _, _, _ := setupMockMCPServer(t)

	t.Run("encode", func(t *testing.T) {
		text := CallMCPToolTextOK(t, mcpClient, "encode_url", map[string]interface{}{
			"input": "hello world&test=<value>",
		})
		assert.Equal(t, "hello+world%26test%3D%3Cvalue%3E", text)
	})

	t.Run("decode", func(t *testing.T) {
		text := CallMCPToolTextOK(t, mcpClient, "encode_url", map[string]interface{}{
			"input":  "hello+world%26test%3D%3Cvalue%3E",
			"decode": true,
		})
		assert.Equal(t, "hello world&test=<value>", text)
	})

	t.Run("decode_malformed", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "encode_url", map[string]interface{}{
			"input":  "%ZZ%invalid",
			"decode": true,
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "URL decode error")
	})
}

func TestMCP_EncodeBase64(t *testing.T) {
	t.Parallel()

	_, mcpClient, _, _, _ := setupMockMCPServer(t)

	t.Run("encode", func(t *testing.T) {
		text := CallMCPToolTextOK(t, mcpClient, "encode_base64", map[string]interface{}{
			"input": "hello world",
		})
		assert.Equal(t, "aGVsbG8gd29ybGQ=", text)
	})

	t.Run("decode", func(t *testing.T) {
		text := CallMCPToolTextOK(t, mcpClient, "encode_base64", map[string]interface{}{
			"input":  "aGVsbG8gd29ybGQ=",
			"decode": true,
		})
		assert.Equal(t, "hello world", text)
	})

	t.Run("invalid_base64", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "encode_base64", map[string]interface{}{
			"input":  "not valid base64!!!",
			"decode": true,
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "base64 decode error")
	})
}

func TestMCP_EncodeHTML(t *testing.T) {
	t.Parallel()

	_, mcpClient, _, _, _ := setupMockMCPServer(t)

	t.Run("encode", func(t *testing.T) {
		text := CallMCPToolTextOK(t, mcpClient, "encode_html", map[string]interface{}{
			"input": "<script>alert('xss')</script>",
		})
		assert.Equal(t, "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;", text)
	})

	t.Run("decode", func(t *testing.T) {
		text := CallMCPToolTextOK(t, mcpClient, "encode_html", map[string]interface{}{
			"input":  "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;",
			"decode": true,
		})
		assert.Equal(t, "<script>alert('xss')</script>", text)
	})
}

func TestMCP_EncodeValidation(t *testing.T) {
	t.Parallel()

	_, mcpClient, _, _, _ := setupMockMCPServer(t)

	cases := []struct {
		name string
		tool string
	}{
		{name: "url_missing_input", tool: "encode_url"},
		{name: "base64_missing_input", tool: "encode_base64"},
		{name: "html_missing_input", tool: "encode_html"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := CallMCPTool(t, mcpClient, tc.tool, map[string]interface{}{})
			assert.True(t, result.IsError)
			assert.Contains(t, ExtractMCPText(t, result), "input is required")
		})
	}
}
