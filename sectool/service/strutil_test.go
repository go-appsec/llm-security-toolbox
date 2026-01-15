package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTruncateString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		path   string
		maxLen int
		want   string
	}{
		{"empty", "", 10, ""},
		{"short", "/short", 100, "/short"},
		{"long", "/very/long/path/that/exceeds/the/maximum/length", 20, "/very/long/path/t..."},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			assert.Equal(t, tt.want, truncateString(tt.path, tt.maxLen))
		})
	}
}
