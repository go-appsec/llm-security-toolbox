package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsTimeoutError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{"nil_error", nil, false},
		{"generic_error", errors.New("some error"), false},
		{"context_deadline", context.DeadlineExceeded, true},
		{"wrapped_deadline", fmt.Errorf("wrapped: %w", context.DeadlineExceeded), true},
		{"os_deadline", os.ErrDeadlineExceeded, true},
		{"wrapped_os_deadline", fmt.Errorf("wrapped: %w", os.ErrDeadlineExceeded), true},
		{"context_canceled", context.Canceled, false},
		{"net_timeout", &timeoutError{timeout: true}, true},
		{"net_non_timeout", &timeoutError{timeout: false}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, IsTimeoutError(tc.err))
		})
	}
}

// timeoutError implements net.Error for testing
type timeoutError struct {
	timeout bool
}

func (e *timeoutError) Error() string   { return "timeout error" }
func (e *timeoutError) Timeout() bool   { return e.timeout }
func (e *timeoutError) Temporary() bool { return false }

var _ net.Error = (*timeoutError)(nil)
