package diff

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/go-appsec/toolbox/sectool/cliutil"
)

func TestSplitRunes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want []string
	}{
		{"ascii", "abc", []string{"a", "b", "c"}},
		{"multibyte", "caf\u00e9", []string{"c", "a", "f", "\u00e9"}},
		{"mixed", "a\u00f1b", []string{"a", "\u00f1", "b"}},
		{"empty", "", []string{}},
		{"single_char", "x", []string{"x"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, splitRunes(tt.in))
		})
	}
}

func TestColorDiffLine(t *testing.T) {
	// No t.Parallel(): mutates global cliutil.Output.ColorMode
	orig := cliutil.Output.ColorMode
	cliutil.Output.ColorMode = cliutil.ColorAlways
	t.Cleanup(func() { cliutil.Output.ColorMode = orig })

	tests := []struct {
		name string
		line string
		want string
	}{
		{"file_header_minus", "--- a/file.txt", cliutil.Muted("--- a/file.txt")},
		{"file_header_plus", "+++ b/file.txt", cliutil.Muted("+++ b/file.txt")},
		{"hunk_header", "@@ -1,3 +1,4 @@", cliutil.Muted("@@ -1,3 +1,4 @@")},
		{"addition", "+new line", cliutil.Success("+new line")},
		{"removal", "-old line", cliutil.Error("-old line")},
		{"context", " unchanged", " unchanged"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, colorDiffLine(tt.line))
		})
	}
}

func TestInlineHighlight(t *testing.T) {
	// No t.Parallel(): mutates global cliutil.Output.ColorMode
	orig := cliutil.Output.ColorMode
	cliutil.Output.ColorMode = cliutil.ColorNever
	t.Cleanup(func() { cliutil.Output.ColorMode = orig })

	tests := []struct {
		name  string
		a     string
		b     string
		wantA string
		wantB string
	}{
		{
			name:  "partial_change",
			a:     "nonce-abc123",
			b:     "nonce-xyz789",
			wantA: "nonce-abc123",
			wantB: "nonce-xyz789",
		},
		{
			name:  "identical",
			a:     "same",
			b:     "same",
			wantA: "same",
			wantB: "same",
		},
		{
			name:  "empty_both",
			a:     "",
			b:     "",
			wantA: "",
			wantB: "",
		},
		{
			name:  "completely_different",
			a:     "abc",
			b:     "xyz",
			wantA: "abc",
			wantB: "xyz",
		},
		{
			name:  "a_empty",
			a:     "",
			b:     "hello",
			wantA: "",
			wantB: "hello",
		},
		{
			name:  "b_empty",
			a:     "hello",
			b:     "",
			wantA: "hello",
			wantB: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotA, gotB := inlineHighlight(tt.a, tt.b)
			assert.Equal(t, tt.wantA, gotA)
			assert.Equal(t, tt.wantB, gotB)
		})
	}
}

func TestInlineHighlight_with_colors(t *testing.T) {
	// No t.Parallel(): mutates global cliutil.Output.ColorMode
	orig := cliutil.Output.ColorMode
	cliutil.Output.ColorMode = cliutil.ColorAlways
	t.Cleanup(func() { cliutil.Output.ColorMode = orig })

	gotA, gotB := inlineHighlight("nonce-abc", "nonce-xyz")

	// Unchanged prefix should appear as-is
	assert.Contains(t, gotA, "nonce-")
	assert.Contains(t, gotB, "nonce-")

	// Changed portions should contain ANSI escape codes
	assert.Contains(t, gotA, "\x1b[")
	assert.Contains(t, gotB, "\x1b[")

	// The raw changed text should be embedded in the output
	assert.Contains(t, gotA, "abc")
	assert.Contains(t, gotB, "xyz")
}
