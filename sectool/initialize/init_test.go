package initialize

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-harden/llm-security-toolbox/sectool/config"
)

func TestWriteGuideIfNeeded(t *testing.T) {
	t.Parallel()

	const testContent = "# Test Guide\n\nContent here."

	t.Run("writes_new_file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "guide.md")

		written, err := writeGuideIfNeeded(path, testContent, false)
		require.NoError(t, err)
		assert.True(t, written)

		content, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, testContent, string(content))
	})

	t.Run("overwrites_when_not_preserving", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "guide.md")

		// Create existing file with different content
		require.NoError(t, os.WriteFile(path, []byte("old content"), 0644))

		written, err := writeGuideIfNeeded(path, testContent, false)
		require.NoError(t, err)
		assert.True(t, written)

		content, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, testContent, string(content))
	})

	t.Run("preserves_existing_file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "guide.md")

		const originalContent = "original content"
		require.NoError(t, os.WriteFile(path, []byte(originalContent), 0644))

		written, err := writeGuideIfNeeded(path, testContent, true)
		require.NoError(t, err)
		assert.False(t, written)

		content, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, originalContent, string(content))
	})

	t.Run("writes_new_when_preserving", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "guide.md")

		written, err := writeGuideIfNeeded(path, testContent, true)
		require.NoError(t, err)
		assert.True(t, written)

		content, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, testContent, string(content))
	})
}

func TestEmbeddedTemplates(t *testing.T) {
	t.Parallel()

	t.Run("explore_guide_not_empty", func(t *testing.T) {
		assert.NotEmpty(t, exploreGuide)
		assert.Contains(t, exploreGuide, "{{.SectoolCmd}}")
	})

	t.Run("test_report_guide_not_empty", func(t *testing.T) {
		assert.NotEmpty(t, testReportGuide)
		assert.Contains(t, testReportGuide, "{{.SectoolCmd}}")
	})
}

func TestRenderTemplate(t *testing.T) {
	t.Parallel()

	t.Run("substitutes_sectool_cmd", func(t *testing.T) {
		tmpl := "Run `{{.SectoolCmd}} --help` for help"
		result, err := renderTemplate(tmpl, templateData{SectoolCmd: "./bin/sectool"})
		require.NoError(t, err)
		assert.Equal(t, "Run `./bin/sectool --help` for help", result)
	})

	t.Run("handles_multiple_occurrences", func(t *testing.T) {
		tmpl := "{{.SectoolCmd}} foo\n{{.SectoolCmd}} bar"
		result, err := renderTemplate(tmpl, templateData{SectoolCmd: "sectool"})
		require.NoError(t, err)
		assert.Equal(t, "sectool foo\nsectool bar", result)
	})

	t.Run("error_on_invalid_template", func(t *testing.T) {
		_, err := renderTemplate("{{.Invalid", templateData{SectoolCmd: "sectool"})
		assert.Error(t, err)
	})
}

func TestRelativeOrAbsPath(t *testing.T) {
	t.Parallel()

	t.Run("returns_relative_with_prefix", func(t *testing.T) {
		wd, err := os.Getwd()
		require.NoError(t, err)

		exePath := filepath.Join(wd, "bin", "sectool")
		result := relativeOrAbsPath(exePath)
		assert.Equal(t, "./bin/sectool", result)
	})

	t.Run("returns_absolute_for_parent_dir", func(t *testing.T) {
		wd, err := os.Getwd()
		require.NoError(t, err)

		exePath := filepath.Join(filepath.Dir(wd), "other", "sectool")
		result := relativeOrAbsPath(exePath)
		// Should return absolute path since it's outside working dir
		assert.Equal(t, exePath, result)
	})
}

func TestRun(t *testing.T) {
	originalWd, err := os.Getwd()
	require.NoError(t, err)
	defer func() { _ = os.Chdir(originalWd) }()

	t.Run("explore_creates_guide", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.Chdir(dir))

		err := run("explore", false)
		require.NoError(t, err)

		// Verify guide was created
		guidePath := filepath.Join(dir, ".sectool", exploreFileName)
		content, err := os.ReadFile(guidePath)
		require.NoError(t, err)
		assert.Contains(t, string(content), "Security Testing and Exploration Guide")

		// Verify config was created
		configPath := filepath.Join(dir, ".sectool", "config.json")
		cfg, err := config.Load(configPath)
		require.NoError(t, err)
		assert.Equal(t, "explore", cfg.LastInitMode)
	})

	t.Run("test_report_creates_guide", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.Chdir(dir))

		err := run("test-report", false)
		require.NoError(t, err)

		// Verify guide was created
		guidePath := filepath.Join(dir, ".sectool", testReportFileName)
		content, err := os.ReadFile(guidePath)
		require.NoError(t, err)
		assert.Contains(t, string(content), "Security Report Validation Guide")

		// Verify config was updated
		configPath := filepath.Join(dir, ".sectool", "config.json")
		cfg, err := config.Load(configPath)
		require.NoError(t, err)
		assert.Equal(t, "test-report", cfg.LastInitMode)
	})

	t.Run("unknown_mode_errors", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.Chdir(dir))

		err := run("unknown", false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown init mode")
	})

	t.Run("reset_clears_directory", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.Chdir(dir))

		// Create initial state
		sectoolDir := filepath.Join(dir, ".sectool")
		require.NoError(t, os.MkdirAll(sectoolDir, 0755))
		oldFile := filepath.Join(sectoolDir, "old-file.txt")
		require.NoError(t, os.WriteFile(oldFile, []byte("old"), 0644))

		// Run with reset
		err := run("explore", true)
		require.NoError(t, err)

		// Old file should be gone
		_, err = os.Stat(oldFile)
		assert.True(t, os.IsNotExist(err))

		// New guide should exist
		guidePath := filepath.Join(sectoolDir, exploreFileName)
		_, err = os.Stat(guidePath)
		assert.NoError(t, err)
	})

	t.Run("respects_preserve_guides", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.Chdir(dir))

		// Create directory and config with preserve_guides
		sectoolDir := filepath.Join(dir, ".sectool")
		require.NoError(t, os.MkdirAll(sectoolDir, 0755))

		cfg := config.DefaultConfig()
		cfg.PreserveGuides = true
		require.NoError(t, cfg.Save(filepath.Join(sectoolDir, "config.json")))

		// Create existing guide with custom content
		guidePath := filepath.Join(sectoolDir, exploreFileName)
		customContent := "# Custom Guide"
		require.NoError(t, os.WriteFile(guidePath, []byte(customContent), 0644))

		// Run init
		err := run("explore", false)
		require.NoError(t, err)

		// Custom content should be preserved
		content, err := os.ReadFile(guidePath)
		require.NoError(t, err)
		assert.Equal(t, customContent, string(content))
	})
}
