package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadSaveRoundTrip(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	original := &Config{
		Version:        "0.0.1",
		InitializedAt:  time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
		LastInitMode:   "explore",
		BurpMCPURL:     "http://localhost:9999/sse",
		PreserveGuides: true,
	}

	err := original.Save(path)
	require.NoError(t, err)

	_, err = os.Stat(path)
	require.NoError(t, err)

	loaded, err := Load(path)
	require.NoError(t, err)

	assert.Equal(t, original.Version, loaded.Version)
	assert.Equal(t, original.InitializedAt.UTC(), loaded.InitializedAt.UTC())
	assert.Equal(t, original.LastInitMode, loaded.LastInitMode)
	assert.Equal(t, original.BurpMCPURL, loaded.BurpMCPURL)
	assert.Equal(t, original.PreserveGuides, loaded.PreserveGuides)
}

func TestLoadNotExist(t *testing.T) {
	t.Parallel()

	_, err := Load("/nonexistent/path/config.json")
	assert.True(t, os.IsNotExist(err))
}

func TestLoadAppliesDefaults(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	// Write minimal config (missing optional fields)
	minimalJSON := `{"version": "0.0.1", "initialized_at": "2025-01-15T10:30:00Z"}`
	err := os.WriteFile(path, []byte(minimalJSON), 0644)
	require.NoError(t, err)

	cfg, err := Load(path)
	require.NoError(t, err)
	assert.Equal(t, DefaultBurpMCPURL, cfg.BurpMCPURL)
}

func TestLoadInvalidJSON(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	err := os.WriteFile(path, []byte("not json"), 0644)
	require.NoError(t, err)

	_, err = Load(path)
	assert.Error(t, err)
}

func TestCrawlerDefaults(t *testing.T) {
	t.Parallel()

	defaults := CrawlerDefaults()

	assert.Equal(t, 2, defaults.MaxConcurrentSessions)
	assert.Equal(t, 1048576, defaults.MaxResponseBodyBytes)
	assert.NotNil(t, defaults.IncludeSubdomains)
	assert.True(t, *defaults.IncludeSubdomains)
	assert.Contains(t, defaults.DefaultDisallowedPaths, "*logout*")
	assert.Contains(t, defaults.DefaultDisallowedPaths, "*delete*")
	assert.Equal(t, 200, defaults.DefaultDelayMS)
	assert.Equal(t, 2, defaults.DefaultParallelism)
	assert.Equal(t, 10, defaults.DefaultMaxDepth)
	assert.Equal(t, 1000, defaults.DefaultMaxRequests)
	assert.NotNil(t, defaults.DefaultExtractForms)
	assert.True(t, *defaults.DefaultExtractForms)
	assert.NotNil(t, defaults.DefaultSubmitForms)
	assert.False(t, *defaults.DefaultSubmitForms)
}

func TestGetCrawler(t *testing.T) {
	t.Parallel()

	t.Run("nil_returns_defaults", func(t *testing.T) {
		cfg := &Config{}
		crawler := cfg.GetCrawler()

		defaults := CrawlerDefaults()
		assert.Equal(t, defaults.MaxConcurrentSessions, crawler.MaxConcurrentSessions)
		assert.Equal(t, defaults.MaxResponseBodyBytes, crawler.MaxResponseBodyBytes)
		assert.Equal(t, defaults.DefaultDelayMS, crawler.DefaultDelayMS)
	})

	t.Run("partial_config_merges_defaults", func(t *testing.T) {
		cfg := &Config{
			Crawler: &CrawlerConfig{
				MaxConcurrentSessions: 5,
				DefaultDelayMS:        500,
			},
		}
		crawler := cfg.GetCrawler()

		assert.Equal(t, 5, crawler.MaxConcurrentSessions)
		assert.Equal(t, 500, crawler.DefaultDelayMS)
		// Should use defaults for unset fields
		assert.Equal(t, 1048576, crawler.MaxResponseBodyBytes)
		assert.Equal(t, 2, crawler.DefaultParallelism)
		assert.Equal(t, 10, crawler.DefaultMaxDepth)
	})

	t.Run("full_config_no_defaults", func(t *testing.T) {
		f := false
		t2 := true
		cfg := &Config{
			Crawler: &CrawlerConfig{
				MaxConcurrentSessions:  3,
				MaxResponseBodyBytes:   512000,
				IncludeSubdomains:      &f,
				DefaultDisallowedPaths: []string{"/admin/*"},
				DefaultDelayMS:         100,
				DefaultParallelism:     4,
				DefaultMaxDepth:        5,
				DefaultMaxRequests:     500,
				DefaultExtractForms:    &t2,
				DefaultSubmitForms:     &t2,
			},
		}
		crawler := cfg.GetCrawler()

		assert.Equal(t, 3, crawler.MaxConcurrentSessions)
		assert.Equal(t, 512000, crawler.MaxResponseBodyBytes)
		assert.False(t, *crawler.IncludeSubdomains)
		assert.Equal(t, []string{"/admin/*"}, crawler.DefaultDisallowedPaths)
		assert.Equal(t, 100, crawler.DefaultDelayMS)
		assert.Equal(t, 4, crawler.DefaultParallelism)
		assert.Equal(t, 5, crawler.DefaultMaxDepth)
		assert.Equal(t, 500, crawler.DefaultMaxRequests)
		assert.True(t, *crawler.DefaultExtractForms)
		assert.True(t, *crawler.DefaultSubmitForms)
	})
}
