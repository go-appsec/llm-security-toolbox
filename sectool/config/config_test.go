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

func TestLoadOrDefaultConfig(t *testing.T) {
	t.Parallel()

	t.Run("creates_new_config", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.json")

		cfg, err := LoadOrDefaultConfig(path)
		require.NoError(t, err)
		assert.Equal(t, Version, cfg.Version)
		assert.Equal(t, DefaultBurpMCPURL, cfg.BurpMCPURL)
	})

	t.Run("loads_existing_config", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.json")

		// Create an existing config
		existing := &Config{
			Version:        "0.0.1",
			BurpMCPURL:     "http://custom:1234/sse",
			PreserveGuides: true,
		}
		require.NoError(t, existing.Save(path))

		cfg, err := LoadOrDefaultConfig(path)
		require.NoError(t, err)
		assert.Equal(t, "http://custom:1234/sse", cfg.BurpMCPURL)
		assert.True(t, cfg.PreserveGuides)
	})

	t.Run("error_on_invalid_JSON", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.json")

		require.NoError(t, os.WriteFile(path, []byte("invalid"), 0644))

		_, err := LoadOrDefaultConfig(path)
		assert.Error(t, err)
	})
}
