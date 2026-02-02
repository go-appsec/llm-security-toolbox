package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadSaveRoundTrip(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	original := &Config{
		Version: Version,
		MCPPort: 8080,
	}

	err := original.Save(path)
	require.NoError(t, err)

	_, err = os.Stat(path)
	require.NoError(t, err)

	loaded, err := Load(path)
	require.NoError(t, err)

	assert.Equal(t, original.Version, loaded.Version)
	assert.Equal(t, original.MCPPort, loaded.MCPPort)
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
	const minimalJSON = `{"version": "0.1.0"}`
	err := os.WriteFile(path, []byte(minimalJSON), 0644)
	require.NoError(t, err)

	cfg, err := Load(path)
	require.NoError(t, err)
	assert.Equal(t, DefaultMCPPort, cfg.MCPPort)
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

	t.Run("creates_default", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.json")

		cfg, err := LoadOrDefaultConfig(path)
		require.NoError(t, err)
		assert.Equal(t, Version, cfg.Version)
		assert.Equal(t, DefaultMCPPort, cfg.MCPPort)
	})

	t.Run("loads_existing", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.json")

		existing := &Config{
			Version: Version,
			MCPPort: 8080,
		}
		require.NoError(t, existing.Save(path))

		cfg, err := LoadOrDefaultConfig(path)
		require.NoError(t, err)
		assert.Equal(t, 8080, cfg.MCPPort)
	})

	t.Run("error_on_invalid_json", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.json")

		require.NoError(t, os.WriteFile(path, []byte("invalid"), 0644))

		_, err := LoadOrDefaultConfig(path)
		assert.Error(t, err)
	})
}

func TestDefaultPath(t *testing.T) {
	t.Parallel()

	path := DefaultPath()
	assert.Contains(t, path, ".sectool")
	assert.Contains(t, path, "config.json")
}
