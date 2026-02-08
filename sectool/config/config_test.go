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

func TestIsDomainAllowed(t *testing.T) {
	t.Parallel()

	boolPtr := func(v bool) *bool { return &v }

	cases := []struct {
		name       string
		cfg        *Config
		hostname   string
		wantOK     bool
		wantReason string
	}{
		{
			name:     "no_config_allows_all",
			cfg:      &Config{IncludeSubdomains: boolPtr(true)},
			hostname: "anything.example.com",
			wantOK:   true,
		},
		{
			name: "exclude_takes_precedence",
			cfg: &Config{
				IncludeSubdomains: boolPtr(true),
				AllowedDomains:    []string{"example.com"},
				ExcludeDomains:    []string{"example.com"},
			},
			hostname:   "example.com",
			wantOK:     false,
			wantReason: "exclude_domains",
		},
		{
			name: "exclude_matches_subdomains",
			cfg: &Config{
				IncludeSubdomains: boolPtr(true),
				ExcludeDomains:    []string{"evil.com"},
			},
			hostname:   "sub.evil.com",
			wantOK:     false,
			wantReason: "exclude_domains",
		},
		{
			name: "allowed_exact_match",
			cfg: &Config{
				IncludeSubdomains: boolPtr(false),
				AllowedDomains:    []string{"example.com"},
			},
			hostname: "example.com",
			wantOK:   true,
		},
		{
			name: "allowed_subdomain_match",
			cfg: &Config{
				IncludeSubdomains: boolPtr(true),
				AllowedDomains:    []string{"example.com"},
			},
			hostname: "api.example.com",
			wantOK:   true,
		},
		{
			name: "allowed_no_subdomains",
			cfg: &Config{
				IncludeSubdomains: boolPtr(false),
				AllowedDomains:    []string{"example.com"},
			},
			hostname:   "api.example.com",
			wantOK:     false,
			wantReason: "not in allowed_domains",
		},
		{
			name: "not_in_allowed",
			cfg: &Config{
				IncludeSubdomains: boolPtr(true),
				AllowedDomains:    []string{"example.com"},
			},
			hostname:   "other.com",
			wantOK:     false,
			wantReason: "not in allowed_domains",
		},
		{
			name: "hostname_with_port",
			cfg: &Config{
				IncludeSubdomains: boolPtr(true),
				AllowedDomains:    []string{"example.com"},
			},
			hostname: "example.com:8443",
			wantOK:   true,
		},
		{
			name: "case_insensitive",
			cfg: &Config{
				IncludeSubdomains: boolPtr(true),
				AllowedDomains:    []string{"Example.COM"},
			},
			hostname: "API.example.com",
			wantOK:   true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, reason := tc.cfg.IsDomainAllowed(tc.hostname)
			assert.Equal(t, tc.wantOK, ok)
			if tc.wantReason != "" {
				assert.Contains(t, reason, tc.wantReason)
			}
		})
	}
}
