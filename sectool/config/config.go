package config

import (
	"encoding/json"
	"errors"
	"os"
	"time"
)

const (
	Version           = "0.0.1"
	DefaultBurpMCPURL = "http://127.0.0.1:9876/sse"
)

// RevNum is the git revision count, injected at build time via ldflags.
// Falls back to "dev" when not set (e.g., go run without ldflags).
var RevNum = "dev"

// UserAgent returns the standard user agent string for sectool requests.
func UserAgent() string {
	return "go-harden/llm-security-toolbox sectool-v" + Version + "-" + RevNum
}

// Config holds the sectool configuration stored in .sectool/config.json
type Config struct {
	Version        string         `json:"version"`
	InitializedAt  time.Time      `json:"initialized_at"`
	LastInitMode   string         `json:"last_init_mode,omitempty"`
	BurpMCPURL     string         `json:"burp_mcp_url"`
	PreserveGuides bool           `json:"preserve_guides,omitempty"`
	Crawler        *CrawlerConfig `json:"crawler,omitempty"`
}

// CrawlerConfig holds crawler-specific settings.
type CrawlerConfig struct {
	MaxConcurrentSessions  int      `json:"max_concurrent_sessions,omitempty"`
	MaxResponseBodyBytes   int      `json:"max_response_body_bytes,omitempty"`
	IncludeSubdomains      *bool    `json:"include_subdomains,omitempty"`
	DefaultDisallowedPaths []string `json:"default_disallowed_paths,omitempty"`
	DefaultDelayMS         int      `json:"default_delay_ms,omitempty"`
	DefaultParallelism     int      `json:"default_parallelism,omitempty"`
	DefaultMaxDepth        int      `json:"default_max_depth,omitempty"`
	DefaultMaxRequests     int      `json:"default_max_requests,omitempty"`
	DefaultExtractForms    *bool    `json:"default_extract_forms,omitempty"`
	DefaultSubmitForms     *bool    `json:"default_submit_forms,omitempty"`
}

// CrawlerDefaults returns a CrawlerConfig with default values.
func CrawlerDefaults() *CrawlerConfig {
	t := true
	f := false
	return &CrawlerConfig{
		MaxConcurrentSessions: 2,
		MaxResponseBodyBytes:  1048576, // 1MB
		IncludeSubdomains:     &t,
		DefaultDisallowedPaths: []string{
			"*logout*",
			"*signout*",
			"*sign-out*",
			"*delete*",
			"*remove*",
		},
		DefaultDelayMS:      200,
		DefaultParallelism:  2,
		DefaultMaxDepth:     10,
		DefaultMaxRequests:  1000,
		DefaultExtractForms: &t,
		DefaultSubmitForms:  &f,
	}
}

// GetCrawler returns the crawler config with defaults applied.
func (c *Config) GetCrawler() *CrawlerConfig {
	defaults := CrawlerDefaults()
	if c.Crawler == nil {
		return defaults
	}
	// Merge user config with defaults
	cfg := *c.Crawler
	if cfg.MaxConcurrentSessions == 0 {
		cfg.MaxConcurrentSessions = defaults.MaxConcurrentSessions
	}
	if cfg.MaxResponseBodyBytes == 0 {
		cfg.MaxResponseBodyBytes = defaults.MaxResponseBodyBytes
	}
	if cfg.IncludeSubdomains == nil {
		cfg.IncludeSubdomains = defaults.IncludeSubdomains
	}
	if len(cfg.DefaultDisallowedPaths) == 0 {
		cfg.DefaultDisallowedPaths = defaults.DefaultDisallowedPaths
	}
	if cfg.DefaultDelayMS == 0 {
		cfg.DefaultDelayMS = defaults.DefaultDelayMS
	}
	if cfg.DefaultParallelism == 0 {
		cfg.DefaultParallelism = defaults.DefaultParallelism
	}
	if cfg.DefaultMaxDepth == 0 {
		cfg.DefaultMaxDepth = defaults.DefaultMaxDepth
	}
	if cfg.DefaultMaxRequests == 0 {
		cfg.DefaultMaxRequests = defaults.DefaultMaxRequests
	}
	if cfg.DefaultExtractForms == nil {
		cfg.DefaultExtractForms = defaults.DefaultExtractForms
	}
	if cfg.DefaultSubmitForms == nil {
		cfg.DefaultSubmitForms = defaults.DefaultSubmitForms
	}
	return &cfg
}

// DefaultConfig returns a new Config with default values
func DefaultConfig(version string) *Config {
	return &Config{
		Version:       version,
		InitializedAt: time.Now().UTC(),
		BurpMCPURL:    DefaultBurpMCPURL,
	}
}

// Load reads and parses config from the given path.
// If the file doesn't exist, returns os.ErrNotExist.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	if cfg.BurpMCPURL == "" {
		cfg.BurpMCPURL = DefaultBurpMCPURL
	}

	return &cfg, nil
}

// Save writes the config to the given path atomically.
func (c *Config) Save(path string) error {
	if c == nil {
		return errors.New("config is nil")
	}

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}
