package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

const (
	DefaultBurpMCPURL    = "http://127.0.0.1:9876/sse"
	DefaultBurpProxyAddr = "127.0.0.1:8080"
	DefaultMCPPort       = 9119
	DefaultProxyPort     = 8080
)

// Version is injected at build time via ldflags; defaults to "dev".
var Version = "dev"

func UserAgent() string {
	return "Mozilla/5.0 (compatible; go-appsec/llm-security-toolbox sectool-" + Version + ")"
}

// DefaultPath returns ~/.sectool/config.json.
func DefaultPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".sectool/config.json"
	}
	return filepath.Join(home, ".sectool", "config.json")
}

type Config struct {
	Version           string        `json:"version"`
	MCPPort           int           `json:"mcp_port,omitempty"`
	ProxyPort         int           `json:"proxy_port,omitempty"`
	BurpRequired      *bool         `json:"burp_required,omitempty"`
	MaxBodyBytes      int           `json:"max_body_bytes,omitempty"` // limits request/response body sizes
	IncludeSubdomains *bool         `json:"include_subdomains,omitempty"`
	AllowedDomains    []string      `json:"allowed_domains,omitempty"`
	ExcludeDomains    []string      `json:"exclude_domains,omitempty"`
	Crawler           CrawlerConfig `json:"crawler,omitempty"`
}

type CrawlerConfig struct {
	DisallowedPaths []string `json:"disallowed_paths,omitempty"`
	DelayMS         int      `json:"delay_ms,omitempty"`
	Parallelism     int      `json:"parallelism,omitempty"`
	MaxDepth        int      `json:"max_depth,omitempty"`
	MaxRequests     int      `json:"max_requests,omitempty"`
	ExtractForms    *bool    `json:"extract_forms,omitempty"`
	SubmitForms     *bool    `json:"submit_forms,omitempty"`
	Recon           *bool    `json:"recon,omitempty"`
}

// DefaultConfig returns a Config with default values.
func DefaultConfig() *Config {
	t := true
	f := false
	return &Config{
		Version:           Version,
		MCPPort:           DefaultMCPPort,
		ProxyPort:         DefaultProxyPort,
		BurpRequired:      &f,
		MaxBodyBytes:      10485760, // 10MB
		IncludeSubdomains: &t,
		Crawler: CrawlerConfig{
			DisallowedPaths: []string{
				"*logout*",
				"*signout*",
				"*sign-out*",
				"*delete*",
				"*remove*",
			},
			DelayMS:      200,
			Parallelism:  2,
			MaxDepth:     10,
			MaxRequests:  1000,
			ExtractForms: &t,
			SubmitForms:  &f,
			Recon:        &f,
		},
	}
}

// Load reads config from path. Returns os.ErrNotExist if file is missing.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	// Apply defaults for missing fields
	if cfg.Version == "" {
		cfg.Version = Version
	}
	if cfg.MCPPort == 0 {
		cfg.MCPPort = DefaultMCPPort
	}
	if cfg.ProxyPort == 0 {
		cfg.ProxyPort = DefaultProxyPort
	}

	// Apply defaults for zero values
	defaults := DefaultConfig()
	if cfg.BurpRequired == nil {
		cfg.BurpRequired = defaults.BurpRequired
	}
	if cfg.MaxBodyBytes == 0 {
		cfg.MaxBodyBytes = defaults.MaxBodyBytes
	}
	if cfg.IncludeSubdomains == nil {
		cfg.IncludeSubdomains = defaults.IncludeSubdomains
	}
	if cfg.Crawler.DisallowedPaths == nil {
		cfg.Crawler.DisallowedPaths = defaults.Crawler.DisallowedPaths
	}
	if cfg.Crawler.DelayMS == 0 {
		cfg.Crawler.DelayMS = defaults.Crawler.DelayMS
	}
	if cfg.Crawler.Parallelism == 0 {
		cfg.Crawler.Parallelism = defaults.Crawler.Parallelism
	}
	if cfg.Crawler.MaxDepth == 0 {
		cfg.Crawler.MaxDepth = defaults.Crawler.MaxDepth
	}
	if cfg.Crawler.MaxRequests == 0 {
		cfg.Crawler.MaxRequests = defaults.Crawler.MaxRequests
	}
	if cfg.Crawler.ExtractForms == nil {
		cfg.Crawler.ExtractForms = defaults.Crawler.ExtractForms
	}
	if cfg.Crawler.SubmitForms == nil {
		cfg.Crawler.SubmitForms = defaults.Crawler.SubmitForms
	}
	if cfg.Crawler.Recon == nil {
		cfg.Crawler.Recon = defaults.Crawler.Recon
	}

	return &cfg, nil
}

func LoadOrDefaultConfig(path string) (*Config, error) {
	cfg, err := Load(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return DefaultConfig(), nil
		}
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	return cfg, nil
}

// Save writes config to path, creating parent directory if needed.
func (c *Config) Save(path string) error {
	if c == nil {
		return errors.New("config is nil")
	}

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}

// LoadOrCreate loads config from default path, creating with defaults if missing.
func LoadOrCreate() (*Config, error) {
	return LoadOrCreatePath(DefaultPath())
}

// LoadOrCreatePath loads config from path, creating with defaults if missing.
func LoadOrCreatePath(path string) (*Config, error) {
	cfg, err := Load(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			cfg = DefaultConfig()
			if err := cfg.Save(path); err != nil {
				return nil, fmt.Errorf("create default config: %w", err)
			}
			return cfg, nil
		}
		return nil, fmt.Errorf("load config: %w", err)
	}
	return cfg, nil
}

// IsDomainAllowed checks whether a hostname is permitted by the domain scoping
// configuration. Returns true if allowed, or false with a reason string.
func (c *Config) IsDomainAllowed(hostname string) (bool, string) {
	// Strip port if present
	if h, _, err := net.SplitHostPort(hostname); err == nil {
		hostname = h
	}
	hostname = strings.ToLower(hostname)

	// Check ExcludeDomains first (always includes subdomains)
	for _, d := range c.ExcludeDomains {
		d = strings.ToLower(d)
		if hostname == d || strings.HasSuffix(hostname, "."+d) {
			return false, "domain " + hostname + " is in exclude_domains"
		}
	}

	if len(c.AllowedDomains) == 0 {
		return true, "" // If AllowedDomains is empty, allow all
	}

	includeSubdomains := c.IncludeSubdomains != nil && *c.IncludeSubdomains

	for _, d := range c.AllowedDomains {
		d = strings.ToLower(d)
		if hostname == d {
			return true, ""
		} else if includeSubdomains && strings.HasSuffix(hostname, "."+d) {
			return true, ""
		}
	}

	return false, "domain " + hostname + " is not in allowed_domains"
}
