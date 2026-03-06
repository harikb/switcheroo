package main

import (
	"fmt"
	"net"
	"os"
	"sort"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server       ServerConfig       `yaml:"server"`
	Routes       []Route            `yaml:"routes"`
	Policy       PolicyConfig       `yaml:"policy,omitempty"`
	ForwardProxy ForwardProxyConfig `yaml:"forward_proxy,omitempty"`
	DeClaw       DeclawConfig       `yaml:"declaw,omitempty"`
}

type PolicyConfig struct {
	Deny  []PolicyRule `yaml:"deny,omitempty"`
	Allow []PolicyRule `yaml:"allow,omitempty"`
}

type ForwardProxyConfig struct {
	Enabled      bool     `yaml:"enabled"`
	AllowedPorts []int    `yaml:"allowed_ports,omitempty"`
	Bypass       []string `yaml:"bypass,omitempty"`
}

type ServerConfig struct {
	Listen                    string   `yaml:"listen"`
	TokenStateFile            string   `yaml:"token_state_file"`
	Mode                      string   `yaml:"mode"`
	GrantDB                   string   `yaml:"grant_db,omitempty"`
	ApprovalTimeout           string   `yaml:"approval_timeout,omitempty"`
	ManagementAPIAllowedCIDRs []string `yaml:"management_api_allowed_cidrs,omitempty"`
	AgentConfigPath           string   `yaml:"agent_config_path,omitempty"`
}

type Route struct {
	Path            string            `yaml:"path"`
	Upstream        string            `yaml:"upstream"`
	InboundAuth     *InboundAuth      `yaml:"inbound_auth,omitempty"`
	UpstreamAuth    UpstreamAuth      `yaml:"upstream_auth"`
	ExtraHeaders    map[string]string `yaml:"extra_headers,omitempty"`
	Approval        string            `yaml:"approval,omitempty"`
	ApprovalTimeout string            `yaml:"approval_timeout,omitempty"`
	Locked          bool              `yaml:"locked,omitempty"`
	LockedFields    []string          `yaml:"locked_fields,omitempty"`
}

type InboundAuth struct {
	Header string `yaml:"header"`
	Value  string `yaml:"value"`
	Strip  bool   `yaml:"strip"`
}

type UpstreamAuth struct {
	Mode         string   `yaml:"mode"`
	Token        string   `yaml:"token,omitempty"`
	Header       string   `yaml:"header,omitempty"`
	Value        string   `yaml:"value,omitempty"`
	ClientID     string   `yaml:"client_id,omitempty"`
	ClientSecret string   `yaml:"client_secret,omitempty"`
	TokenURL     string   `yaml:"token_url,omitempty"`
	AccessToken  string   `yaml:"access_token,omitempty"`
	RefreshToken string   `yaml:"refresh_token,omitempty"`
	Scopes       []string `yaml:"scopes,omitempty"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	expanded := os.ExpandEnv(string(data))

	var cfg Config
	if err := yaml.Unmarshal([]byte(expanded), &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	if cfg.Server.Listen == "" {
		cfg.Server.Listen = ":4000"
	}

	// grant_db is required
	if cfg.Server.GrantDB == "" {
		return nil, fmt.Errorf("server.grant_db is required")
	}

	// Mode is required
	switch cfg.Server.Mode {
	case "passthrough", "gated":
	case "":
		return nil, fmt.Errorf("server.mode is required (must be passthrough or gated)")
	default:
		return nil, fmt.Errorf("server.mode: invalid value %q (must be passthrough or gated)", cfg.Server.Mode)
	}

	// Forward proxy defaults
	if cfg.ForwardProxy.Enabled && len(cfg.ForwardProxy.AllowedPorts) == 0 {
		cfg.ForwardProxy.AllowedPorts = []int{80, 443}
	}

	// Validate management API allowed CIDRs
	for _, cidr := range cfg.Server.ManagementAPIAllowedCIDRs {
		_, _, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("server.management_api_allowed_cidrs: invalid CIDR %q: %w", cidr, err)
		}
	}

	// Validate DeClaw config
	if err := ValidateDeclawConfig(&cfg.DeClaw); err != nil {
		return nil, err
	}

	// Sort routes by path length descending (longest prefix first)
	sort.Slice(cfg.Routes, func(i, j int) bool {
		return len(cfg.Routes[i].Path) > len(cfg.Routes[j].Path)
	})

	// Validate routes
	for i, r := range cfg.Routes {
		if r.Path == "" {
			return nil, fmt.Errorf("route %d: path is required", i)
		}
		if r.Upstream == "" {
			return nil, fmt.Errorf("route %d (%s): upstream is required", i, r.Path)
		}
		switch r.UpstreamAuth.Mode {
		case "static_bearer":
			if r.UpstreamAuth.Token == "" {
				return nil, fmt.Errorf("route %s: static_bearer requires token", r.Path)
			}
		case "static_api_key":
			if r.UpstreamAuth.Header == "" || r.UpstreamAuth.Value == "" {
				return nil, fmt.Errorf("route %s: static_api_key requires header and value", r.Path)
			}
		case "oauth_refresh_token":
			if r.UpstreamAuth.ClientID == "" || r.UpstreamAuth.ClientSecret == "" || r.UpstreamAuth.TokenURL == "" {
				return nil, fmt.Errorf("route %s: oauth_refresh_token requires client_id, client_secret, token_url", r.Path)
			}
		case "oauth_client_credentials":
			if r.UpstreamAuth.ClientID == "" || r.UpstreamAuth.ClientSecret == "" || r.UpstreamAuth.TokenURL == "" {
				return nil, fmt.Errorf("route %s: oauth_client_credentials requires client_id, client_secret, token_url", r.Path)
			}
		case "":
			// Routes are optional in gated mode (may only use forward proxy)
		default:
			return nil, fmt.Errorf("route %s: unknown auth mode %q", r.Path, r.UpstreamAuth.Mode)
		}

		// Validate approval mode
		switch r.Approval {
		case "", "required", "auto", "notify-only":
		default:
			return nil, fmt.Errorf("route %s: invalid approval mode %q (must be required, auto, or notify-only)", r.Path, r.Approval)
		}

		// Default approval to "required" when mode is "gated" and approval is empty
		if cfg.Server.Mode == "gated" && r.Approval == "" {
			cfg.Routes[i].Approval = "required"
		}

		// Validate approval_timeout
		if r.ApprovalTimeout != "" {
			if _, err := time.ParseDuration(r.ApprovalTimeout); err != nil {
				return nil, fmt.Errorf("route %s: invalid approval_timeout %q: %w", r.Path, r.ApprovalTimeout, err)
			}
		}

		// Validate locked_fields
		validLockedFields := map[string]bool{
			"upstream": true, "upstream_auth": true, "inbound_auth": true,
			"extra_headers": true, "path": true, "none": true,
		}
		for _, f := range r.LockedFields {
			if !validLockedFields[f] {
				return nil, fmt.Errorf("route %s: invalid locked_field %q (must be one of: upstream, upstream_auth, inbound_auth, extra_headers, path, none)", r.Path, f)
			}
		}
	}

	return &cfg, nil
}
