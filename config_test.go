package main

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTestConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

// testGrantDB returns a grant_db path inside a temp dir for use in test configs.
func testGrantDB(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "test-grants.db")
}

func TestModeRequired(t *testing.T) {
	path := writeTestConfig(t, `
server:
  listen: ":5000"
  grant_db: "`+testGrantDB(t)+`"
routes:
  - path: /api
    upstream: https://api.example.com
    upstream_auth:
      mode: static_bearer
      token: secret123
`)
	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected error when mode is omitted")
	}
}

func TestGrantDBRequired(t *testing.T) {
	path := writeTestConfig(t, `
server:
  listen: ":5000"
  mode: "gated"
`)
	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected error when grant_db is omitted")
	}
}

func TestModeGated(t *testing.T) {
	path := writeTestConfig(t, `
server:
  listen: ":5000"
  mode: "gated"
  grant_db: "`+testGrantDB(t)+`"
routes:
  - path: /api
    upstream: https://api.example.com
    upstream_auth:
      mode: static_bearer
      token: secret123
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Server.Mode != "gated" {
		t.Fatalf("expected mode=gated, got %s", cfg.Server.Mode)
	}
}

func TestModePassthrough(t *testing.T) {
	path := writeTestConfig(t, `
server:
  listen: ":5000"
  mode: "passthrough"
  grant_db: "`+testGrantDB(t)+`"
routes:
  - path: /api
    upstream: https://api.example.com
    upstream_auth:
      mode: static_bearer
      token: secret123
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Server.Mode != "passthrough" {
		t.Fatalf("expected mode=passthrough, got %s", cfg.Server.Mode)
	}
}

func TestInvalidMode(t *testing.T) {
	path := writeTestConfig(t, `
server:
  mode: "invalid"
  grant_db: "`+testGrantDB(t)+`"
routes:
  - path: /api
    upstream: https://api.example.com
    upstream_auth:
      mode: static_bearer
      token: secret123
`)
	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected error for invalid mode")
	}
}

func TestPolicyConfig(t *testing.T) {
	path := writeTestConfig(t, `
server:
  listen: ":5000"
  mode: "gated"
  grant_db: "`+testGrantDB(t)+`"
policy:
  deny:
    - domain: "*.evil.com"
    - domain: "api.stripe.com"
      path_prefix: "/v1/transfers"
      methods: ["POST", "DELETE"]
  allow:
    - domain: "httpbin.org"
    - domain: "api.stripe.com"
      path_prefix: "/v1/charges"
      methods: ["GET"]
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Policy.Deny) != 2 {
		t.Fatalf("expected 2 deny rules, got %d", len(cfg.Policy.Deny))
	}
	if len(cfg.Policy.Allow) != 2 {
		t.Fatalf("expected 2 allow rules, got %d", len(cfg.Policy.Allow))
	}
	if cfg.Policy.Deny[0].Domain != "*.evil.com" {
		t.Fatalf("expected *.evil.com, got %s", cfg.Policy.Deny[0].Domain)
	}
	if cfg.Policy.Allow[0].Domain != "httpbin.org" {
		t.Fatalf("expected httpbin.org, got %s", cfg.Policy.Allow[0].Domain)
	}
}

func TestForwardProxyConfig(t *testing.T) {
	path := writeTestConfig(t, `
server:
  listen: ":5000"
  mode: "gated"
  grant_db: "`+testGrantDB(t)+`"
forward_proxy:
  enabled: true
  allowed_ports: [80, 443, 8080]
  bypass:
    - "localhost"
    - "127.0.0.1"
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.ForwardProxy.Enabled {
		t.Fatal("expected forward_proxy.enabled=true")
	}
	if len(cfg.ForwardProxy.AllowedPorts) != 3 {
		t.Fatalf("expected 3 allowed ports, got %d", len(cfg.ForwardProxy.AllowedPorts))
	}
	if len(cfg.ForwardProxy.Bypass) != 2 {
		t.Fatalf("expected 2 bypass entries, got %d", len(cfg.ForwardProxy.Bypass))
	}
}

func TestForwardProxyDefaults(t *testing.T) {
	path := writeTestConfig(t, `
server:
  listen: ":5000"
  mode: "gated"
  grant_db: "`+testGrantDB(t)+`"
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ForwardProxy.Enabled {
		t.Fatal("expected forward_proxy.enabled=false by default")
	}
}

func TestForwardProxyDefaultPorts(t *testing.T) {
	path := writeTestConfig(t, `
server:
  listen: ":5000"
  mode: "gated"
  grant_db: "`+testGrantDB(t)+`"
forward_proxy:
  enabled: true
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.ForwardProxy.AllowedPorts) != 2 {
		t.Fatalf("expected 2 default ports, got %d", len(cfg.ForwardProxy.AllowedPorts))
	}
	if cfg.ForwardProxy.AllowedPorts[0] != 80 || cfg.ForwardProxy.AllowedPorts[1] != 443 {
		t.Fatalf("expected [80,443], got %v", cfg.ForwardProxy.AllowedPorts)
	}
}

func TestServerFields(t *testing.T) {
	path := writeTestConfig(t, `
server:
  listen: ":5000"
  mode: "gated"
  grant_db: "/tmp/grants.db"
  approval_timeout: "30s"
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Server.GrantDB != "/tmp/grants.db" {
		t.Fatalf("expected grant_db, got %s", cfg.Server.GrantDB)
	}
	if cfg.Server.ApprovalTimeout != "30s" {
		t.Fatalf("expected 30s, got %s", cfg.Server.ApprovalTimeout)
	}
}

func TestDefaultListenAddress(t *testing.T) {
	path := writeTestConfig(t, `
server:
  mode: "gated"
  grant_db: "`+testGrantDB(t)+`"
routes:
  - path: /api
    upstream: https://api.example.com
    upstream_auth:
      mode: static_bearer
      token: secret123
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Server.Listen != ":4000" {
		t.Fatalf("expected default :4000, got %s", cfg.Server.Listen)
	}
}

func TestDeclawConfigOmitted(t *testing.T) {
	path := writeTestConfig(t, `
server:
  listen: ":5000"
  mode: "gated"
  grant_db: "`+testGrantDB(t)+`"
routes:
  - path: /api
    upstream: https://api.example.com
    upstream_auth:
      mode: static_bearer
      token: secret123
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.DeClaw.Enabled {
		t.Fatal("expected declaw disabled by default")
	}
}

func TestDeclawConfigEnabled(t *testing.T) {
	path := writeTestConfig(t, `
server:
  listen: ":5000"
  mode: "gated"
  grant_db: "`+testGrantDB(t)+`"
declaw:
  enabled: true
  gateway_url: "https://declawapp.com"
  proxy_id: "prx_123"
  proxy_api_key: "dk_live_xxx"
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.DeClaw.Enabled {
		t.Fatal("expected declaw enabled")
	}
	if cfg.DeClaw.GatewayURL != "https://declawapp.com" {
		t.Fatalf("expected gateway_url, got %s", cfg.DeClaw.GatewayURL)
	}
}

func TestDeclawConfigEnabledNoGateway(t *testing.T) {
	path := writeTestConfig(t, `
server:
  listen: ":5000"
  mode: "gated"
  grant_db: "`+testGrantDB(t)+`"
declaw:
  enabled: true
`)
	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected error when declaw enabled without gateway_url")
	}
}

func TestDeclawConfigEnvExpansion(t *testing.T) {
	t.Setenv("TEST_DECLAW_KEY", "dk_live_secret")
	path := writeTestConfig(t, `
server:
  listen: ":5000"
  mode: "gated"
  grant_db: "`+testGrantDB(t)+`"
declaw:
  enabled: true
  gateway_url: "https://declawapp.com"
  proxy_api_key: "${TEST_DECLAW_KEY}"
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.DeClaw.ProxyAPIKey != "dk_live_secret" {
		t.Fatalf("expected env expansion, got %s", cfg.DeClaw.ProxyAPIKey)
	}
}

func TestManagementAPIAllowedCIDRsValid(t *testing.T) {
	path := writeTestConfig(t, `
server:
  mode: "gated"
  grant_db: "`+testGrantDB(t)+`"
  management_api_allowed_cidrs:
    - "172.16.0.0/12"
    - "10.0.0.0/8"
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Server.ManagementAPIAllowedCIDRs) != 2 {
		t.Fatalf("expected 2 CIDRs, got %d", len(cfg.Server.ManagementAPIAllowedCIDRs))
	}
}

func TestManagementAPIAllowedCIDRsInvalid(t *testing.T) {
	path := writeTestConfig(t, `
server:
  mode: "gated"
  grant_db: "`+testGrantDB(t)+`"
  management_api_allowed_cidrs:
    - "not-a-cidr"
`)
	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

func TestManagementAPIAllowedCIDRsEmpty(t *testing.T) {
	path := writeTestConfig(t, `
server:
  mode: "gated"
  grant_db: "`+testGrantDB(t)+`"
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Server.ManagementAPIAllowedCIDRs) != 0 {
		t.Fatalf("expected 0 CIDRs, got %d", len(cfg.Server.ManagementAPIAllowedCIDRs))
	}
}

func TestApprovalModeValid(t *testing.T) {
	for _, mode := range []string{"required", "auto", "notify-only"} {
		t.Run(mode, func(t *testing.T) {
			path := writeTestConfig(t, `
server:
  mode: "gated"
  grant_db: "`+testGrantDB(t)+`"
routes:
  - path: /api
    upstream: https://api.example.com
    upstream_auth:
      mode: static_bearer
      token: secret123
    approval: "`+mode+`"
`)
			cfg, err := LoadConfig(path)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cfg.Routes[0].Approval != mode {
				t.Fatalf("expected approval=%s, got %s", mode, cfg.Routes[0].Approval)
			}
		})
	}
}

func TestApprovalModeInvalid(t *testing.T) {
	path := writeTestConfig(t, `
server:
  mode: "gated"
  grant_db: "`+testGrantDB(t)+`"
routes:
  - path: /api
    upstream: https://api.example.com
    upstream_auth:
      mode: static_bearer
      token: secret123
    approval: "invalid"
`)
	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected error for invalid approval mode")
	}
}

func TestApprovalModeDefaultsToRequired(t *testing.T) {
	path := writeTestConfig(t, `
server:
  mode: "gated"
  grant_db: "`+testGrantDB(t)+`"
routes:
  - path: /api
    upstream: https://api.example.com
    upstream_auth:
      mode: static_bearer
      token: secret123
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Routes[0].Approval != "required" {
		t.Fatalf("expected approval=required (default for gated), got %s", cfg.Routes[0].Approval)
	}
}

func TestApprovalTimeoutValid(t *testing.T) {
	path := writeTestConfig(t, `
server:
  mode: "gated"
  grant_db: "`+testGrantDB(t)+`"
routes:
  - path: /api
    upstream: https://api.example.com
    upstream_auth:
      mode: static_bearer
      token: secret123
    approval_timeout: "30s"
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Routes[0].ApprovalTimeout != "30s" {
		t.Fatalf("expected 30s, got %s", cfg.Routes[0].ApprovalTimeout)
	}
}

func TestApprovalTimeoutInvalid(t *testing.T) {
	path := writeTestConfig(t, `
server:
  mode: "gated"
  grant_db: "`+testGrantDB(t)+`"
routes:
  - path: /api
    upstream: https://api.example.com
    upstream_auth:
      mode: static_bearer
      token: secret123
    approval_timeout: "not-a-duration"
`)
	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected error for invalid approval_timeout")
	}
}

func TestLockedFieldsValid(t *testing.T) {
	path := writeTestConfig(t, `
server:
  mode: "gated"
  grant_db: "`+testGrantDB(t)+`"
routes:
  - path: /api
    upstream: https://api.example.com
    upstream_auth:
      mode: static_bearer
      token: secret123
    locked_fields: ["upstream", "upstream_auth", "path"]
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Routes[0].LockedFields) != 3 {
		t.Fatalf("expected 3 locked fields, got %d", len(cfg.Routes[0].LockedFields))
	}
}

func TestLockedFieldsInvalid(t *testing.T) {
	path := writeTestConfig(t, `
server:
  mode: "gated"
  grant_db: "`+testGrantDB(t)+`"
routes:
  - path: /api
    upstream: https://api.example.com
    upstream_auth:
      mode: static_bearer
      token: secret123
    locked_fields: ["bogus"]
`)
	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected error for invalid locked_field")
	}
}

func TestLockedRoute(t *testing.T) {
	path := writeTestConfig(t, `
server:
  mode: "gated"
  grant_db: "`+testGrantDB(t)+`"
routes:
  - path: /api
    upstream: https://api.example.com
    upstream_auth:
      mode: static_bearer
      token: secret123
    locked: true
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.Routes[0].Locked {
		t.Fatal("expected locked=true")
	}
}

func TestGatedNoRoutes(t *testing.T) {
	path := writeTestConfig(t, `
server:
  mode: "gated"
  grant_db: "`+testGrantDB(t)+`"
policy:
  allow:
    - domain: "httpbin.org"
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Routes) != 0 {
		t.Fatalf("expected 0 routes, got %d", len(cfg.Routes))
	}
}
