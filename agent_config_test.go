package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAgentConfigNonexistent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nonexistent.yaml")
	cfg, err := LoadAgentConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Routes) != 0 {
		t.Fatalf("expected 0 routes, got %d", len(cfg.Routes))
	}
}

func TestLoadAgentConfigValid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent_config.yaml")
	content := `routes:
  - path: /api
    upstream: https://api.example.com
    approval: required
    _meta:
      source: agent
      agent_id: test-agent
      approved_at: "2024-01-01T00:00:00Z"
      request_id: req-123
`
	os.WriteFile(path, []byte(content), 0644)

	cfg, err := LoadAgentConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(cfg.Routes))
	}
	if cfg.Routes[0].Path != "/api" {
		t.Fatalf("expected /api, got %s", cfg.Routes[0].Path)
	}
	if cfg.Routes[0].Meta.RequestID != "req-123" {
		t.Fatalf("expected req-123, got %s", cfg.Routes[0].Meta.RequestID)
	}
}

func TestLoadAgentConfigMalformed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent_config.yaml")
	os.WriteFile(path, []byte("not: [valid: yaml: {{"), 0644)

	_, err := LoadAgentConfig(path)
	if err == nil {
		t.Fatal("expected error for malformed YAML")
	}
}

func TestAgentConfigAddAndSave(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent_config.yaml")

	cfg, _ := LoadAgentConfig(path)
	err := cfg.AddRoute(Route{
		Path:     "/test",
		Upstream: "https://test.example.com",
	}, AgentRouteMeta{
		Source:    "agent",
		RequestID: "req-add",
	})
	if err != nil {
		t.Fatalf("AddRoute: %v", err)
	}

	// Verify persisted to disk
	reloaded, err := LoadAgentConfig(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(reloaded.Routes) != 1 {
		t.Fatalf("expected 1 route after reload, got %d", len(reloaded.Routes))
	}
	if reloaded.Routes[0].Path != "/test" {
		t.Fatalf("expected /test, got %s", reloaded.Routes[0].Path)
	}
	// Verify approval forced to "required"
	if reloaded.Routes[0].Approval != "required" {
		t.Fatalf("expected approval=required, got %s", reloaded.Routes[0].Approval)
	}
}

func TestAgentConfigRemoveRoute(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent_config.yaml")

	cfg, _ := LoadAgentConfig(path)
	cfg.AddRoute(Route{Path: "/a", Upstream: "https://a.com"}, AgentRouteMeta{RequestID: "req-a"})
	cfg.AddRoute(Route{Path: "/b", Upstream: "https://b.com"}, AgentRouteMeta{RequestID: "req-b"})

	removed, err := cfg.RemoveRoute("req-a")
	if err != nil {
		t.Fatalf("RemoveRoute: %v", err)
	}
	if !removed {
		t.Fatal("expected route to be removed")
	}

	routes := cfg.ListRoutes()
	if len(routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(routes))
	}
	if routes[0].Meta.RequestID != "req-b" {
		t.Fatalf("expected req-b, got %s", routes[0].Meta.RequestID)
	}
}

func TestAgentConfigRemoveRouteNotFound(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent_config.yaml")

	cfg, _ := LoadAgentConfig(path)
	removed, err := cfg.RemoveRoute("nonexistent")
	if err != nil {
		t.Fatalf("RemoveRoute: %v", err)
	}
	if removed {
		t.Fatal("expected not removed")
	}
}

func TestMergeIntoRoutes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent_config.yaml")

	cfg, _ := LoadAgentConfig(path)
	cfg.AddRoute(Route{Path: "/agent", Upstream: "https://agent.com", Approval: "auto"}, AgentRouteMeta{RequestID: "req-1"})

	base := []Route{
		{Path: "/base", Upstream: "https://base.com"},
	}
	merged := cfg.MergeIntoRoutes(base)
	if len(merged) != 2 {
		t.Fatalf("expected 2 routes, got %d", len(merged))
	}
	// Agent route should have approval forced to "required"
	if merged[1].Approval != "required" {
		t.Fatalf("expected approval=required for agent route, got %s", merged[1].Approval)
	}
	// Base routes should be unchanged
	if merged[0].Path != "/base" {
		t.Fatalf("expected /base, got %s", merged[0].Path)
	}
}

func TestValidateLockedFieldsLockedRoute(t *testing.T) {
	routes := []Route{
		{Path: "/locked", Upstream: "https://locked.com", Locked: true},
	}
	proposal := &ConfigProposal{
		AddRoute: &Route{Path: "/locked", Upstream: "https://other.com"},
	}
	err := ValidateLockedFields(proposal, routes)
	if err == nil {
		t.Fatal("expected error for locked route")
	}
}

func TestValidateLockedFieldsLockedField(t *testing.T) {
	routes := []Route{
		{Path: "/partial", Upstream: "https://partial.com", LockedFields: []string{"upstream"}},
	}
	proposal := &ConfigProposal{
		AddRoute: &Route{Path: "/partial", Upstream: "https://different.com"},
	}
	err := ValidateLockedFields(proposal, routes)
	if err == nil {
		t.Fatal("expected error for locked upstream field")
	}
}

func TestValidateLockedFieldsImplicitCredentialLock(t *testing.T) {
	routes := []Route{
		{Path: "/creds", Upstream: "https://creds.com", UpstreamAuth: UpstreamAuth{Mode: "static_bearer", Token: "secret"}},
	}
	proposal := &ConfigProposal{
		AddRoute: &Route{Path: "/creds", UpstreamAuth: UpstreamAuth{Mode: "static_bearer", Token: "new"}},
	}
	err := ValidateLockedFields(proposal, routes)
	if err == nil {
		t.Fatal("expected error for implicit upstream_auth lock")
	}
}

func TestValidateLockedFieldsNoneDisablesImplicit(t *testing.T) {
	routes := []Route{
		{Path: "/open", Upstream: "https://open.com", LockedFields: []string{"none"}},
	}
	proposal := &ConfigProposal{
		AddRoute: &Route{Path: "/open", UpstreamAuth: UpstreamAuth{Mode: "static_bearer", Token: "new"}},
	}
	err := ValidateLockedFields(proposal, routes)
	if err != nil {
		t.Fatalf("expected no error with none locked_fields, got: %v", err)
	}
}

func TestValidateLockedFieldsNewRoute(t *testing.T) {
	routes := []Route{
		{Path: "/existing", Upstream: "https://existing.com", Locked: true},
	}
	proposal := &ConfigProposal{
		AddRoute: &Route{Path: "/new-route", Upstream: "https://new.com"},
	}
	err := ValidateLockedFields(proposal, routes)
	if err != nil {
		t.Fatalf("expected no error for new route, got: %v", err)
	}
}

func TestValidateLockedFieldsNilProposal(t *testing.T) {
	err := ValidateLockedFields(nil, []Route{})
	if err != nil {
		t.Fatalf("expected no error for nil proposal, got: %v", err)
	}
}
