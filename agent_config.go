package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// AgentRouteMeta contains metadata about who added an agent route and when.
type AgentRouteMeta struct {
	Source     string `yaml:"source" json:"source"`
	AgentID   string `yaml:"agent_id" json:"agent_id"`
	ApprovedAt string `yaml:"approved_at" json:"approved_at"`
	RequestID string `yaml:"request_id" json:"request_id"`
}

// AgentRoute is a route added by an agent, with metadata.
type AgentRoute struct {
	Route `yaml:",inline"`
	Meta  AgentRouteMeta `yaml:"_meta" json:"_meta"`
}

// AgentConfig holds agent-added routes, persisted to a separate YAML file.
type AgentConfig struct {
	mu     sync.Mutex
	path   string
	Routes []AgentRoute `yaml:"routes"`
}

// LoadAgentConfig loads agent config from the given path.
// Returns an empty config (not nil) if the file does not exist.
func LoadAgentConfig(path string) (*AgentConfig, error) {
	cfg := &AgentConfig{path: path}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			cfg.Routes = []AgentRoute{}
			return cfg, nil
		}
		return nil, fmt.Errorf("reading agent config: %w", err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing agent config: %w", err)
	}
	if cfg.Routes == nil {
		cfg.Routes = []AgentRoute{}
	}

	return cfg, nil
}

// Save writes the agent config to disk atomically (temp file + rename).
func (ac *AgentConfig) Save() error {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	return ac.saveLocked()
}

func (ac *AgentConfig) saveLocked() error {
	data, err := yaml.Marshal(ac)
	if err != nil {
		return fmt.Errorf("marshal agent config: %w", err)
	}

	dir := filepath.Dir(ac.path)
	tmp, err := os.CreateTemp(dir, "agent_config_*.yaml")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpName, ac.path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("rename temp file: %w", err)
	}
	return nil
}

// AddRoute adds an agent route with metadata and saves to disk.
func (ac *AgentConfig) AddRoute(route Route, meta AgentRouteMeta) error {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	// Force agent routes to approval: required
	route.Approval = "required"

	ac.Routes = append(ac.Routes, AgentRoute{
		Route: route,
		Meta:  meta,
	})
	return ac.saveLocked()
}

// RemoveRoute removes an agent route by request ID and saves to disk.
// Returns true if a route was removed.
func (ac *AgentConfig) RemoveRoute(requestID string) (bool, error) {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	for i, r := range ac.Routes {
		if r.Meta.RequestID == requestID {
			ac.Routes = append(ac.Routes[:i], ac.Routes[i+1:]...)
			return true, ac.saveLocked()
		}
	}
	return false, nil
}

// ListRoutes returns a copy of the agent routes.
func (ac *AgentConfig) ListRoutes() []AgentRoute {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	result := make([]AgentRoute, len(ac.Routes))
	copy(result, ac.Routes)
	return result
}

// MergeIntoRoutes appends agent routes to the base routes.
// All agent routes are forced to approval: required.
func (ac *AgentConfig) MergeIntoRoutes(baseRoutes []Route) []Route {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	merged := make([]Route, len(baseRoutes))
	copy(merged, baseRoutes)
	for _, ar := range ac.Routes {
		r := ar.Route
		r.Approval = "required"
		merged = append(merged, r)
	}
	return merged
}

// ConfigProposal is a config change proposal from an agent.
type ConfigProposal struct {
	AddRoute *Route `json:"add_route,omitempty"`
}

// ValidateLockedFields checks if a config proposal violates locked routes.
func ValidateLockedFields(proposal *ConfigProposal, existingRoutes []Route) error {
	if proposal == nil || proposal.AddRoute == nil {
		return nil
	}

	newRoute := proposal.AddRoute
	for _, existing := range existingRoutes {
		if existing.Path != newRoute.Path {
			continue
		}

		// Route with this path already exists
		if existing.Locked {
			return fmt.Errorf("route %s is locked and cannot be modified", existing.Path)
		}

		// Check individual locked fields
		lockedFields := existing.LockedFields
		if len(lockedFields) == 0 {
			// No locked_fields means implicit credential locks
			lockedFields = []string{"upstream_auth"}
		}
		// Special value "none" disables implicit locks
		for _, f := range existing.LockedFields {
			if f == "none" {
				lockedFields = nil
				break
			}
		}

		for _, field := range lockedFields {
			switch field {
			case "upstream":
				if newRoute.Upstream != "" && newRoute.Upstream != existing.Upstream {
					return fmt.Errorf("route %s: field 'upstream' is locked", existing.Path)
				}
			case "upstream_auth":
				if newRoute.UpstreamAuth.Mode != "" {
					return fmt.Errorf("route %s: field 'upstream_auth' is locked", existing.Path)
				}
			case "inbound_auth":
				if newRoute.InboundAuth != nil {
					return fmt.Errorf("route %s: field 'inbound_auth' is locked", existing.Path)
				}
			case "extra_headers":
				if len(newRoute.ExtraHeaders) > 0 {
					return fmt.Errorf("route %s: field 'extra_headers' is locked", existing.Path)
				}
			case "path":
				return fmt.Errorf("route %s: field 'path' is locked", existing.Path)
			}
		}
	}

	return nil
}

// formatConfigSummary returns a human-readable summary of a config proposal.
func formatConfigSummary(proposal *ConfigProposal) string {
	if proposal == nil || proposal.AddRoute == nil {
		return ""
	}
	r := proposal.AddRoute
	return fmt.Sprintf("Add route %s -> %s", r.Path, r.Upstream)
}

// newAgentRouteMeta creates metadata for an agent route.
func newAgentRouteMeta(requestID string) AgentRouteMeta {
	return AgentRouteMeta{
		Source:     "agent",
		ApprovedAt: time.Now().Format(time.RFC3339),
		RequestID: requestID,
	}
}
