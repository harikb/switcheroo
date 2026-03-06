package main

import (
	"strings"
	"sync"
	"time"
)

const (
	GrantTypeLiteral    = "literal"
	GrantTypePathPrefix = "path_prefix"
	GrantTypeDomain     = "domain"
)

// Grant represents a permission for a specific request pattern.
type Grant struct {
	ID         string        `json:"id"`
	Type       string        `json:"type"`
	Domain     string        `json:"domain,omitempty"`
	PathPrefix string        `json:"path_prefix,omitempty"`
	Method     string        `json:"method,omitempty"`
	URL        string        `json:"url,omitempty"`
	GrantedAt  time.Time     `json:"granted_at"`
	Duration   time.Duration `json:"duration,omitempty"`
	ExpiresAt  time.Time     `json:"expires_at,omitempty"`
	OneShot    bool          `json:"one_shot,omitempty"`
	Source     string        `json:"source"`
	Signature  []byte        `json:"signature,omitempty"`
}

// isExpired returns true if the grant has a non-zero expiry that is in the past.
func (g *Grant) isExpired() bool {
	if g.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(g.ExpiresAt)
}

// matchesDomain returns true if the pattern matches the given domain.
// Supports wildcard domains like "*.example.com".
func matchesDomain(pattern, domain string) bool {
	if pattern == domain {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // e.g., ".example.com"
		return strings.HasSuffix(domain, suffix) && domain != pattern[2:]
	}
	return false
}

// GrantStore defines the interface for grant storage and retrieval.
type GrantStore interface {
	Add(grant *Grant)
	Remove(id string)
	FindMatch(method, url, domain, path string) *Grant
	List() []*Grant
	RemoveBySource(source string)
}

// InMemoryGrantStore is a thread-safe in-memory implementation of GrantStore.
type InMemoryGrantStore struct {
	mu     sync.Mutex
	grants map[string]*Grant
}

func NewInMemoryGrantStore() *InMemoryGrantStore {
	return &InMemoryGrantStore{
		grants: make(map[string]*Grant),
	}
}

func (s *InMemoryGrantStore) Add(grant *Grant) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.grants[grant.ID] = grant
}

func (s *InMemoryGrantStore) Remove(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.grants, id)
}

func (s *InMemoryGrantStore) RemoveBySource(source string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, g := range s.grants {
		if g.Source == source {
			delete(s.grants, id)
		}
	}
}

func (s *InMemoryGrantStore) List() []*Grant {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]*Grant, 0, len(s.grants))
	for _, g := range s.grants {
		result = append(result, g)
	}
	return result
}

// FindMatch finds the best matching grant for the given request parameters.
// Priority: literal > path_prefix > domain.
// If the matched grant is one-shot, it is consumed (removed) atomically.
func (s *InMemoryGrantStore) FindMatch(method, url, domain, path string) *Grant {
	s.mu.Lock()
	defer s.mu.Unlock()

	var bestLiteral, bestPrefix, bestDomain *Grant

	for _, g := range s.grants {
		if g.isExpired() {
			continue
		}
		if g.Method != "" && g.Method != method {
			continue
		}

		switch g.Type {
		case GrantTypeLiteral:
			if g.URL == url {
				bestLiteral = g
			}
		case GrantTypePathPrefix:
			if matchesDomain(g.Domain, domain) && matchesPathPrefix(g.PathPrefix, path) {
				if bestPrefix == nil || len(g.PathPrefix) > len(bestPrefix.PathPrefix) {
					bestPrefix = g
				}
			}
		case GrantTypeDomain:
			if matchesDomain(g.Domain, domain) {
				bestDomain = g
			}
		}
	}

	var match *Grant
	switch {
	case bestLiteral != nil:
		match = bestLiteral
	case bestPrefix != nil:
		match = bestPrefix
	case bestDomain != nil:
		match = bestDomain
	default:
		return nil
	}

	if match.OneShot {
		delete(s.grants, match.ID)
	}

	return match
}

// matchesPathPrefix checks if the given path matches the prefix.
// The path must either equal the prefix or have the prefix followed by '/'.
func matchesPathPrefix(prefix, path string) bool {
	if path == prefix {
		return true
	}
	return strings.HasPrefix(path, prefix+"/")
}
