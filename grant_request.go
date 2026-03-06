package main

import (
	"sync"
	"time"
	"unicode"
)

const (
	GrantRequestStatusPending  = "pending"
	GrantRequestStatusApproved = "approved"
	GrantRequestStatusDenied   = "denied"
	GrantRequestStatusTimeout  = "timeout"

	// Resolved grant requests are retained for 10 minutes before cleanup.
	grantRequestRetention = 10 * time.Minute

	// Maximum length for the reason field.
	maxReasonLength = 500
)

// GrantRequest represents a pre-approval request from an agent.
type GrantRequest struct {
	ID             string          `json:"request_id"`
	Status         string          `json:"status"`
	Domain         string          `json:"domain,omitempty"`
	PathPrefix     string          `json:"path_prefix,omitempty"`
	URL            string          `json:"url,omitempty"`
	Methods        []string        `json:"methods,omitempty"`
	Reason         string          `json:"reason"`
	Duration       string          `json:"duration,omitempty"`
	OneShot        bool            `json:"one_shot,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
	ResolvedAt     time.Time       `json:"resolved_at,omitempty"`
	Grant          *Grant          `json:"grant,omitempty"`
	ConfigProposal *ConfigProposal `json:"config,omitempty"`
}

// GrantRequestStore is a thread-safe in-memory store for grant requests.
// Resolved requests are cleaned up after the retention period.
type GrantRequestStore struct {
	mu       sync.Mutex
	requests map[string]*GrantRequest
}

// NewGrantRequestStore creates a new GrantRequestStore.
func NewGrantRequestStore() *GrantRequestStore {
	return &GrantRequestStore{
		requests: make(map[string]*GrantRequest),
	}
}

// Add stores a grant request.
func (s *GrantRequestStore) Add(gr *GrantRequest) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests[gr.ID] = gr
	s.cleanupLocked()
}

// Get retrieves a grant request by ID. Returns nil if not found.
func (s *GrantRequestStore) Get(id string) *GrantRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked()
	return s.requests[id]
}

// List returns all active grant requests (pending + recently resolved).
func (s *GrantRequestStore) List() []*GrantRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked()
	result := make([]*GrantRequest, 0, len(s.requests))
	for _, gr := range s.requests {
		result = append(result, gr)
	}
	return result
}

// Resolve updates a grant request's status and records the resolution time.
func (s *GrantRequestStore) Resolve(id, status string, grant *Grant) {
	s.mu.Lock()
	defer s.mu.Unlock()
	gr, ok := s.requests[id]
	if !ok {
		return
	}
	gr.Status = status
	gr.ResolvedAt = time.Now()
	gr.Grant = grant
}

// cleanupLocked removes resolved requests older than the retention period.
// Must be called with the lock held.
func (s *GrantRequestStore) cleanupLocked() {
	cutoff := time.Now().Add(-grantRequestRetention)
	for id, gr := range s.requests {
		if gr.Status != GrantRequestStatusPending && !gr.ResolvedAt.IsZero() && gr.ResolvedAt.Before(cutoff) {
			delete(s.requests, id)
		}
	}
}

// sanitizeReason strips control characters and truncates to maxReasonLength.
func sanitizeReason(s string) string {
	cleaned := make([]rune, 0, len(s))
	for _, r := range s {
		if unicode.IsControl(r) && r != '\n' {
			continue
		}
		cleaned = append(cleaned, r)
	}
	if len(cleaned) > maxReasonLength {
		cleaned = cleaned[:maxReasonLength]
	}
	return string(cleaned)
}
