package main

import (
	"strings"
	"testing"
	"time"
)

func TestGrantRequestStoreAddAndGet(t *testing.T) {
	store := NewGrantRequestStore()

	gr := &GrantRequest{
		ID:        "req-1",
		Status:    GrantRequestStatusPending,
		Domain:    "api.example.com",
		Reason:    "need access",
		CreatedAt: time.Now(),
	}
	store.Add(gr)

	got := store.Get("req-1")
	if got == nil {
		t.Fatal("expected to find grant request")
	}
	if got.ID != "req-1" {
		t.Fatalf("expected ID req-1, got %s", got.ID)
	}
	if got.Status != GrantRequestStatusPending {
		t.Fatalf("expected pending status, got %s", got.Status)
	}
}

func TestGrantRequestStoreGetNotFound(t *testing.T) {
	store := NewGrantRequestStore()
	got := store.Get("nonexistent")
	if got != nil {
		t.Fatal("expected nil for nonexistent request")
	}
}

func TestGrantRequestStoreList(t *testing.T) {
	store := NewGrantRequestStore()

	store.Add(&GrantRequest{ID: "req-1", Status: GrantRequestStatusPending, CreatedAt: time.Now()})
	store.Add(&GrantRequest{ID: "req-2", Status: GrantRequestStatusPending, CreatedAt: time.Now()})

	list := store.List()
	if len(list) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(list))
	}
}

func TestGrantRequestStoreResolve(t *testing.T) {
	store := NewGrantRequestStore()

	gr := &GrantRequest{
		ID:        "req-1",
		Status:    GrantRequestStatusPending,
		Domain:    "api.example.com",
		CreatedAt: time.Now(),
	}
	store.Add(gr)

	grant := &Grant{
		ID:     "declaw-req-1",
		Type:   GrantTypeDomain,
		Domain: "api.example.com",
		Source: "declaw",
	}
	store.Resolve("req-1", GrantRequestStatusApproved, grant)

	got := store.Get("req-1")
	if got.Status != GrantRequestStatusApproved {
		t.Fatalf("expected approved, got %s", got.Status)
	}
	if got.Grant == nil {
		t.Fatal("expected grant to be set")
	}
	if got.Grant.ID != "declaw-req-1" {
		t.Fatalf("expected grant ID declaw-req-1, got %s", got.Grant.ID)
	}
	if got.ResolvedAt.IsZero() {
		t.Fatal("expected ResolvedAt to be set")
	}
}

func TestGrantRequestStoreResolveDenied(t *testing.T) {
	store := NewGrantRequestStore()

	store.Add(&GrantRequest{
		ID:        "req-1",
		Status:    GrantRequestStatusPending,
		CreatedAt: time.Now(),
	})

	store.Resolve("req-1", GrantRequestStatusDenied, nil)

	got := store.Get("req-1")
	if got.Status != GrantRequestStatusDenied {
		t.Fatalf("expected denied, got %s", got.Status)
	}
	if got.Grant != nil {
		t.Fatal("expected no grant for denied request")
	}
}

func TestGrantRequestStoreResolveNonexistent(t *testing.T) {
	store := NewGrantRequestStore()
	// Should not panic
	store.Resolve("nonexistent", GrantRequestStatusDenied, nil)
}

func TestGrantRequestStoreCleanup(t *testing.T) {
	store := NewGrantRequestStore()

	// Add a resolved request with old resolution time
	gr := &GrantRequest{
		ID:         "old-req",
		Status:     GrantRequestStatusApproved,
		CreatedAt:  time.Now().Add(-20 * time.Minute),
		ResolvedAt: time.Now().Add(-15 * time.Minute), // resolved 15 min ago, beyond retention
	}
	store.mu.Lock()
	store.requests[gr.ID] = gr
	store.mu.Unlock()

	// Add a recent pending request
	store.Add(&GrantRequest{
		ID:        "new-req",
		Status:    GrantRequestStatusPending,
		CreatedAt: time.Now(),
	})

	// Get should trigger cleanup
	list := store.List()
	if len(list) != 1 {
		t.Fatalf("expected 1 request after cleanup, got %d", len(list))
	}
	if list[0].ID != "new-req" {
		t.Fatalf("expected new-req to survive cleanup, got %s", list[0].ID)
	}
}

func TestGrantRequestStoreCleanupRetainsRecent(t *testing.T) {
	store := NewGrantRequestStore()

	// Add a resolved request within retention period
	gr := &GrantRequest{
		ID:         "recent-req",
		Status:     GrantRequestStatusApproved,
		CreatedAt:  time.Now().Add(-5 * time.Minute),
		ResolvedAt: time.Now().Add(-1 * time.Minute), // resolved 1 min ago, within retention
	}
	store.mu.Lock()
	store.requests[gr.ID] = gr
	store.mu.Unlock()

	list := store.List()
	if len(list) != 1 {
		t.Fatalf("expected 1 request (recent resolved should be retained), got %d", len(list))
	}
}

func TestSanitizeReason(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "normal text",
			input:    "Need to check payment status",
			expected: "Need to check payment status",
		},
		{
			name:     "control characters stripped",
			input:    "test\x00\x01\x02reason",
			expected: "testreason",
		},
		{
			name:     "newlines preserved",
			input:    "line1\nline2",
			expected: "line1\nline2",
		},
		{
			name:     "truncated to max length",
			input:    strings.Repeat("a", 600),
			expected: strings.Repeat("a", 500),
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeReason(tt.input)
			if got != tt.expected {
				t.Errorf("sanitizeReason(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}
