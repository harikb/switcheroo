package main

import (
	"sync"
	"testing"
	"time"
)

func TestPendingRequestAddGetRemove(t *testing.T) {
	store := NewPendingRequestStore()

	pr := &PendingRequest{
		ID:        "req-1",
		Domain:    "example.com",
		Method:    "GET",
		CreatedAt: time.Now(),
		ResultCh:  make(chan struct{}),
	}

	store.Add(pr)

	got := store.Get("req-1")
	if got == nil {
		t.Fatal("expected to find pending request")
	}
	if got.ID != "req-1" {
		t.Fatalf("expected req-1, got %s", got.ID)
	}

	store.Remove("req-1")

	got = store.Get("req-1")
	if got != nil {
		t.Fatal("expected nil after removal")
	}
}

func TestPendingRequestResolve(t *testing.T) {
	store := NewPendingRequestStore()

	pr := &PendingRequest{
		ID:       "req-2",
		Domain:   "example.com",
		ResultCh: make(chan struct{}),
	}
	store.Add(pr)

	result := ApprovalResult{
		Approved: true,
		Grant: &Grant{
			ID:     "grant-1",
			Type:   GrantTypeDomain,
			Domain: "example.com",
			Source: "declaw",
		},
	}
	store.Resolve("req-2", result)

	// Check channel received the result
	select {
	case <-pr.ResultCh:
		got := pr.Result
		if !got.Approved {
			t.Fatal("expected approved")
		}
		if got.Grant.Domain != "example.com" {
			t.Fatalf("expected example.com, got %s", got.Grant.Domain)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for result")
	}

	// Verify removed from store
	if store.Get("req-2") != nil {
		t.Fatal("expected request removed after resolve")
	}
}

func TestResolveNonexistentIsNoop(t *testing.T) {
	store := NewPendingRequestStore()

	// Should not panic
	store.Resolve("nonexistent", ApprovalResult{Approved: false})
}

func TestConcurrentResolve(t *testing.T) {
	store := NewPendingRequestStore()

	pr := &PendingRequest{
		ID:       "req-3",
		ResultCh: make(chan struct{}),
	}
	store.Add(pr)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			store.Resolve("req-3", ApprovalResult{Approved: true})
		}()
	}

	wg.Wait()

	// Should be resolved
	select {
	case <-pr.ResultCh:
		if !pr.Result.Approved {
			t.Fatal("expected approved")
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for result")
	}
}

func TestFindByDomain(t *testing.T) {
	store := NewPendingRequestStore()

	pr := &PendingRequest{
		ID:       "req-find",
		Domain:   "example.com",
		ResultCh: make(chan struct{}),
	}
	store.Add(pr)

	found := store.FindByDomain("example.com")
	if found == nil {
		t.Fatal("expected to find by domain")
	}
	if found.ID != "req-find" {
		t.Fatalf("expected req-find, got %s", found.ID)
	}

	notFound := store.FindByDomain("other.com")
	if notFound != nil {
		t.Fatal("expected nil for other domain")
	}
}

func TestCoalescingMultipleWaiters(t *testing.T) {
	store := NewPendingRequestStore()

	pr := &PendingRequest{
		ID:          "req-coal",
		Domain:      "example.com",
		ResultCh:    make(chan struct{}),
		WaiterCount: 2,
	}
	store.Add(pr)

	var wg sync.WaitGroup
	results := make([]ApprovalResult, 2)

	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = pr.Wait()
		}(i)
	}

	// Resolve after a short delay
	time.Sleep(50 * time.Millisecond)
	pr.Resolve(ApprovalResult{
		Approved: true,
		Grant:    &Grant{ID: "shared", Domain: "example.com", Source: "declaw"},
	})

	wg.Wait()

	for i, r := range results {
		if !r.Approved {
			t.Fatalf("waiter %d: expected approved", i)
		}
		if r.Grant.ID != "shared" {
			t.Fatalf("waiter %d: expected shared grant, got %s", i, r.Grant.ID)
		}
	}
}

func TestList(t *testing.T) {
	store := NewPendingRequestStore()

	store.Add(&PendingRequest{ID: "a", Domain: "a.com", ResultCh: make(chan struct{})})
	store.Add(&PendingRequest{ID: "b", Domain: "b.com", ResultCh: make(chan struct{})})

	list := store.List()
	if len(list) != 2 {
		t.Fatalf("expected 2, got %d", len(list))
	}
}
