package main

import (
	"sync"
	"testing"
	"time"
)

func TestLiteralMatch(t *testing.T) {
	store := NewInMemoryGrantStore()
	store.Add(&Grant{
		ID:     "l1",
		Type:   GrantTypeLiteral,
		URL:    "https://api.stripe.com/v1/charges",
		Method: "POST",
		Source: "policy",
	})

	l := store.FindMatch("POST", "https://api.stripe.com/v1/charges", "api.stripe.com", "/v1/charges")
	if l == nil || l.ID != "l1" {
		t.Fatal("expected literal match")
	}

	l = store.FindMatch("GET", "https://api.stripe.com/v1/charges", "api.stripe.com", "/v1/charges")
	if l != nil {
		t.Fatal("expected no match for wrong method")
	}

	l = store.FindMatch("POST", "https://api.stripe.com/v1/charges/ch_123", "api.stripe.com", "/v1/charges/ch_123")
	if l != nil {
		t.Fatal("expected no match for different URL")
	}
}

func TestLiteralMatchNoMethod(t *testing.T) {
	store := NewInMemoryGrantStore()
	store.Add(&Grant{
		ID:     "l1",
		Type:   GrantTypeLiteral,
		URL:    "https://api.stripe.com/v1/charges",
		Source: "policy",
	})

	l := store.FindMatch("GET", "https://api.stripe.com/v1/charges", "api.stripe.com", "/v1/charges")
	if l == nil || l.ID != "l1" {
		t.Fatal("expected match with any method")
	}

	l = store.FindMatch("POST", "https://api.stripe.com/v1/charges", "api.stripe.com", "/v1/charges")
	if l == nil || l.ID != "l1" {
		t.Fatal("expected match with any method")
	}
}

func TestPathPrefixMatch(t *testing.T) {
	store := NewInMemoryGrantStore()
	store.Add(&Grant{
		ID:         "p1",
		Type:       GrantTypePathPrefix,
		Domain:     "api.stripe.com",
		PathPrefix: "/v1/charges",
		Source:     "policy",
	})

	l := store.FindMatch("GET", "", "api.stripe.com", "/v1/charges")
	if l == nil || l.ID != "p1" {
		t.Fatal("expected path prefix match on exact path")
	}

	l = store.FindMatch("GET", "", "api.stripe.com", "/v1/charges/ch_123")
	if l == nil || l.ID != "p1" {
		t.Fatal("expected path prefix match on subpath")
	}

	l = store.FindMatch("GET", "", "api.stripe.com", "/v1/charge")
	if l != nil {
		t.Fatal("expected no match for /v1/charge (not a proper prefix)")
	}

	l = store.FindMatch("GET", "", "api.other.com", "/v1/charges")
	if l != nil {
		t.Fatal("expected no match for different domain")
	}
}

func TestDomainMatch(t *testing.T) {
	store := NewInMemoryGrantStore()
	store.Add(&Grant{ID: "d1", Type: GrantTypeDomain, Domain: "httpbin.org", Source: "policy"})
	store.Add(&Grant{ID: "d2", Type: GrantTypeDomain, Domain: "*.example.com", Source: "policy"})

	l := store.FindMatch("GET", "", "httpbin.org", "/get")
	if l == nil || l.ID != "d1" {
		t.Fatal("expected exact domain match")
	}

	l = store.FindMatch("GET", "", "api.example.com", "/foo")
	if l == nil || l.ID != "d2" {
		t.Fatal("expected wildcard domain match")
	}

	l = store.FindMatch("GET", "", "example.com", "/foo")
	if l != nil {
		t.Fatal("expected no match for bare domain against wildcard")
	}

	l = store.FindMatch("GET", "", "unknown.com", "/")
	if l != nil {
		t.Fatal("expected no match")
	}
}

func TestMatchPriority(t *testing.T) {
	store := NewInMemoryGrantStore()
	store.Add(&Grant{ID: "domain", Type: GrantTypeDomain, Domain: "api.stripe.com", Source: "policy"})
	store.Add(&Grant{ID: "prefix", Type: GrantTypePathPrefix, Domain: "api.stripe.com", PathPrefix: "/v1/charges", Source: "policy"})
	store.Add(&Grant{ID: "literal", Type: GrantTypeLiteral, URL: "https://api.stripe.com/v1/charges", Source: "policy"})

	l := store.FindMatch("GET", "https://api.stripe.com/v1/charges", "api.stripe.com", "/v1/charges")
	if l == nil || l.ID != "literal" {
		t.Fatalf("expected literal match, got %v", l)
	}

	store.Remove("literal")
	l = store.FindMatch("GET", "https://api.stripe.com/v1/charges", "api.stripe.com", "/v1/charges")
	if l == nil || l.ID != "prefix" {
		t.Fatalf("expected prefix match, got %v", l)
	}

	store.Remove("prefix")
	l = store.FindMatch("GET", "https://api.stripe.com/v1/charges", "api.stripe.com", "/v1/charges")
	if l == nil || l.ID != "domain" {
		t.Fatalf("expected domain match, got %v", l)
	}
}

func TestExpiry(t *testing.T) {
	store := NewInMemoryGrantStore()

	store.Add(&Grant{
		ID: "expired", Type: GrantTypeDomain, Domain: "expired.com",
		ExpiresAt: time.Now().Add(-1 * time.Hour), Source: "declaw",
	})
	l := store.FindMatch("GET", "", "expired.com", "/")
	if l != nil {
		t.Fatal("expected no match for expired grant")
	}

	store.Add(&Grant{
		ID: "future", Type: GrantTypeDomain, Domain: "future.com",
		ExpiresAt: time.Now().Add(1 * time.Hour), Source: "declaw",
	})
	l = store.FindMatch("GET", "", "future.com", "/")
	if l == nil || l.ID != "future" {
		t.Fatal("expected match for future grant")
	}

	store.Add(&Grant{ID: "forever", Type: GrantTypeDomain, Domain: "forever.com", Source: "policy"})
	l = store.FindMatch("GET", "", "forever.com", "/")
	if l == nil || l.ID != "forever" {
		t.Fatal("expected match for non-expiring grant")
	}
}

func TestOneShotConsumption(t *testing.T) {
	store := NewInMemoryGrantStore()
	store.Add(&Grant{ID: "os1", Type: GrantTypeDomain, Domain: "oneshot.com", OneShot: true, Source: "policy"})

	l := store.FindMatch("GET", "", "oneshot.com", "/")
	if l == nil || l.ID != "os1" {
		t.Fatal("expected first match to succeed")
	}

	l = store.FindMatch("GET", "", "oneshot.com", "/")
	if l != nil {
		t.Fatal("expected second match to fail after one-shot consumed")
	}
}

func TestConcurrentOneShotSafety(t *testing.T) {
	store := NewInMemoryGrantStore()
	store.Add(&Grant{ID: "cos1", Type: GrantTypeDomain, Domain: "concurrent.com", OneShot: true, Source: "policy"})

	var wg sync.WaitGroup
	matches := make(chan string, 100)

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l := store.FindMatch("GET", "", "concurrent.com", "/")
			if l != nil {
				matches <- l.ID
			}
		}()
	}

	wg.Wait()
	close(matches)

	count := 0
	for range matches {
		count++
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 match for one-shot, got %d", count)
	}
}

func TestListGrants(t *testing.T) {
	store := NewInMemoryGrantStore()
	store.Add(&Grant{ID: "a", Type: GrantTypeDomain, Domain: "a.com", Source: "policy"})
	store.Add(&Grant{ID: "b", Type: GrantTypeDomain, Domain: "b.com", Source: "policy"})

	list := store.List()
	if len(list) != 2 {
		t.Fatalf("expected 2 grants, got %d", len(list))
	}
}

func TestRemoveBySource(t *testing.T) {
	store := NewInMemoryGrantStore()
	store.Add(&Grant{ID: "c1", Type: GrantTypeDomain, Domain: "a.com", Source: "policy"})
	store.Add(&Grant{ID: "c2", Type: GrantTypeDomain, Domain: "b.com", Source: "policy"})
	store.Add(&Grant{ID: "d1", Type: GrantTypeDomain, Domain: "c.com", Source: "declaw"})

	store.RemoveBySource("policy")

	list := store.List()
	if len(list) != 1 {
		t.Fatalf("expected 1 grant after RemoveBySource, got %d", len(list))
	}
	if list[0].ID != "d1" {
		t.Fatalf("expected d1 to remain, got %s", list[0].ID)
	}
}

func TestMethodFiltering(t *testing.T) {
	store := NewInMemoryGrantStore()
	store.Add(&Grant{
		ID: "m1", Type: GrantTypePathPrefix, Domain: "api.example.com",
		PathPrefix: "/data", Method: "GET", Source: "policy",
	})

	l := store.FindMatch("GET", "", "api.example.com", "/data/123")
	if l == nil {
		t.Fatal("expected match for GET")
	}

	l = store.FindMatch("POST", "", "api.example.com", "/data/123")
	if l != nil {
		t.Fatal("expected no match for POST with GET-only grant")
	}
}

func TestGrantedAtAndDuration(t *testing.T) {
	now := time.Now()
	g := &Grant{
		ID:        "g1",
		Type:      GrantTypeDomain,
		Domain:    "test.com",
		GrantedAt: now.Add(-10 * time.Second),
		Duration:  1 * time.Hour,
		ExpiresAt: now.Add(1*time.Hour - 10*time.Second),
		Source:    "declaw",
	}

	if g.GrantedAt.After(now) {
		t.Fatal("expected GrantedAt to be in the past")
	}
	if g.Duration != 1*time.Hour {
		t.Fatalf("expected 1h duration, got %v", g.Duration)
	}
	if g.isExpired() {
		t.Fatal("expected grant to not be expired")
	}
}
