package main

import (
	"path/filepath"
	"testing"
	"time"
)

func TestSQLiteGrantStoreBasicCRUD(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	store, err := NewSQLiteGrantStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	now := time.Now().Add(-10 * time.Second)
	g := &Grant{
		ID:        "declaw-1",
		Type:      GrantTypeDomain,
		Domain:    "example.com",
		Source:    "declaw",
		GrantedAt: now,
	}
	store.Add(g)

	// Should find match
	match := store.FindMatch("GET", "", "example.com", "/")
	if match == nil || match.ID != "declaw-1" {
		t.Fatal("expected to find declaw-1")
	}

	// List should return it
	list := store.List()
	if len(list) != 1 {
		t.Fatalf("expected 1 grant, got %d", len(list))
	}

	// Remove
	store.Remove("declaw-1")
	match = store.FindMatch("GET", "", "example.com", "/")
	if match != nil {
		t.Fatal("expected nil after removal")
	}
}

func TestSQLiteGrantStorePolicyNotPersisted(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	store, err := NewSQLiteGrantStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	// Add a policy grant — should be in memory but NOT in DB
	store.Add(&Grant{
		ID:     "policy-0",
		Type:   GrantTypeDomain,
		Domain: "httpbin.org",
		Source: "policy",
	})

	// Should find in memory
	match := store.FindMatch("GET", "", "httpbin.org", "/")
	if match == nil {
		t.Fatal("expected to find policy grant in memory")
	}

	// Open a second store on same DB — policy grant should NOT be there
	store2, err := NewSQLiteGrantStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create second store: %v", err)
	}
	defer store2.Close()

	match = store2.FindMatch("GET", "", "httpbin.org", "/")
	if match != nil {
		t.Fatal("policy grants should not be persisted to DB")
	}
}

func TestSQLiteGrantStoreDeclawPersisted(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	store, err := NewSQLiteGrantStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	now := time.Now().Add(-10 * time.Second)
	store.Add(&Grant{
		ID:        "declaw-persist",
		Type:      GrantTypeDomain,
		Domain:    "persist.com",
		Source:    "declaw",
		GrantedAt: now,
		Duration:  1 * time.Hour,
		ExpiresAt: now.Add(1 * time.Hour),
	})
	store.Close()

	// Re-open — should load from DB
	store2, err := NewSQLiteGrantStore(dbPath)
	if err != nil {
		t.Fatalf("failed to reopen store: %v", err)
	}
	defer store2.Close()

	match := store2.FindMatch("GET", "", "persist.com", "/")
	if match == nil {
		t.Fatal("expected declaw grant to persist across restarts")
	}
	if match.ID != "declaw-persist" {
		t.Fatalf("expected declaw-persist, got %s", match.ID)
	}
	if match.Duration != 1*time.Hour {
		t.Fatalf("expected 1h duration, got %v", match.Duration)
	}
}

func TestSQLiteGrantStoreExpiredPurgedOnStartup(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	store, err := NewSQLiteGrantStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	// Add an already-expired grant
	past := time.Now().Add(-2 * time.Hour)
	store.Add(&Grant{
		ID:        "declaw-expired",
		Type:      GrantTypeDomain,
		Domain:    "expired.com",
		Source:    "declaw",
		GrantedAt: past,
		Duration:  30 * time.Minute,
		ExpiresAt: past.Add(30 * time.Minute), // 1.5h ago
	})

	// Add a still-valid grant
	now := time.Now().Add(-10 * time.Second)
	store.Add(&Grant{
		ID:        "declaw-valid",
		Type:      GrantTypeDomain,
		Domain:    "valid.com",
		Source:    "declaw",
		GrantedAt: now,
		Duration:  1 * time.Hour,
		ExpiresAt: now.Add(1 * time.Hour),
	})
	store.Close()

	// Re-open — expired should be purged
	store2, err := NewSQLiteGrantStore(dbPath)
	if err != nil {
		t.Fatalf("failed to reopen store: %v", err)
	}
	defer store2.Close()

	list := store2.List()
	if len(list) != 1 {
		t.Fatalf("expected 1 grant after purge, got %d", len(list))
	}
	if list[0].ID != "declaw-valid" {
		t.Fatalf("expected declaw-valid to survive, got %s", list[0].ID)
	}
}

func TestSQLiteGrantStoreNoExpiryNotPurged(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	store, err := NewSQLiteGrantStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	// Grant with no expiry
	store.Add(&Grant{
		ID:        "declaw-forever",
		Type:      GrantTypeDomain,
		Domain:    "forever.com",
		Source:    "declaw",
		GrantedAt: time.Now().Add(-10 * time.Second),
	})
	store.Close()

	store2, err := NewSQLiteGrantStore(dbPath)
	if err != nil {
		t.Fatalf("failed to reopen store: %v", err)
	}
	defer store2.Close()

	match := store2.FindMatch("GET", "", "forever.com", "/")
	if match == nil {
		t.Fatal("non-expiring grant should survive restart")
	}
}

func TestSQLiteGrantStoreRemoveBySource(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	store, err := NewSQLiteGrantStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	store.Add(&Grant{ID: "p1", Type: GrantTypeDomain, Domain: "a.com", Source: "policy"})
	store.Add(&Grant{ID: "d1", Type: GrantTypeDomain, Domain: "b.com", Source: "declaw", GrantedAt: time.Now()})

	store.RemoveBySource("policy")

	list := store.List()
	if len(list) != 1 {
		t.Fatalf("expected 1 grant, got %d", len(list))
	}
	if list[0].ID != "d1" {
		t.Fatalf("expected d1 to remain, got %s", list[0].ID)
	}
}

func TestSQLiteGrantStoreRemoveDeclawFromDB(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	store, err := NewSQLiteGrantStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	store.Add(&Grant{
		ID:        "declaw-rm",
		Type:      GrantTypeDomain,
		Domain:    "rm.com",
		Source:    "declaw",
		GrantedAt: time.Now(),
	})
	store.Remove("declaw-rm")
	store.Close()

	// Re-open — should not find removed grant
	store2, err := NewSQLiteGrantStore(dbPath)
	if err != nil {
		t.Fatalf("failed to reopen store: %v", err)
	}
	defer store2.Close()

	if len(store2.List()) != 0 {
		t.Fatal("expected removed declaw grant to be gone from DB")
	}
}

func TestSQLiteGrantStorePathPrefix(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	store, err := NewSQLiteGrantStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	now := time.Now().Add(-10 * time.Second)
	store.Add(&Grant{
		ID:         "declaw-pp",
		Type:       GrantTypePathPrefix,
		Domain:     "api.stripe.com",
		PathPrefix: "/v1/charges",
		Source:     "declaw",
		GrantedAt:  now,
	})
	store.Close()

	store2, err := NewSQLiteGrantStore(dbPath)
	if err != nil {
		t.Fatalf("failed to reopen store: %v", err)
	}
	defer store2.Close()

	match := store2.FindMatch("GET", "", "api.stripe.com", "/v1/charges/ch_123")
	if match == nil || match.ID != "declaw-pp" {
		t.Fatal("expected path prefix grant to persist and match")
	}
}

func TestSQLiteGrantStoreOneShot(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	store, err := NewSQLiteGrantStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	store.Add(&Grant{
		ID:        "declaw-os",
		Type:      GrantTypeDomain,
		Domain:    "oneshot.com",
		OneShot:   true,
		Source:    "declaw",
		GrantedAt: time.Now(),
	})
	store.Close()

	store2, err := NewSQLiteGrantStore(dbPath)
	if err != nil {
		t.Fatalf("failed to reopen store: %v", err)
	}
	defer store2.Close()

	// First match consumes it
	match := store2.FindMatch("GET", "", "oneshot.com", "/")
	if match == nil {
		t.Fatal("expected one-shot grant to persist")
	}

	// Second match should fail
	match = store2.FindMatch("GET", "", "oneshot.com", "/")
	if match != nil {
		t.Fatal("expected one-shot consumed after first use")
	}
}

func TestSQLiteGrantStoreSignatureRoundTrip(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	store, err := NewSQLiteGrantStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	sig := []byte("fake-signature-data-64-bytes-padding-here-to-make-it-look-real!!")
	store.Add(&Grant{
		ID:        "declaw-sig",
		Type:      GrantTypeDomain,
		Domain:    "sig.com",
		Source:    "declaw",
		GrantedAt: time.Now(),
		Signature: sig,
	})
	store.Close()

	store2, err := NewSQLiteGrantStore(dbPath)
	if err != nil {
		t.Fatalf("failed to reopen store: %v", err)
	}
	defer store2.Close()

	match := store2.FindMatch("GET", "", "sig.com", "/")
	if match == nil {
		t.Fatal("expected to find grant")
	}
	if string(match.Signature) != string(sig) {
		t.Fatalf("expected signature round-trip, got %v", match.Signature)
	}
}

func TestSQLiteGrantStoreUsedLiterals(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	store, err := NewSQLiteGrantStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	store.Add(&Grant{
		ID:        "declaw-used",
		Type:      GrantTypeLiteral,
		URL:       "https://api.example.com/v1/thing",
		Domain:    "api.example.com",
		OneShot:   true,
		Source:    "declaw",
		GrantedAt: time.Now(),
	})

	// Consume it
	match := store.FindMatch("GET", "https://api.example.com/v1/thing", "api.example.com", "/v1/thing")
	if match == nil {
		t.Fatal("expected match")
	}

	// Should be in used_literals
	used, err := store.ListUsedLiterals()
	if err != nil {
		t.Fatalf("ListUsedLiterals: %v", err)
	}
	if len(used) != 1 {
		t.Fatalf("expected 1 used literal, got %d", len(used))
	}
	if used[0].ID != "declaw-used" {
		t.Fatalf("expected declaw-used, got %s", used[0].ID)
	}
	if used[0].UsedAt.IsZero() {
		t.Fatal("expected UsedAt to be set")
	}

	// Should not be in grants anymore
	match = store.FindMatch("GET", "https://api.example.com/v1/thing", "api.example.com", "/v1/thing")
	if match != nil {
		t.Fatal("expected one-shot consumed")
	}
}

func TestSQLiteGrantStoreUsedLiteralsEmpty(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	store, err := NewSQLiteGrantStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	used, err := store.ListUsedLiterals()
	if err != nil {
		t.Fatalf("ListUsedLiterals: %v", err)
	}
	if len(used) != 0 {
		t.Fatalf("expected 0 used literals, got %d", len(used))
	}
}

func TestSQLiteGrantStoreMethodFilter(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	store, err := NewSQLiteGrantStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	store.Add(&Grant{
		ID:        "declaw-method",
		Type:      GrantTypeDomain,
		Domain:    "api.com",
		Method:    "GET",
		Source:    "declaw",
		GrantedAt: time.Now(),
	})
	store.Close()

	store2, err := NewSQLiteGrantStore(dbPath)
	if err != nil {
		t.Fatalf("failed to reopen store: %v", err)
	}
	defer store2.Close()

	match := store2.FindMatch("GET", "", "api.com", "/")
	if match == nil {
		t.Fatal("expected GET to match")
	}

	match = store2.FindMatch("POST", "", "api.com", "/")
	if match != nil {
		t.Fatal("expected POST to not match GET-only grant")
	}
}
