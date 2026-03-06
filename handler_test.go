package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// mockGatewayServer returns a test server that accepts notify requests.
func mockGatewayServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(NotifyResponse{APNSID: "apns-test"})
	}))
}

// newTestDeclawClient creates a GatewayClient for testing that will resolve via the given store.
func newTestDeclawClient(gatewayURL string, store *PendingRequestStore, phonePub interface{}) *GatewayClient {
	_, pub, _ := GenerateX25519KeyPair()
	return &GatewayClient{
		gatewayURL:         gatewayURL,
		apiKey:             "dk_test",
		httpClient:         &http.Client{Timeout: 5 * time.Second},
		pendingStore:       store,
		phoneEncryptionKey: pub,
		approvalTimeout:    200 * time.Millisecond,
	}
}

// fakeAuth is a test AuthProvider that sets a fixed header.
type fakeAuth struct{}

func (f *fakeAuth) ApplyAuth(req *http.Request) error {
	req.Header.Set("Authorization", "Bearer fake-token")
	return nil
}
func (f *fakeAuth) ForceRefresh() (bool, error) { return false, nil }

func newTestHandler(t *testing.T, mode string, routes []Route, grantStore GrantStore, denyList *DenyList, upstream *httptest.Server) *ProxyHandler {
	t.Helper()

	var entries []routeEntry
	for _, r := range routes {
		u, _ := parseURL(upstream.URL)
		entries = append(entries, routeEntry{
			route:    r,
			auth:     &fakeAuth{},
			upstream: u,
		})
	}

	if grantStore == nil {
		grantStore = NewInMemoryGrantStore()
	}
	if denyList == nil {
		denyList = NewDenyList(nil)
	}

	return &ProxyHandler{
		routes:     entries,
		mode:       mode,
		grantStore: grantStore,
		denyList:   denyList,
	}
}

func TestPassthroughMode(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	h := newTestHandler(t, "passthrough", []Route{
		{Path: "/api", Upstream: upstream.URL},
	}, nil, nil, upstream)

	req := httptest.NewRequest("GET", "/api/test", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if w.Body.String() != "ok" {
		t.Fatalf("expected ok, got %s", w.Body.String())
	}
}

func TestGatedWithGrant(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("allowed"))
	}))
	defer upstream.Close()

	store := NewInMemoryGrantStore()
	store.Add(&Grant{
		ID:     "test-grant",
		Type:   GrantTypeDomain,
		Domain: "127.0.0.1",
		Source: "policy",
	})

	h := newTestHandler(t, "gated", []Route{
		{Path: "/api", Upstream: upstream.URL},
	}, store, nil, upstream)

	req := httptest.NewRequest("GET", "/api/test", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestGatedNoGrant(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach upstream")
	}))
	defer upstream.Close()

	store := NewInMemoryGrantStore() // empty

	h := newTestHandler(t, "gated", []Route{
		{Path: "/api", Upstream: upstream.URL},
	}, store, nil, upstream)

	req := httptest.NewRequest("GET", "/api/test", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}

	var errResp ErrorResponse
	json.Unmarshal(w.Body.Bytes(), &errResp)
	if errResp.Error != "not_allowed" {
		t.Fatalf("expected not_allowed, got %s", errResp.Error)
	}
}

func TestGatedWithDenyRule(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach upstream")
	}))
	defer upstream.Close()

	store := NewInMemoryGrantStore()
	store.Add(&Grant{
		ID:     "allow-grant",
		Type:   GrantTypeDomain,
		Domain: "127.0.0.1",
		Source: "policy",
	})

	deny := NewDenyList([]PolicyRule{
		{Domain: "127.0.0.1"},
	})

	h := newTestHandler(t, "gated", []Route{
		{Path: "/api", Upstream: upstream.URL},
	}, store, deny, upstream)

	req := httptest.NewRequest("GET", "/api/test", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}

	var errResp ErrorResponse
	json.Unmarshal(w.Body.Bytes(), &errResp)
	if errResp.Error != "denied" {
		t.Fatalf("expected denied, got %s", errResp.Error)
	}
}

func TestOneShotConsumedSecondRequest(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	store := NewInMemoryGrantStore()
	store.Add(&Grant{
		ID:      "oneshot",
		Type:    GrantTypeDomain,
		Domain:  "127.0.0.1",
		OneShot: true,
		Source:  "policy",
	})

	h := newTestHandler(t, "gated", []Route{
		{Path: "/api", Upstream: upstream.URL},
	}, store, nil, upstream)

	// First request should succeed
	req := httptest.NewRequest("GET", "/api/test", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 on first request, got %d", w.Code)
	}

	// Second request should fail
	req = httptest.NewRequest("GET", "/api/test", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 on second request, got %d", w.Code)
	}
}

func TestExpiredGrantForbidden(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach upstream")
	}))
	defer upstream.Close()

	store := NewInMemoryGrantStore()
	store.Add(&Grant{
		ID:        "expired",
		Type:      GrantTypeDomain,
		Domain:    "127.0.0.1",
		ExpiresAt: time.Now().Add(-1 * time.Hour),
		Source:    "declaw",
	})

	h := newTestHandler(t, "gated", []Route{
		{Path: "/api", Upstream: upstream.URL},
	}, store, nil, upstream)

	req := httptest.NewRequest("GET", "/api/test", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for expired grant, got %d", w.Code)
	}
}

func TestInboundAuthBeforeGrantCheck(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach upstream")
	}))
	defer upstream.Close()

	store := NewInMemoryGrantStore()
	store.Add(&Grant{
		ID:     "valid",
		Type:   GrantTypeDomain,
		Domain: "127.0.0.1",
		Source: "policy",
	})

	h := newTestHandler(t, "gated", []Route{
		{
			Path:     "/api",
			Upstream: upstream.URL,
			InboundAuth: &InboundAuth{
				Header: "X-Api-Key",
				Value:  "secret",
				Strip:  true,
			},
		},
	}, store, nil, upstream)

	// Request without auth should be rejected before grant check
	req := httptest.NewRequest("GET", "/api/test", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}

	var errResp ErrorResponse
	json.Unmarshal(w.Body.Bytes(), &errResp)
	if errResp.Error != "unauthorized" {
		t.Fatalf("expected unauthorized, got %s", errResp.Error)
	}
}

func TestNoMatchingRouteReturnsJSON(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach upstream")
	}))
	defer upstream.Close()

	h := newTestHandler(t, "passthrough", []Route{
		{Path: "/api", Upstream: upstream.URL},
	}, nil, nil, upstream)

	req := httptest.NewRequest("GET", "/nonexistent/path", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("expected application/json, got %s", ct)
	}

	var errResp ErrorResponse
	json.Unmarshal(w.Body.Bytes(), &errResp)
	if errResp.Error != "no_route" {
		t.Fatalf("expected no_route, got %s", errResp.Error)
	}
	if !strings.Contains(errResp.Message, "/nonexistent/path") {
		t.Fatalf("expected message to contain the path, got %s", errResp.Message)
	}
	if !strings.Contains(errResp.Hint, "/api") {
		t.Fatalf("expected hint to list available routes, got %s", errResp.Hint)
	}
}

func TestGatedNoGrantShowsUpstreamPath(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach upstream")
	}))
	defer upstream.Close()

	store := NewInMemoryGrantStore() // empty

	h := newTestHandler(t, "gated", []Route{
		{Path: "/httpbin", Upstream: upstream.URL},
	}, store, nil, upstream)

	req := httptest.NewRequest("GET", "/httpbin/get", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}

	var errResp ErrorResponse
	json.Unmarshal(w.Body.Bytes(), &errResp)
	if errResp.Error != "not_allowed" {
		t.Fatalf("expected not_allowed, got %s", errResp.Error)
	}
	// The message should show the upstream path /get, not the local path /httpbin/get
	if !strings.Contains(errResp.Message, "/get") {
		t.Fatalf("expected message to contain upstream path /get, got %s", errResp.Message)
	}
	if errResp.Route != "/httpbin" {
		t.Fatalf("expected route /httpbin, got %s", errResp.Route)
	}
}

func TestManagementAPIRouting(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach upstream")
	}))
	defer upstream.Close()

	store := NewInMemoryGrantStore()
	mgmt := NewManagementAPI(store, NewDenyList(nil), "gated", PolicyConfig{})

	h := &ProxyHandler{
		mode:       "gated",
		grantStore: store,
		denyList:   NewDenyList(nil),
		mgmtAPI:    mgmt,
	}

	req := httptest.NewRequest("GET", "/_switcheroo/v1/status", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for management API, got %d", w.Code)
	}

	var status map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &status)
	if status["mode"] != "gated" {
		t.Fatalf("expected mode=gated, got %v", status["mode"])
	}
}

func TestManagementAPINonLoopback(t *testing.T) {
	store := NewInMemoryGrantStore()
	mgmt := NewManagementAPI(store, NewDenyList(nil), "gated", PolicyConfig{})

	h := &ProxyHandler{
		mode:       "gated",
		grantStore: store,
		denyList:   NewDenyList(nil),
		mgmtAPI:    mgmt,
	}

	req := httptest.NewRequest("GET", "/_switcheroo/v1/status", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for non-loopback, got %d", w.Code)
	}
}

func TestManagementAPIAllowedCIDR(t *testing.T) {
	store := NewInMemoryGrantStore()
	mgmt := NewManagementAPI(store, NewDenyList(nil), "gated", PolicyConfig{})

	nets, err := parseCIDRs([]string{"172.16.0.0/12"})
	if err != nil {
		t.Fatalf("parseCIDRs: %v", err)
	}

	h := &ProxyHandler{
		mode:            "gated",
		grantStore:      store,
		denyList:        NewDenyList(nil),
		mgmtAPI:         mgmt,
		mgmtAllowedNets: nets,
	}

	// Docker network IP should be allowed
	req := httptest.NewRequest("GET", "/_switcheroo/v1/status", nil)
	req.RemoteAddr = "172.18.0.5:12345"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for allowed CIDR, got %d", w.Code)
	}
}

func TestManagementAPIDisallowedIP(t *testing.T) {
	store := NewInMemoryGrantStore()
	mgmt := NewManagementAPI(store, NewDenyList(nil), "gated", PolicyConfig{})

	nets, err := parseCIDRs([]string{"172.16.0.0/12"})
	if err != nil {
		t.Fatalf("parseCIDRs: %v", err)
	}

	h := &ProxyHandler{
		mode:            "gated",
		grantStore:      store,
		denyList:        NewDenyList(nil),
		mgmtAPI:         mgmt,
		mgmtAllowedNets: nets,
	}

	// 10.x.x.x is not in 172.16.0.0/12
	req := httptest.NewRequest("GET", "/_switcheroo/v1/status", nil)
	req.RemoteAddr = "10.0.0.5:12345"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for disallowed IP, got %d", w.Code)
	}
}

func TestManagementAPILoopbackAlwaysAllowed(t *testing.T) {
	store := NewInMemoryGrantStore()
	mgmt := NewManagementAPI(store, NewDenyList(nil), "gated", PolicyConfig{})

	// No CIDRs configured — loopback should still work
	h := &ProxyHandler{
		mode:       "gated",
		grantStore: store,
		denyList:   NewDenyList(nil),
		mgmtAPI:    mgmt,
	}

	req := httptest.NewRequest("GET", "/_switcheroo/v1/status", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for loopback, got %d", w.Code)
	}
}

func TestRequestBodyForwarded(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}))
	defer upstream.Close()

	h := newTestHandler(t, "passthrough", []Route{
		{Path: "/api", Upstream: upstream.URL},
	}, nil, nil, upstream)

	req := httptest.NewRequest("POST", "/api/echo", strings.NewReader(`{"key":"value"}`))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if w.Body.String() != `{"key":"value"}` {
		t.Fatalf("expected body forwarded, got %s", w.Body.String())
	}
}

func TestDeclawApprovalSuccess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("declaw-approved"))
	}))
	defer upstream.Close()

	gateway := mockGatewayServer()
	defer gateway.Close()

	store := NewInMemoryGrantStore()
	pendingStore := NewPendingRequestStore()
	declawClient := newTestDeclawClient(gateway.URL, pendingStore, nil)
	declawClient.approvalTimeout = 2 * time.Second

	h := newTestHandler(t, "gated", []Route{
		{Path: "/api", Upstream: upstream.URL},
	}, store, nil, upstream)
	h.declawClient = declawClient

	// Simulate approval arriving after a short delay
	go func() {
		time.Sleep(50 * time.Millisecond)
		// Find the pending request and resolve it
		for i := 0; i < 20; i++ {
			pendingStore.mu.Lock()
			for id := range pendingStore.requests {
				pendingStore.mu.Unlock()
				pendingStore.Resolve(id, ApprovalResult{
					Approved: true,
					Grant: &Grant{
						ID:     "declaw-test",
						Type:   GrantTypeDomain,
						Domain: "127.0.0.1",
						Source: "declaw",
					},
				})
				return
			}
			pendingStore.mu.Unlock()
			time.Sleep(10 * time.Millisecond)
		}
	}()

	req := httptest.NewRequest("GET", "/api/test", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if w.Body.String() != "declaw-approved" {
		t.Fatalf("expected declaw-approved, got %s", w.Body.String())
	}
}

func TestDeclawApprovalDenied(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach upstream")
	}))
	defer upstream.Close()

	gateway := mockGatewayServer()
	defer gateway.Close()

	store := NewInMemoryGrantStore()
	pendingStore := NewPendingRequestStore()
	declawClient := newTestDeclawClient(gateway.URL, pendingStore, nil)
	declawClient.approvalTimeout = 2 * time.Second

	h := newTestHandler(t, "gated", []Route{
		{Path: "/api", Upstream: upstream.URL},
	}, store, nil, upstream)
	h.declawClient = declawClient

	go func() {
		time.Sleep(50 * time.Millisecond)
		for i := 0; i < 20; i++ {
			pendingStore.mu.Lock()
			for id := range pendingStore.requests {
				pendingStore.mu.Unlock()
				pendingStore.Resolve(id, ApprovalResult{Approved: false})
				return
			}
			pendingStore.mu.Unlock()
			time.Sleep(10 * time.Millisecond)
		}
	}()

	req := httptest.NewRequest("GET", "/api/test", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestDeclawApprovalTimeout(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach upstream")
	}))
	defer upstream.Close()

	gateway := mockGatewayServer()
	defer gateway.Close()

	store := NewInMemoryGrantStore()
	pendingStore := NewPendingRequestStore()
	declawClient := newTestDeclawClient(gateway.URL, pendingStore, nil)
	declawClient.approvalTimeout = 100 * time.Millisecond

	h := newTestHandler(t, "gated", []Route{
		{Path: "/api", Upstream: upstream.URL},
	}, store, nil, upstream)
	h.declawClient = declawClient

	req := httptest.NewRequest("GET", "/api/test", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 on timeout, got %d", w.Code)
	}
}

func TestAutoApprovalMode(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("auto-ok"))
	}))
	defer upstream.Close()

	store := NewInMemoryGrantStore() // empty, should not matter

	h := newTestHandler(t, "gated", []Route{
		{Path: "/api", Upstream: upstream.URL, Approval: "auto"},
	}, store, nil, upstream)

	req := httptest.NewRequest("GET", "/api/test", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for auto mode, got %d", w.Code)
	}
	if w.Body.String() != "auto-ok" {
		t.Fatalf("expected auto-ok, got %s", w.Body.String())
	}
}

func TestNotifyOnlyApprovalMode(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("notify-ok"))
	}))
	defer upstream.Close()

	store := NewInMemoryGrantStore() // empty

	h := newTestHandler(t, "gated", []Route{
		{Path: "/api", Upstream: upstream.URL, Approval: "notify-only"},
	}, store, nil, upstream)
	// No declawClient — notification is skipped silently

	req := httptest.NewRequest("GET", "/api/test", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for notify-only mode, got %d", w.Code)
	}
	if w.Body.String() != "notify-ok" {
		t.Fatalf("expected notify-ok, got %s", w.Body.String())
	}
}

func TestRequiredApprovalModeBlocks(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach upstream")
	}))
	defer upstream.Close()

	store := NewInMemoryGrantStore() // empty

	h := newTestHandler(t, "gated", []Route{
		{Path: "/api", Upstream: upstream.URL, Approval: "required"},
	}, store, nil, upstream)

	req := httptest.NewRequest("GET", "/api/test", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for required mode with no grant, got %d", w.Code)
	}
}

func TestPerRouteApprovalTimeout(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach upstream")
	}))
	defer upstream.Close()

	gateway := mockGatewayServer()
	defer gateway.Close()

	store := NewInMemoryGrantStore()
	pendingStore := NewPendingRequestStore()
	declawClient := newTestDeclawClient(gateway.URL, pendingStore, nil)
	declawClient.approvalTimeout = 5 * time.Second // default long

	h := newTestHandler(t, "gated", []Route{
		{Path: "/api", Upstream: upstream.URL, Approval: "required", ApprovalTimeout: "100ms"},
	}, store, nil, upstream)
	h.declawClient = declawClient

	start := time.Now()
	req := httptest.NewRequest("GET", "/api/test", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	elapsed := time.Since(start)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 on timeout, got %d", w.Code)
	}
	// Should have timed out in ~100ms, not 5s
	if elapsed > 2*time.Second {
		t.Fatalf("per-route timeout not effective, took %v", elapsed)
	}
}

func TestDeclawNilStandaloneBehavior(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach upstream")
	}))
	defer upstream.Close()

	store := NewInMemoryGrantStore()

	h := newTestHandler(t, "gated", []Route{
		{Path: "/api", Upstream: upstream.URL},
	}, store, nil, upstream)
	// declawClient is nil — standalone behavior

	req := httptest.NewRequest("GET", "/api/test", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 in standalone, got %d", w.Code)
	}
}
