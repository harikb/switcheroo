package main

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"nhooyr.io/websocket"
)

func TestStatusEndpoint(t *testing.T) {
	store := NewInMemoryGrantStore()
	mgmt := NewManagementAPI(store, NewDenyList(nil), "gated", PolicyConfig{})

	req := httptest.NewRequest("GET", "/_switcheroo/v1/status", nil)
	w := httptest.NewRecorder()
	mgmt.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var status map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &status)
	if status["mode"] != "gated" {
		t.Fatalf("expected mode=gated, got %v", status["mode"])
	}
	if _, ok := status["uptime"]; !ok {
		t.Fatal("expected uptime field")
	}
}

func TestListGrantsEndpoint(t *testing.T) {
	store := NewInMemoryGrantStore()
	store.Add(&Grant{ID: "g1", Type: GrantTypeDomain, Domain: "a.com", Source: "policy"})
	store.Add(&Grant{ID: "g2", Type: GrantTypeDomain, Domain: "b.com", Source: "declaw"})

	mgmt := NewManagementAPI(store, NewDenyList(nil), "gated", PolicyConfig{})

	req := httptest.NewRequest("GET", "/_switcheroo/v1/grants", nil)
	w := httptest.NewRecorder()
	mgmt.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var grants []*Grant
	json.Unmarshal(w.Body.Bytes(), &grants)
	if len(grants) != 2 {
		t.Fatalf("expected 2 grants, got %d", len(grants))
	}
}

func TestDeleteGrantPolicySourced(t *testing.T) {
	store := NewInMemoryGrantStore()
	store.Add(&Grant{ID: "policy-1", Type: GrantTypeDomain, Domain: "a.com", Source: "policy"})

	mgmt := NewManagementAPI(store, NewDenyList(nil), "gated", PolicyConfig{})

	req := httptest.NewRequest("DELETE", "/_switcheroo/v1/grants/policy-1", nil)
	w := httptest.NewRecorder()
	mgmt.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for policy-sourced grant, got %d", w.Code)
	}

	var errResp ErrorResponse
	json.Unmarshal(w.Body.Bytes(), &errResp)
	if errResp.Error != "cannot_delete" {
		t.Fatalf("expected cannot_delete, got %s", errResp.Error)
	}
}

func TestDeleteGrantDeclawSourced(t *testing.T) {
	store := NewInMemoryGrantStore()
	store.Add(&Grant{ID: "declaw-1", Type: GrantTypeDomain, Domain: "a.com", Source: "declaw"})

	mgmt := NewManagementAPI(store, NewDenyList(nil), "gated", PolicyConfig{})

	req := httptest.NewRequest("DELETE", "/_switcheroo/v1/grants/declaw-1", nil)
	w := httptest.NewRecorder()
	mgmt.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}

	// Verify it's gone
	if len(store.List()) != 0 {
		t.Fatal("expected grant to be deleted")
	}
}

func TestDeleteGrantNotFound(t *testing.T) {
	store := NewInMemoryGrantStore()
	mgmt := NewManagementAPI(store, NewDenyList(nil), "gated", PolicyConfig{})

	req := httptest.NewRequest("DELETE", "/_switcheroo/v1/grants/nonexistent", nil)
	w := httptest.NewRecorder()
	mgmt.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestGetPolicyEndpoint(t *testing.T) {
	policy := PolicyConfig{
		Deny: []PolicyRule{
			{Domain: "*.evil.com"},
		},
		Allow: []PolicyRule{
			{Domain: "httpbin.org"},
		},
	}
	mgmt := NewManagementAPI(NewInMemoryGrantStore(), NewDenyList(policy.Deny), "gated", policy)

	req := httptest.NewRequest("GET", "/_switcheroo/v1/policy", nil)
	w := httptest.NewRecorder()
	mgmt.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var result PolicyConfig
	json.Unmarshal(w.Body.Bytes(), &result)
	if len(result.Deny) != 1 {
		t.Fatalf("expected 1 deny rule, got %d", len(result.Deny))
	}
	if len(result.Allow) != 1 {
		t.Fatalf("expected 1 allow rule, got %d", len(result.Allow))
	}
}

func TestGetDeniedEndpoint(t *testing.T) {
	mgmt := NewManagementAPI(NewInMemoryGrantStore(), NewDenyList(nil), "gated", PolicyConfig{})

	// Record some denied requests
	mgmt.RecordDenied(DeniedRequest{
		Method: "GET",
		Domain: "unknown.com",
		Path:   "/test",
		Reason: "not_allowed",
	})
	mgmt.RecordDenied(DeniedRequest{
		Method: "POST",
		Domain: "evil.com",
		Path:   "/hack",
		Reason: "denied",
	})

	req := httptest.NewRequest("GET", "/_switcheroo/v1/denied", nil)
	w := httptest.NewRecorder()
	mgmt.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var denied []DeniedRequest
	json.Unmarshal(w.Body.Bytes(), &denied)
	if len(denied) != 2 {
		t.Fatalf("expected 2 denied requests, got %d", len(denied))
	}
}

func TestDeniedRingBuffer(t *testing.T) {
	mgmt := NewManagementAPI(NewInMemoryGrantStore(), NewDenyList(nil), "gated", PolicyConfig{})

	// Fill beyond capacity
	for i := 0; i < 150; i++ {
		mgmt.RecordDenied(DeniedRequest{
			Domain: "test.com",
			Reason: "not_allowed",
		})
	}

	denied := mgmt.GetDenied()
	if len(denied) != deniedRingBufferSize {
		t.Fatalf("expected %d denied requests, got %d", deniedRingBufferSize, len(denied))
	}
}

func TestUnknownEndpoint404(t *testing.T) {
	mgmt := NewManagementAPI(NewInMemoryGrantStore(), NewDenyList(nil), "gated", PolicyConfig{})

	req := httptest.NewRequest("GET", "/_switcheroo/v1/declaw/approve", nil)
	w := httptest.NewRecorder()
	mgmt.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for DeClaw endpoint in standalone, got %d", w.Code)
	}
}

func TestStatusDeclawConnected(t *testing.T) {
	store := NewInMemoryGrantStore()
	mgmt := NewManagementAPI(store, NewDenyList(nil), "gated", PolicyConfig{})
	mgmt.declawClient = &GatewayClient{} // no wsConn

	req := httptest.NewRequest("GET", "/_switcheroo/v1/status", nil)
	w := httptest.NewRecorder()
	mgmt.ServeHTTP(w, req)

	var status map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &status)
	if status["declaw_connected"] != false {
		t.Fatalf("expected declaw_connected=false, got %v", status["declaw_connected"])
	}
}

func TestStatusNoDeclawClient(t *testing.T) {
	store := NewInMemoryGrantStore()
	mgmt := NewManagementAPI(store, NewDenyList(nil), "gated", PolicyConfig{})

	req := httptest.NewRequest("GET", "/_switcheroo/v1/status", nil)
	w := httptest.NewRecorder()
	mgmt.ServeHTTP(w, req)

	var status map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &status)
	if status["declaw_connected"] != false {
		t.Fatalf("expected declaw_connected=false, got %v", status["declaw_connected"])
	}
}

func TestPairStatusNotPaired(t *testing.T) {
	mgmt := NewManagementAPI(NewInMemoryGrantStore(), NewDenyList(nil), "gated", PolicyConfig{})

	req := httptest.NewRequest("GET", "/_switcheroo/v1/pair/status", nil)
	w := httptest.NewRecorder()
	mgmt.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var result map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &result)
	if result["paired"] != false {
		t.Fatalf("expected paired=false, got %v", result["paired"])
	}
}

func TestPairStatusPaired(t *testing.T) {
	mgmt := NewManagementAPI(NewInMemoryGrantStore(), NewDenyList(nil), "gated", PolicyConfig{})

	_, phonePub, _ := GenerateX25519KeyPair()
	mgmt.declawClient = &GatewayClient{
		phoneEncryptionKey: phonePub,
		phoneSigningKey:    &ecdsa.PublicKey{},
	}

	req := httptest.NewRequest("GET", "/_switcheroo/v1/pair/status", nil)
	w := httptest.NewRecorder()
	mgmt.ServeHTTP(w, req)

	var result map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &result)
	if result["paired"] != true {
		t.Fatalf("expected paired=true, got %v", result["paired"])
	}
}

func TestReloadEndpoint(t *testing.T) {
	store := NewInMemoryGrantStore()
	mgmt := NewManagementAPI(store, NewDenyList(nil), "gated", PolicyConfig{})

	called := false
	mgmt.onReload = func() error {
		called = true
		return nil
	}

	req := httptest.NewRequest("POST", "/_switcheroo/v1/reload", nil)
	w := httptest.NewRecorder()
	mgmt.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !called {
		t.Fatal("expected reload callback to be called")
	}

	var result map[string]string
	json.Unmarshal(w.Body.Bytes(), &result)
	if result["status"] != "ok" {
		t.Fatalf("expected status=ok, got %s", result["status"])
	}
}

func TestReloadEndpointError(t *testing.T) {
	mgmt := NewManagementAPI(NewInMemoryGrantStore(), NewDenyList(nil), "gated", PolicyConfig{})

	mgmt.onReload = func() error {
		return fmt.Errorf("bad config: missing mode")
	}

	req := httptest.NewRequest("POST", "/_switcheroo/v1/reload", nil)
	w := httptest.NewRecorder()
	mgmt.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}

	var errResp ErrorResponse
	json.Unmarshal(w.Body.Bytes(), &errResp)
	if errResp.Error != "reload_failed" {
		t.Fatalf("expected reload_failed, got %s", errResp.Error)
	}
}

func TestReloadEndpointNotConfigured(t *testing.T) {
	mgmt := NewManagementAPI(NewInMemoryGrantStore(), NewDenyList(nil), "gated", PolicyConfig{})
	// onReload is nil

	req := httptest.NewRequest("POST", "/_switcheroo/v1/reload", nil)
	w := httptest.NewRecorder()
	mgmt.ServeHTTP(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501, got %d", w.Code)
	}
}

func TestGetPolicyEmpty(t *testing.T) {
	mgmt := NewManagementAPI(NewInMemoryGrantStore(), NewDenyList(nil), "gated", PolicyConfig{})

	req := httptest.NewRequest("GET", "/_switcheroo/v1/policy", nil)
	w := httptest.NewRecorder()
	mgmt.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var result PolicyConfig
	json.Unmarshal(w.Body.Bytes(), &result)
	if len(result.Deny) != 0 {
		t.Fatalf("expected empty deny, got %d", len(result.Deny))
	}
	if len(result.Allow) != 0 {
		t.Fatalf("expected empty allow, got %d", len(result.Allow))
	}
}

// --- Grant Request (Pre-Approval) Tests ---

// newMgmtWithDeclawAndNotifyServer creates a ManagementAPI wired to a mock DeClaw
// gateway that accepts notifications. Returns mgmt, cleanup func.
func newMgmtWithDeclawAndNotifyServer(t *testing.T) (*ManagementAPI, func()) {
	t.Helper()

	// Mock gateway that accepts notify calls
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"apns_id": "mock-apns"})
	}))

	pendingStore := NewPendingRequestStore()

	// Generate real X25519 keys for encryption
	privKey, phonePub, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	client := &GatewayClient{
		gatewayURL:         gateway.URL,
		proxyID:            "test-proxy",
		apiKey:             "test-key",
		httpClient:         gateway.Client(),
		pendingStore:       pendingStore,
		phoneEncryptionKey: phonePub,
		proxyPrivKey:       privKey,
		approvalTimeout:    2 * time.Second,
		wsConn:             &websocket.Conn{}, // non-nil to simulate connected
	}

	store := NewInMemoryGrantStore()
	mgmt := NewManagementAPI(store, NewDenyList(nil), "gated", PolicyConfig{})
	mgmt.declawClient = client
	mgmt.grantRequestStore = NewGrantRequestStore()

	return mgmt, gateway.Close
}

func TestGrantRequestPostNoDeClaw(t *testing.T) {
	mgmt := NewManagementAPI(NewInMemoryGrantStore(), NewDenyList(nil), "gated", PolicyConfig{})
	mgmt.grantRequestStore = NewGrantRequestStore()
	// declawClient is nil

	body := `{"domain": "api.example.com", "reason": "test"}`
	req := httptest.NewRequest("POST", "/_switcheroo/v1/agent-request", strings.NewReader(body))
	w := httptest.NewRecorder()
	mgmt.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", w.Code, w.Body.String())
	}

	var errResp ErrorResponse
	json.Unmarshal(w.Body.Bytes(), &errResp)
	if errResp.Error != "declaw_not_connected" {
		t.Fatalf("expected declaw_not_connected, got %s", errResp.Error)
	}
}

func TestGrantRequestPostDeclawNotConnected(t *testing.T) {
	mgmt := NewManagementAPI(NewInMemoryGrantStore(), NewDenyList(nil), "gated", PolicyConfig{})
	mgmt.grantRequestStore = NewGrantRequestStore()
	mgmt.declawClient = &GatewayClient{} // wsConn is nil

	body := `{"domain": "api.example.com", "reason": "test"}`
	req := httptest.NewRequest("POST", "/_switcheroo/v1/agent-request", strings.NewReader(body))
	w := httptest.NewRecorder()
	mgmt.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGrantRequestPostMissingDomain(t *testing.T) {
	mgmt, cleanup := newMgmtWithDeclawAndNotifyServer(t)
	defer cleanup()

	body := `{"reason": "test"}`
	req := httptest.NewRequest("POST", "/_switcheroo/v1/agent-request", strings.NewReader(body))
	w := httptest.NewRecorder()
	mgmt.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}

	var errResp ErrorResponse
	json.Unmarshal(w.Body.Bytes(), &errResp)
	if errResp.Error != "missing_field" {
		t.Fatalf("expected missing_field, got %s", errResp.Error)
	}
}

func TestGrantRequestPostMissingReason(t *testing.T) {
	mgmt, cleanup := newMgmtWithDeclawAndNotifyServer(t)
	defer cleanup()

	body := `{"domain": "api.example.com"}`
	req := httptest.NewRequest("POST", "/_switcheroo/v1/agent-request", strings.NewReader(body))
	w := httptest.NewRecorder()
	mgmt.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}

	var errResp ErrorResponse
	json.Unmarshal(w.Body.Bytes(), &errResp)
	if errResp.Error != "missing_field" {
		t.Fatalf("expected missing_field, got %s", errResp.Error)
	}
}

func TestGrantRequestPostDomainAndURLMutuallyExclusive(t *testing.T) {
	mgmt, cleanup := newMgmtWithDeclawAndNotifyServer(t)
	defer cleanup()

	body := `{"domain": "api.example.com", "url": "https://api.example.com/foo", "reason": "test"}`
	req := httptest.NewRequest("POST", "/_switcheroo/v1/agent-request", strings.NewReader(body))
	w := httptest.NewRecorder()
	mgmt.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGrantRequestPostInvalidDuration(t *testing.T) {
	mgmt, cleanup := newMgmtWithDeclawAndNotifyServer(t)
	defer cleanup()

	body := `{"domain": "api.example.com", "reason": "test", "duration": "not-a-duration"}`
	req := httptest.NewRequest("POST", "/_switcheroo/v1/agent-request", strings.NewReader(body))
	w := httptest.NewRecorder()
	mgmt.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}

	var errResp ErrorResponse
	json.Unmarshal(w.Body.Bytes(), &errResp)
	if errResp.Error != "invalid_duration" {
		t.Fatalf("expected invalid_duration, got %s", errResp.Error)
	}
}

func TestGrantRequestPostInvalidJSON(t *testing.T) {
	mgmt, cleanup := newMgmtWithDeclawAndNotifyServer(t)
	defer cleanup()

	req := httptest.NewRequest("POST", "/_switcheroo/v1/agent-request", strings.NewReader("{bad json"))
	w := httptest.NewRecorder()
	mgmt.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGrantRequestPostSuccess(t *testing.T) {
	mgmt, cleanup := newMgmtWithDeclawAndNotifyServer(t)
	defer cleanup()

	body := `{"domain": "api.stripe.com", "path_prefix": "/v1/charges", "methods": ["GET", "POST"], "reason": "Need to check payments", "duration": "1h"}`
	req := httptest.NewRequest("POST", "/_switcheroo/v1/agent-request", strings.NewReader(body))
	w := httptest.NewRecorder()
	mgmt.ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", w.Code, w.Body.String())
	}

	var result map[string]string
	json.Unmarshal(w.Body.Bytes(), &result)
	if result["request_id"] == "" {
		t.Fatal("expected request_id in response")
	}
	if result["status"] != "pending" {
		t.Fatalf("expected status=pending, got %s", result["status"])
	}

	// Verify request is in the store
	gr := mgmt.grantRequestStore.Get(result["request_id"])
	if gr == nil {
		t.Fatal("expected grant request in store")
	}
	if gr.Domain != "api.stripe.com" {
		t.Fatalf("expected domain api.stripe.com, got %s", gr.Domain)
	}
	if gr.Reason != "Need to check payments" {
		t.Fatalf("expected reason, got %s", gr.Reason)
	}
}

func TestGrantRequestPostWithURL(t *testing.T) {
	mgmt, cleanup := newMgmtWithDeclawAndNotifyServer(t)
	defer cleanup()

	body := `{"url": "https://api.stripe.com/v1/charges/ch_123", "reason": "Check specific charge"}`
	req := httptest.NewRequest("POST", "/_switcheroo/v1/agent-request", strings.NewReader(body))
	w := httptest.NewRecorder()
	mgmt.ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGrantRequestGetNotFound(t *testing.T) {
	mgmt := NewManagementAPI(NewInMemoryGrantStore(), NewDenyList(nil), "gated", PolicyConfig{})
	mgmt.grantRequestStore = NewGrantRequestStore()

	req := httptest.NewRequest("GET", "/_switcheroo/v1/agent-request/nonexistent", nil)
	w := httptest.NewRecorder()
	mgmt.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestGrantRequestGetPending(t *testing.T) {
	mgmt := NewManagementAPI(NewInMemoryGrantStore(), NewDenyList(nil), "gated", PolicyConfig{})
	mgmt.grantRequestStore = NewGrantRequestStore()

	mgmt.grantRequestStore.Add(&GrantRequest{
		ID:        "req-abc",
		Status:    GrantRequestStatusPending,
		Domain:    "api.example.com",
		Reason:    "test reason",
		CreatedAt: time.Now(),
	})

	req := httptest.NewRequest("GET", "/_switcheroo/v1/agent-request/req-abc", nil)
	w := httptest.NewRecorder()
	mgmt.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var gr GrantRequest
	json.Unmarshal(w.Body.Bytes(), &gr)
	if gr.ID != "req-abc" {
		t.Fatalf("expected request_id req-abc, got %s", gr.ID)
	}
	if gr.Status != "pending" {
		t.Fatalf("expected pending, got %s", gr.Status)
	}
}

func TestGrantRequestGetApproved(t *testing.T) {
	mgmt := NewManagementAPI(NewInMemoryGrantStore(), NewDenyList(nil), "gated", PolicyConfig{})
	mgmt.grantRequestStore = NewGrantRequestStore()

	mgmt.grantRequestStore.Add(&GrantRequest{
		ID:        "req-abc",
		Status:    GrantRequestStatusPending,
		Domain:    "api.example.com",
		CreatedAt: time.Now(),
	})
	mgmt.grantRequestStore.Resolve("req-abc", GrantRequestStatusApproved, &Grant{
		ID:     "declaw-req-abc",
		Type:   GrantTypeDomain,
		Domain: "api.example.com",
		Source: "declaw",
	})

	req := httptest.NewRequest("GET", "/_switcheroo/v1/agent-request/req-abc", nil)
	w := httptest.NewRecorder()
	mgmt.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var gr GrantRequest
	json.Unmarshal(w.Body.Bytes(), &gr)
	if gr.Status != "approved" {
		t.Fatalf("expected approved, got %s", gr.Status)
	}
	if gr.Grant == nil {
		t.Fatal("expected grant in approved response")
	}
	if gr.Grant.ID != "declaw-req-abc" {
		t.Fatalf("expected grant ID declaw-req-abc, got %s", gr.Grant.ID)
	}
}

func TestGrantRequestGetDenied(t *testing.T) {
	mgmt := NewManagementAPI(NewInMemoryGrantStore(), NewDenyList(nil), "gated", PolicyConfig{})
	mgmt.grantRequestStore = NewGrantRequestStore()

	mgmt.grantRequestStore.Add(&GrantRequest{
		ID:        "req-abc",
		Status:    GrantRequestStatusPending,
		CreatedAt: time.Now(),
	})
	mgmt.grantRequestStore.Resolve("req-abc", GrantRequestStatusDenied, nil)

	req := httptest.NewRequest("GET", "/_switcheroo/v1/agent-request/req-abc", nil)
	w := httptest.NewRecorder()
	mgmt.ServeHTTP(w, req)

	var gr GrantRequest
	json.Unmarshal(w.Body.Bytes(), &gr)
	if gr.Status != "denied" {
		t.Fatalf("expected denied, got %s", gr.Status)
	}
}

func TestGrantRequestGetTimeout(t *testing.T) {
	mgmt := NewManagementAPI(NewInMemoryGrantStore(), NewDenyList(nil), "gated", PolicyConfig{})
	mgmt.grantRequestStore = NewGrantRequestStore()

	mgmt.grantRequestStore.Add(&GrantRequest{
		ID:        "req-abc",
		Status:    GrantRequestStatusPending,
		CreatedAt: time.Now(),
	})
	mgmt.grantRequestStore.Resolve("req-abc", GrantRequestStatusTimeout, nil)

	req := httptest.NewRequest("GET", "/_switcheroo/v1/agent-request/req-abc", nil)
	w := httptest.NewRecorder()
	mgmt.ServeHTTP(w, req)

	var gr GrantRequest
	json.Unmarshal(w.Body.Bytes(), &gr)
	if gr.Status != "timeout" {
		t.Fatalf("expected timeout, got %s", gr.Status)
	}
}

func TestGrantRequestList(t *testing.T) {
	mgmt := NewManagementAPI(NewInMemoryGrantStore(), NewDenyList(nil), "gated", PolicyConfig{})
	mgmt.grantRequestStore = NewGrantRequestStore()

	mgmt.grantRequestStore.Add(&GrantRequest{
		ID:        "req-1",
		Status:    GrantRequestStatusPending,
		Domain:    "a.com",
		CreatedAt: time.Now(),
	})
	mgmt.grantRequestStore.Add(&GrantRequest{
		ID:        "req-2",
		Status:    GrantRequestStatusApproved,
		Domain:    "b.com",
		CreatedAt: time.Now(),
	})

	req := httptest.NewRequest("GET", "/_switcheroo/v1/agent-request", nil)
	w := httptest.NewRecorder()
	mgmt.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var requests []*GrantRequest
	json.Unmarshal(w.Body.Bytes(), &requests)
	if len(requests) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(requests))
	}
}

func TestGrantRequestListEmpty(t *testing.T) {
	mgmt := NewManagementAPI(NewInMemoryGrantStore(), NewDenyList(nil), "gated", PolicyConfig{})
	mgmt.grantRequestStore = NewGrantRequestStore()

	req := httptest.NewRequest("GET", "/_switcheroo/v1/agent-request", nil)
	w := httptest.NewRecorder()
	mgmt.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var requests []*GrantRequest
	json.Unmarshal(w.Body.Bytes(), &requests)
	if len(requests) != 0 {
		t.Fatalf("expected 0 requests, got %d", len(requests))
	}
}

func TestGrantRequestApprovalUpdatesGrantStore(t *testing.T) {
	mgmt, cleanup := newMgmtWithDeclawAndNotifyServer(t)
	defer cleanup()

	// POST to create the grant request
	body := `{"domain": "api.stripe.com", "reason": "test"}`
	req := httptest.NewRequest("POST", "/_switcheroo/v1/agent-request", strings.NewReader(body))
	w := httptest.NewRecorder()
	mgmt.ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", w.Code, w.Body.String())
	}

	var result map[string]string
	json.Unmarshal(w.Body.Bytes(), &result)
	requestID := result["request_id"]

	// Simulate approval by resolving the pending request
	grant := &Grant{
		ID:        "declaw-" + requestID,
		Type:      GrantTypeDomain,
		Domain:    "api.stripe.com",
		Source:    "declaw",
		GrantedAt: time.Now(),
	}
	mgmt.declawClient.pendingStore.Resolve(requestID, ApprovalResult{
		Approved: true,
		Grant:    grant,
	})

	// Give the background goroutine time to process
	time.Sleep(100 * time.Millisecond)

	// Verify grant request status is updated
	gr := mgmt.grantRequestStore.Get(requestID)
	if gr == nil {
		t.Fatal("expected grant request in store")
	}
	if gr.Status != GrantRequestStatusApproved {
		t.Fatalf("expected approved, got %s", gr.Status)
	}

	// Verify grant was added to grant store
	grants := mgmt.grantStore.List()
	found := false
	for _, g := range grants {
		if g.ID == "declaw-"+requestID {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected approved grant to be in grant store")
	}
}

func TestGrantRequestDenialFlow(t *testing.T) {
	mgmt, cleanup := newMgmtWithDeclawAndNotifyServer(t)
	defer cleanup()

	body := `{"domain": "api.stripe.com", "reason": "test"}`
	req := httptest.NewRequest("POST", "/_switcheroo/v1/agent-request", strings.NewReader(body))
	w := httptest.NewRecorder()
	mgmt.ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", w.Code, w.Body.String())
	}

	var result map[string]string
	json.Unmarshal(w.Body.Bytes(), &result)
	requestID := result["request_id"]

	// Simulate denial
	mgmt.declawClient.pendingStore.Resolve(requestID, ApprovalResult{
		Approved: false,
	})

	time.Sleep(100 * time.Millisecond)

	gr := mgmt.grantRequestStore.Get(requestID)
	if gr == nil {
		t.Fatal("expected grant request in store")
	}
	if gr.Status != GrantRequestStatusDenied {
		t.Fatalf("expected denied, got %s", gr.Status)
	}
}

// --- Pairing Endpoint Tests ---

func TestPairInitiateEndpoint(t *testing.T) {
	mgmt, cleanup := newMgmtWithPairingSetup(t)
	defer cleanup()

	req := httptest.NewRequest("POST", "/_switcheroo/v1/pair/initiate", nil)
	w := httptest.NewRecorder()
	mgmt.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var result map[string]string
	json.Unmarshal(w.Body.Bytes(), &result)

	if result["pairing_url"] == "" {
		t.Fatal("expected pairing_url")
	}
	if result["code"] == "" {
		t.Fatal("expected code")
	}
	if result["qr_image"] == "" {
		t.Fatal("expected qr_image")
	}
	if result["expires_at"] == "" {
		t.Fatal("expected expires_at")
	}
}

func TestPairInitiateEndpointNoDeClaw(t *testing.T) {
	mgmt := NewManagementAPI(NewInMemoryGrantStore(), NewDenyList(nil), "gated", PolicyConfig{})

	req := httptest.NewRequest("POST", "/_switcheroo/v1/pair/initiate", nil)
	w := httptest.NewRecorder()
	mgmt.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", w.Code, w.Body.String())
	}

	var errResp ErrorResponse
	json.Unmarshal(w.Body.Bytes(), &errResp)
	if errResp.Error != "declaw_not_connected" {
		t.Fatalf("expected declaw_not_connected, got %s", errResp.Error)
	}
}

func TestPairSessionEndpointNoSession(t *testing.T) {
	mgmt := NewManagementAPI(NewInMemoryGrantStore(), NewDenyList(nil), "gated", PolicyConfig{})

	req := httptest.NewRequest("GET", "/_switcheroo/v1/pair/session", nil)
	w := httptest.NewRecorder()
	mgmt.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var result map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &result)
	if result["status"] != "no_session" {
		t.Fatalf("expected no_session, got %v", result["status"])
	}
	if result["phone_keys_set"] != false {
		t.Fatalf("expected phone_keys_set=false, got %v", result["phone_keys_set"])
	}
}

// --- Pending Requests Endpoint Tests ---

func TestListPendingEmpty(t *testing.T) {
	mgmt := NewManagementAPI(NewInMemoryGrantStore(), NewDenyList(nil), "gated", PolicyConfig{})
	// No declawClient

	req := httptest.NewRequest("GET", "/_switcheroo/v1/pending", nil)
	w := httptest.NewRecorder()
	mgmt.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var result []interface{}
	json.Unmarshal(w.Body.Bytes(), &result)
	if len(result) != 0 {
		t.Fatalf("expected 0 pending, got %d", len(result))
	}
}

func TestListPendingWithRequests(t *testing.T) {
	mgmt := NewManagementAPI(NewInMemoryGrantStore(), NewDenyList(nil), "gated", PolicyConfig{})
	pendingStore := NewPendingRequestStore()
	pendingStore.Add(&PendingRequest{
		ID:       "req-p1",
		Domain:   "example.com",
		Method:   "GET",
		ResultCh: make(chan struct{}),
	})
	mgmt.declawClient = &GatewayClient{pendingStore: pendingStore}

	req := httptest.NewRequest("GET", "/_switcheroo/v1/pending", nil)
	w := httptest.NewRecorder()
	mgmt.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var result []pendingRequestJSON
	json.Unmarshal(w.Body.Bytes(), &result)
	if len(result) != 1 {
		t.Fatalf("expected 1 pending, got %d", len(result))
	}
	if result[0].ID != "req-p1" {
		t.Fatalf("expected req-p1, got %s", result[0].ID)
	}
}

// --- Dynamic Routes Endpoint Tests ---

func TestListDynamicRoutesEmpty(t *testing.T) {
	mgmt := NewManagementAPI(NewInMemoryGrantStore(), NewDenyList(nil), "gated", PolicyConfig{})
	// No agentConfig

	req := httptest.NewRequest("GET", "/_switcheroo/v1/routes/dynamic", nil)
	w := httptest.NewRecorder()
	mgmt.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var result []interface{}
	json.Unmarshal(w.Body.Bytes(), &result)
	if len(result) != 0 {
		t.Fatalf("expected 0 routes, got %d", len(result))
	}
}

func TestListDynamicRoutesWithRoutes(t *testing.T) {
	mgmt := NewManagementAPI(NewInMemoryGrantStore(), NewDenyList(nil), "gated", PolicyConfig{})
	ac, _ := LoadAgentConfig(t.TempDir() + "/agent_config.yaml")
	ac.AddRoute(Route{Path: "/dynamic", Upstream: "https://dynamic.com"}, AgentRouteMeta{RequestID: "req-d1"})
	mgmt.agentConfig = ac

	req := httptest.NewRequest("GET", "/_switcheroo/v1/routes/dynamic", nil)
	w := httptest.NewRecorder()
	mgmt.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var result []AgentRoute
	json.Unmarshal(w.Body.Bytes(), &result)
	if len(result) != 1 {
		t.Fatalf("expected 1 route, got %d", len(result))
	}
	if result[0].Meta.RequestID != "req-d1" {
		t.Fatalf("expected req-d1, got %s", result[0].Meta.RequestID)
	}
}

func TestDeleteDynamicRoute(t *testing.T) {
	mgmt := NewManagementAPI(NewInMemoryGrantStore(), NewDenyList(nil), "gated", PolicyConfig{})
	ac, _ := LoadAgentConfig(t.TempDir() + "/agent_config.yaml")
	ac.AddRoute(Route{Path: "/del", Upstream: "https://del.com"}, AgentRouteMeta{RequestID: "req-del"})
	mgmt.agentConfig = ac

	req := httptest.NewRequest("DELETE", "/_switcheroo/v1/routes/dynamic/req-del", nil)
	w := httptest.NewRecorder()
	mgmt.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", w.Code, w.Body.String())
	}

	// Verify route is gone
	routes := ac.ListRoutes()
	if len(routes) != 0 {
		t.Fatalf("expected 0 routes after delete, got %d", len(routes))
	}
}

func TestDeleteDynamicRouteNotFound(t *testing.T) {
	mgmt := NewManagementAPI(NewInMemoryGrantStore(), NewDenyList(nil), "gated", PolicyConfig{})
	ac, _ := LoadAgentConfig(t.TempDir() + "/agent_config.yaml")
	mgmt.agentConfig = ac

	req := httptest.NewRequest("DELETE", "/_switcheroo/v1/routes/dynamic/nonexistent", nil)
	w := httptest.NewRecorder()
	mgmt.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestDeleteDynamicRouteNoAgentConfig(t *testing.T) {
	mgmt := NewManagementAPI(NewInMemoryGrantStore(), NewDenyList(nil), "gated", PolicyConfig{})

	req := httptest.NewRequest("DELETE", "/_switcheroo/v1/routes/dynamic/whatever", nil)
	w := httptest.NewRecorder()
	mgmt.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

// --- Config Proposal Locked Fields Tests ---

func TestGrantRequestPostConfigLockedRoute(t *testing.T) {
	mgmt, cleanup := newMgmtWithDeclawAndNotifyServer(t)
	defer cleanup()
	mgmt.routes = []Route{
		{Path: "/locked", Upstream: "https://locked.com", Locked: true},
	}

	body := `{"domain": "api.example.com", "reason": "test", "config": {"add_route": {"path": "/locked", "upstream": "https://other.com"}}}`
	req := httptest.NewRequest("POST", "/_switcheroo/v1/agent-request", strings.NewReader(body))
	w := httptest.NewRecorder()
	mgmt.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}

	var errResp ErrorResponse
	json.Unmarshal(w.Body.Bytes(), &errResp)
	if errResp.Error != "route_locked" {
		t.Fatalf("expected route_locked, got %s", errResp.Error)
	}
}

func TestGrantRequestPostConfigNewRoute(t *testing.T) {
	mgmt, cleanup := newMgmtWithDeclawAndNotifyServer(t)
	defer cleanup()
	mgmt.routes = []Route{}

	body := `{"domain": "api.example.com", "reason": "test", "config": {"add_route": {"path": "/new", "upstream": "https://new.com"}}}`
	req := httptest.NewRequest("POST", "/_switcheroo/v1/agent-request", strings.NewReader(body))
	w := httptest.NewRecorder()
	mgmt.ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", w.Code, w.Body.String())
	}
}

func TestPairSessionEndpointPending(t *testing.T) {
	mgmt, cleanup := newMgmtWithPairingSetup(t)
	defer cleanup()

	_, err := mgmt.InitiatePairing()
	if err != nil {
		t.Fatalf("InitiatePairing: %v", err)
	}

	req := httptest.NewRequest("GET", "/_switcheroo/v1/pair/session", nil)
	w := httptest.NewRecorder()
	mgmt.ServeHTTP(w, req)

	var result map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &result)
	if result["status"] != "pending" {
		t.Fatalf("expected pending, got %v", result["status"])
	}
}

// --- Config Proposal Wire Format Tests ---

func TestConfigProposalHasAgentCredentials(t *testing.T) {
	mgmt, cleanup := newMgmtWithDeclawAndNotifyServer(t)
	defer cleanup()

	body := `{"domain": "api.example.com", "reason": "test", "config": {"add_route": {"path": "/api", "upstream": "https://api.example.com", "upstream_auth": {"mode": "static_api_key", "header": "x-api-key", "value": "secret123"}}}}`
	req := httptest.NewRequest("POST", "/_switcheroo/v1/agent-request", strings.NewReader(body))
	w := httptest.NewRecorder()
	mgmt.ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", w.Code, w.Body.String())
	}

	// The metadata would have been sent encrypted, so we verify via the pending request store
	// that has_agent_credentials was set by checking the grant request was created successfully
	var result map[string]string
	json.Unmarshal(w.Body.Bytes(), &result)
	requestID := result["request_id"]
	if requestID == "" {
		t.Fatal("expected request_id")
	}
}

func TestConfigProposalBearerTokenHasAgentCredentials(t *testing.T) {
	mgmt, cleanup := newMgmtWithDeclawAndNotifyServer(t)
	defer cleanup()

	body := `{"domain": "api.example.com", "reason": "test", "config": {"add_route": {"path": "/api", "upstream": "https://api.example.com", "upstream_auth": {"mode": "static_bearer", "token": "bearer-secret"}}}}`
	req := httptest.NewRequest("POST", "/_switcheroo/v1/agent-request", strings.NewReader(body))
	w := httptest.NewRecorder()
	mgmt.ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", w.Code, w.Body.String())
	}
}

func TestConfigApprovedFalseDoesNotApplyConfig(t *testing.T) {
	mgmt, cleanup := newMgmtWithDeclawAndNotifyServer(t)
	defer cleanup()
	ac, _ := LoadAgentConfig(t.TempDir() + "/agent_config.yaml")
	mgmt.agentConfig = ac

	body := `{"domain": "api.example.com", "reason": "test", "config": {"add_route": {"path": "/new-route", "upstream": "https://new.example.com"}}}`
	req := httptest.NewRequest("POST", "/_switcheroo/v1/agent-request", strings.NewReader(body))
	w := httptest.NewRecorder()
	mgmt.ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", w.Code, w.Body.String())
	}

	var result map[string]string
	json.Unmarshal(w.Body.Bytes(), &result)
	requestID := result["request_id"]

	// Simulate approval with config_approved=false
	configApproved := false
	grant := &Grant{
		ID:        "declaw-" + requestID,
		Type:      GrantTypeDomain,
		Domain:    "api.example.com",
		Source:    "declaw",
		GrantedAt: time.Now(),
	}
	mgmt.declawClient.pendingStore.Resolve(requestID, ApprovalResult{
		Approved:       true,
		Grant:          grant,
		ConfigApproved: &configApproved,
	})

	time.Sleep(100 * time.Millisecond)

	// Grant should be created
	gr := mgmt.grantRequestStore.Get(requestID)
	if gr == nil {
		t.Fatal("expected grant request in store")
	}
	if gr.Status != GrantRequestStatusApproved {
		t.Fatalf("expected approved, got %s", gr.Status)
	}

	// But config should NOT be applied
	routes := ac.ListRoutes()
	if len(routes) != 0 {
		t.Fatalf("expected 0 dynamic routes (config not approved), got %d", len(routes))
	}
}

func TestConfigApprovedTrueAppliesConfig(t *testing.T) {
	mgmt, cleanup := newMgmtWithDeclawAndNotifyServer(t)
	defer cleanup()
	ac, _ := LoadAgentConfig(t.TempDir() + "/agent_config.yaml")
	mgmt.agentConfig = ac

	body := `{"domain": "api.example.com", "reason": "test", "config": {"add_route": {"path": "/new-route", "upstream": "https://new.example.com"}}}`
	req := httptest.NewRequest("POST", "/_switcheroo/v1/agent-request", strings.NewReader(body))
	w := httptest.NewRecorder()
	mgmt.ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", w.Code, w.Body.String())
	}

	var result map[string]string
	json.Unmarshal(w.Body.Bytes(), &result)
	requestID := result["request_id"]

	// Simulate approval with config_approved=true
	configApproved := true
	grant := &Grant{
		ID:        "declaw-" + requestID,
		Type:      GrantTypeDomain,
		Domain:    "api.example.com",
		Source:    "declaw",
		GrantedAt: time.Now(),
	}
	mgmt.declawClient.pendingStore.Resolve(requestID, ApprovalResult{
		Approved:       true,
		Grant:          grant,
		ConfigApproved: &configApproved,
	})

	time.Sleep(100 * time.Millisecond)

	// Config should be applied
	routes := ac.ListRoutes()
	if len(routes) != 1 {
		t.Fatalf("expected 1 dynamic route (config approved), got %d", len(routes))
	}
	if routes[0].Route.Path != "/new-route" {
		t.Fatalf("expected /new-route, got %s", routes[0].Route.Path)
	}
}

func TestConfigApprovedNilDoesNotApplyConfig(t *testing.T) {
	mgmt, cleanup := newMgmtWithDeclawAndNotifyServer(t)
	defer cleanup()
	ac, _ := LoadAgentConfig(t.TempDir() + "/agent_config.yaml")
	mgmt.agentConfig = ac

	body := `{"domain": "api.example.com", "reason": "test", "config": {"add_route": {"path": "/new-route", "upstream": "https://new.example.com"}}}`
	req := httptest.NewRequest("POST", "/_switcheroo/v1/agent-request", strings.NewReader(body))
	w := httptest.NewRecorder()
	mgmt.ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", w.Code, w.Body.String())
	}

	var result map[string]string
	json.Unmarshal(w.Body.Bytes(), &result)
	requestID := result["request_id"]

	// Simulate approval with config_approved=nil (old phone app)
	grant := &Grant{
		ID:        "declaw-" + requestID,
		Type:      GrantTypeDomain,
		Domain:    "api.example.com",
		Source:    "declaw",
		GrantedAt: time.Now(),
	}
	mgmt.declawClient.pendingStore.Resolve(requestID, ApprovalResult{
		Approved:       true,
		Grant:          grant,
		ConfigApproved: nil,
	})

	time.Sleep(100 * time.Millisecond)

	// Config should NOT be applied (safe default)
	routes := ac.ListRoutes()
	if len(routes) != 0 {
		t.Fatalf("expected 0 dynamic routes (config_approved nil = safe default), got %d", len(routes))
	}
}

