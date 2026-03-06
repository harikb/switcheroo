package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"nhooyr.io/websocket"
)

func newMCPTestHandler(t *testing.T) (*MCPHandler, *ManagementAPI) {
	t.Helper()
	store := NewInMemoryGrantStore()
	mgmt := NewManagementAPI(store, NewDenyList(nil), "gated", PolicyConfig{})
	mgmt.grantRequestStore = NewGrantRequestStore()
	mcpH := NewMCPHandler(mgmt)
	return mcpH, mgmt
}

func mcpRequest(t *testing.T, h *MCPHandler, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/_switcheroo/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestMCPInitialize(t *testing.T) {
	h, _ := newMCPTestHandler(t)

	w := mcpRequest(t, h, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}`)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp jsonRPCResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Error != nil {
		t.Fatalf("expected no error, got %v", resp.Error)
	}

	resultBytes, _ := json.Marshal(resp.Result)
	var result mcpInitializeResult
	json.Unmarshal(resultBytes, &result)

	if result.ProtocolVersion != mcpProtocolVersion {
		t.Fatalf("expected protocol version %s, got %s", mcpProtocolVersion, result.ProtocolVersion)
	}
	if result.ServerInfo.Name != "switcheroo" {
		t.Fatalf("expected server name switcheroo, got %s", result.ServerInfo.Name)
	}
	if result.Capabilities.Tools == nil {
		t.Fatal("expected tools capability")
	}
}

func TestMCPToolsList(t *testing.T) {
	h, _ := newMCPTestHandler(t)

	w := mcpRequest(t, h, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp jsonRPCResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Error != nil {
		t.Fatalf("expected no error, got %v", resp.Error)
	}

	resultBytes, _ := json.Marshal(resp.Result)
	var result mcpToolsListResult
	json.Unmarshal(resultBytes, &result)

	if len(result.Tools) != 4 {
		t.Fatalf("expected 4 tools, got %d", len(result.Tools))
	}

	names := map[string]bool{}
	for _, tool := range result.Tools {
		names[tool.Name] = true
	}
	for _, expected := range []string{"request_api_access", "check_access_request", "initiate_pairing", "check_pairing_status"} {
		if !names[expected] {
			t.Fatalf("expected %s tool", expected)
		}
	}
}

func TestMCPToolsCallRequestAPIAccessSuccess(t *testing.T) {
	h, mgmt := newMCPTestHandler(t)

	// Wire up DeClaw with a mock server
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"apns_id": "mock-apns"})
	}))
	defer gateway.Close()

	privKey, phonePub, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	mgmt.declawClient = &GatewayClient{
		gatewayURL:         gateway.URL,
		proxyID:            "test-proxy",
		apiKey:             "test-key",
		httpClient:         gateway.Client(),
		pendingStore:       NewPendingRequestStore(),
		phoneEncryptionKey: phonePub,
		proxyPrivKey:       privKey,
		approvalTimeout:    2 * time.Second,
		wsConn:             &websocket.Conn{},
	}

	w := mcpRequest(t, h, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"request_api_access","arguments":{"domain":"api.stripe.com","reason":"Need to check payments"}}}`)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp jsonRPCResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Error != nil {
		t.Fatalf("expected no error, got %v", resp.Error)
	}

	resultBytes, _ := json.Marshal(resp.Result)
	var result mcpToolResult
	json.Unmarshal(resultBytes, &result)

	if result.IsError {
		t.Fatalf("expected success, got error: %s", result.Content[0].Text)
	}
	if len(result.Content) != 1 {
		t.Fatalf("expected 1 content item, got %d", len(result.Content))
	}

	var parsed map[string]string
	json.Unmarshal([]byte(result.Content[0].Text), &parsed)
	if parsed["request_id"] == "" {
		t.Fatal("expected request_id in response")
	}
	if parsed["status"] != "pending" {
		t.Fatalf("expected status=pending, got %s", parsed["status"])
	}
}

func TestMCPToolsCallCheckAccessRequest(t *testing.T) {
	h, mgmt := newMCPTestHandler(t)

	// Add a grant request to the store
	mgmt.grantRequestStore.Add(&GrantRequest{
		ID:        "req-test-123",
		Status:    GrantRequestStatusPending,
		Domain:    "api.example.com",
		Reason:    "test",
		CreatedAt: time.Now(),
	})

	w := mcpRequest(t, h, `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"check_access_request","arguments":{"request_id":"req-test-123"}}}`)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp jsonRPCResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Error != nil {
		t.Fatalf("expected no error, got %v", resp.Error)
	}

	resultBytes, _ := json.Marshal(resp.Result)
	var result mcpToolResult
	json.Unmarshal(resultBytes, &result)

	if result.IsError {
		t.Fatalf("expected success, got error: %s", result.Content[0].Text)
	}

	var gr GrantRequest
	json.Unmarshal([]byte(result.Content[0].Text), &gr)
	if gr.ID != "req-test-123" {
		t.Fatalf("expected request_id req-test-123, got %s", gr.ID)
	}
	if gr.Status != "pending" {
		t.Fatalf("expected status pending, got %s", gr.Status)
	}
}

func TestMCPToolsCallCheckAccessRequestNotFound(t *testing.T) {
	h, _ := newMCPTestHandler(t)

	w := mcpRequest(t, h, `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"check_access_request","arguments":{"request_id":"nonexistent"}}}`)

	var resp jsonRPCResponse
	json.Unmarshal(w.Body.Bytes(), &resp)

	resultBytes, _ := json.Marshal(resp.Result)
	var result mcpToolResult
	json.Unmarshal(resultBytes, &result)

	if !result.IsError {
		t.Fatal("expected isError=true for not found request")
	}
	if !strings.Contains(result.Content[0].Text, "not found") {
		t.Fatalf("expected 'not found' message, got: %s", result.Content[0].Text)
	}
}

func TestMCPToolsCallRequestAPIAccessNoDeClaw(t *testing.T) {
	h, _ := newMCPTestHandler(t)
	// declawClient is nil

	w := mcpRequest(t, h, `{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"request_api_access","arguments":{"domain":"api.example.com","reason":"test"}}}`)

	var resp jsonRPCResponse
	json.Unmarshal(w.Body.Bytes(), &resp)

	resultBytes, _ := json.Marshal(resp.Result)
	var result mcpToolResult
	json.Unmarshal(resultBytes, &result)

	if !result.IsError {
		t.Fatal("expected isError=true when DeClaw not connected")
	}
	if !strings.Contains(result.Content[0].Text, "DeClaw") {
		t.Fatalf("expected DeClaw-related error, got: %s", result.Content[0].Text)
	}
}

func TestMCPUnknownTool(t *testing.T) {
	h, _ := newMCPTestHandler(t)

	w := mcpRequest(t, h, `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"nonexistent_tool","arguments":{}}}`)

	var resp jsonRPCResponse
	json.Unmarshal(w.Body.Bytes(), &resp)

	if resp.Error == nil {
		t.Fatal("expected JSON-RPC error for unknown tool")
	}
	if resp.Error.Code != -32602 {
		t.Fatalf("expected error code -32602, got %d", resp.Error.Code)
	}
}

func TestMCPUnknownMethod(t *testing.T) {
	h, _ := newMCPTestHandler(t)

	w := mcpRequest(t, h, `{"jsonrpc":"2.0","id":8,"method":"unknown/method"}`)

	var resp jsonRPCResponse
	json.Unmarshal(w.Body.Bytes(), &resp)

	if resp.Error == nil {
		t.Fatal("expected JSON-RPC error for unknown method")
	}
	if resp.Error.Code != -32601 {
		t.Fatalf("expected error code -32601, got %d", resp.Error.Code)
	}
}

func TestMCPInvalidJSON(t *testing.T) {
	h, _ := newMCPTestHandler(t)

	w := mcpRequest(t, h, `{bad json`)

	var resp jsonRPCResponse
	json.Unmarshal(w.Body.Bytes(), &resp)

	if resp.Error == nil {
		t.Fatal("expected JSON-RPC error for invalid JSON")
	}
	if resp.Error.Code != -32700 {
		t.Fatalf("expected error code -32700, got %d", resp.Error.Code)
	}
}

func TestMCPGetMethodNotAllowed(t *testing.T) {
	h, _ := newMCPTestHandler(t)

	req := httptest.NewRequest("GET", "/_switcheroo/mcp", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestMCPNotificationReturns202(t *testing.T) {
	h, _ := newMCPTestHandler(t)

	// Notification has null id
	w := mcpRequest(t, h, `{"jsonrpc":"2.0","id":null,"method":"notifications/initialized"}`)

	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", w.Code)
	}

	if w.Body.Len() != 0 {
		t.Fatalf("expected empty body, got %s", w.Body.String())
	}
}

func TestMCPNotificationNoID(t *testing.T) {
	h, _ := newMCPTestHandler(t)

	// Notification with absent id field
	w := mcpRequest(t, h, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)

	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", w.Code)
	}
}

func TestMCPInitiatePairing(t *testing.T) {
	h, mgmt := newMCPTestHandler(t)

	// Wire up DeClaw with a mock gateway
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer gateway.Close()

	privKey, _, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	mgmt.declawClient = &GatewayClient{
		gatewayURL:   gateway.URL,
		proxyID:      "test-proxy",
		apiKey:       "test-key",
		httpClient:   gateway.Client(),
		pendingStore: NewPendingRequestStore(),
		proxyPrivKey: privKey,
		wsConn:       &websocket.Conn{},
	}

	w := mcpRequest(t, h, `{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"initiate_pairing","arguments":{}}}`)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp jsonRPCResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Error != nil {
		t.Fatalf("expected no error, got %v", resp.Error)
	}

	resultBytes, _ := json.Marshal(resp.Result)
	var result mcpToolResult
	json.Unmarshal(resultBytes, &result)

	if result.IsError {
		t.Fatalf("expected success, got error: %s", result.Content[0].Text)
	}

	var parsed map[string]string
	json.Unmarshal([]byte(result.Content[0].Text), &parsed)
	if parsed["pairing_url"] == "" {
		t.Fatal("expected pairing_url in response")
	}
	if parsed["code"] == "" {
		t.Fatal("expected code in response")
	}
	if parsed["qr_image"] == "" {
		t.Fatal("expected qr_image in response")
	}
	if parsed["expires_at"] == "" {
		t.Fatal("expected expires_at in response")
	}
}

func TestMCPInitiatePairingNoDeClaw(t *testing.T) {
	h, _ := newMCPTestHandler(t)
	// declawClient is nil

	w := mcpRequest(t, h, `{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"initiate_pairing","arguments":{}}}`)

	var resp jsonRPCResponse
	json.Unmarshal(w.Body.Bytes(), &resp)

	resultBytes, _ := json.Marshal(resp.Result)
	var result mcpToolResult
	json.Unmarshal(resultBytes, &result)

	if !result.IsError {
		t.Fatal("expected isError=true when DeClaw not connected")
	}
	if !strings.Contains(result.Content[0].Text, "DeClaw") {
		t.Fatalf("expected DeClaw-related error, got: %s", result.Content[0].Text)
	}
}

func TestMCPCheckPairingStatus(t *testing.T) {
	h, _ := newMCPTestHandler(t)

	// No session
	w := mcpRequest(t, h, `{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"check_pairing_status","arguments":{}}}`)

	var resp jsonRPCResponse
	json.Unmarshal(w.Body.Bytes(), &resp)

	resultBytes, _ := json.Marshal(resp.Result)
	var result mcpToolResult
	json.Unmarshal(resultBytes, &result)

	if result.IsError {
		t.Fatalf("expected success, got error: %s", result.Content[0].Text)
	}

	var parsed map[string]string
	json.Unmarshal([]byte(result.Content[0].Text), &parsed)
	if parsed["status"] != "no_session" {
		t.Fatalf("expected no_session, got %s", parsed["status"])
	}
}

func TestMCPCheckPairingStatusPending(t *testing.T) {
	h, mgmt := newMCPTestHandler(t)

	// Wire up DeClaw and initiate pairing
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer gateway.Close()

	privKey, _, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	mgmt.declawClient = &GatewayClient{
		gatewayURL:   gateway.URL,
		proxyID:      "test-proxy",
		apiKey:       "test-key",
		httpClient:   gateway.Client(),
		pendingStore: NewPendingRequestStore(),
		proxyPrivKey: privKey,
		wsConn:       &websocket.Conn{},
	}

	// Initiate pairing first
	_, err = mgmt.InitiatePairing()
	if err != nil {
		t.Fatalf("InitiatePairing: %v", err)
	}

	// Check status via MCP
	w := mcpRequest(t, h, `{"jsonrpc":"2.0","id":13,"method":"tools/call","params":{"name":"check_pairing_status","arguments":{}}}`)

	var resp jsonRPCResponse
	json.Unmarshal(w.Body.Bytes(), &resp)

	resultBytes, _ := json.Marshal(resp.Result)
	var result mcpToolResult
	json.Unmarshal(resultBytes, &result)

	var parsed map[string]string
	json.Unmarshal([]byte(result.Content[0].Text), &parsed)
	if parsed["status"] != "pending" {
		t.Fatalf("expected pending, got %s", parsed["status"])
	}
}

func TestMCPRouteViaManagementAPI(t *testing.T) {
	store := NewInMemoryGrantStore()
	mgmt := NewManagementAPI(store, NewDenyList(nil), "gated", PolicyConfig{})
	mgmt.grantRequestStore = NewGrantRequestStore()
	mgmt.mcpHandler = NewMCPHandler(mgmt)

	h := &ProxyHandler{
		mode:       "gated",
		grantStore: store,
		denyList:   NewDenyList(nil),
		mgmtAPI:    mgmt,
	}

	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
	req := httptest.NewRequest("POST", "/_switcheroo/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp jsonRPCResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Error != nil {
		t.Fatalf("expected no error, got %v", resp.Error)
	}
}
