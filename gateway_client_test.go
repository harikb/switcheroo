package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRegister(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/proxy/register" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != "POST" {
			t.Fatalf("expected POST, got %s", r.Method)
		}

		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		if body["name"] != "test-proxy" {
			t.Fatalf("expected name=test-proxy, got %s", body["name"])
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(RegisterResponse{
			ProxyID: "prx_test123",
			APIKey:  "dk_live_test",
		})
	}))
	defer server.Close()

	client := &GatewayClient{
		gatewayURL: server.URL,
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}

	proxyID, apiKey, err := client.Register("test-proxy")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if proxyID != "prx_test123" {
		t.Fatalf("expected prx_test123, got %s", proxyID)
	}
	if apiKey != "dk_live_test" {
		t.Fatalf("expected dk_live_test, got %s", apiKey)
	}
}

func TestSetPairingToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/proxy/pairing_token" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer dk_live_test" {
			t.Fatalf("expected auth header, got %s", r.Header.Get("Authorization"))
		}

		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		if body["pairing_token_hash"] == "" {
			t.Fatal("expected pairing_token_hash")
		}
		if body["pairing_code"] != "123456" {
			t.Fatalf("expected pairing_code 123456, got %s", body["pairing_code"])
		}
		if body["proxy_public_key"] == "" {
			t.Fatal("expected proxy_public_key")
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	client := &GatewayClient{
		gatewayURL: server.URL,
		apiKey:     "dk_live_test",
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}

	err := client.SetPairingToken("$2a$10$hashvalue", time.Now().Add(5*time.Minute), "123456", []byte("fake-public-key-bytes"))
	if err != nil {
		t.Fatalf("set pairing token: %v", err)
	}
}

func TestNotify(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/notify" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer dk_live_test" {
			t.Fatalf("expected auth header")
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(NotifyResponse{APNSID: "apns-123"})
	}))
	defer server.Close()

	client := &GatewayClient{
		gatewayURL: server.URL,
		apiKey:     "dk_live_test",
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}

	apnsID, err := client.Notify(EncryptedPayload{
		EphemeralPublicKey: "ephkey",
		Ciphertext:         "ct",
		Nonce:              "nonce",
	})
	if err != nil {
		t.Fatalf("notify: %v", err)
	}
	if apnsID != "apns-123" {
		t.Fatalf("expected apns-123, got %s", apnsID)
	}
}

func TestRequestApprovalTimeout(t *testing.T) {
	// Server that accepts notify but never sends approval
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(NotifyResponse{APNSID: "apns-timeout"})
	}))
	defer server.Close()

	_, phonePub, _ := GenerateX25519KeyPair()

	store := NewPendingRequestStore()
	client := &GatewayClient{
		gatewayURL:         server.URL,
		apiKey:             "dk_live_test",
		httpClient:         &http.Client{Timeout: 5 * time.Second},
		pendingStore:       store,
		phoneEncryptionKey: phonePub,
		approvalTimeout:    100 * time.Millisecond,
	}

	_, err := client.RequestApproval(context.Background(), RequestMetadata{
		RequestID: "req-timeout",
		Domain:    "example.com",
		Method:    "GET",
	})
	if err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestRequestApprovalSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(NotifyResponse{APNSID: "apns-ok"})
	}))
	defer server.Close()

	_, phonePub, _ := GenerateX25519KeyPair()

	store := NewPendingRequestStore()
	client := &GatewayClient{
		gatewayURL:         server.URL,
		apiKey:             "dk_live_test",
		httpClient:         &http.Client{Timeout: 5 * time.Second},
		pendingStore:       store,
		phoneEncryptionKey: phonePub,
		approvalTimeout:    5 * time.Second,
	}

	// Simulate approval arriving via channel
	go func() {
		time.Sleep(50 * time.Millisecond)
		store.Resolve("req-success", ApprovalResult{
			Approved: true,
			Grant: &Grant{
				ID:     "declaw-req-success",
				Type:   GrantTypeDomain,
				Domain: "example.com",
				Source: "declaw",
			},
		})
	}()

	result, err := client.RequestApproval(context.Background(), RequestMetadata{
		RequestID: "req-success",
		Domain:    "example.com",
		Method:    "GET",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Approved {
		t.Fatal("expected approved")
	}
	if result.Grant.Domain != "example.com" {
		t.Fatalf("expected example.com, got %s", result.Grant.Domain)
	}
}

func TestHandleWSMessageApproval(t *testing.T) {
	store := NewPendingRequestStore()
	pr := &PendingRequest{
		ID:       "req-ws",
		ResultCh: make(chan struct{}),
	}
	store.Add(pr)

	client := &GatewayClient{
		pendingStore: store,
		// No crypto keys — will resolve with error
	}

	payload := WSApprovalPayload{
		RequestID: "req-ws",
		Response: ApprovalResponse{
			Ciphertext:         "dGVzdA==",
			Nonce:              "dGVzdA==",
			EphemeralPublicKey: "dGVzdA==",
		},
	}
	payloadJSON, _ := json.Marshal(payload)
	msg := WSMessage{Type: "approval_response", Payload: payloadJSON}
	msgJSON, _ := json.Marshal(msg)

	client.handleWSMessage(msgJSON)

	select {
	case <-pr.ResultCh:
		if pr.Result.Approved {
			t.Fatal("expected not approved (no crypto keys)")
		}
		if pr.Result.Error == nil {
			t.Fatal("expected error")
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for ws message handling")
	}
}

func TestReplayProtectionOldTimestamp(t *testing.T) {
	// Create a real key pair for the proxy
	proxyPriv, _, _ := GenerateX25519KeyPair()

	// Generate a P256 signing key pair
	sigPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	store := NewPendingRequestStore()
	pr := &PendingRequest{
		ID:       "req-replay",
		ResultCh: make(chan struct{}),
	}
	store.Add(pr)

	client := &GatewayClient{
		pendingStore:    store,
		proxyPrivKey:    proxyPriv,
		phoneSigningKey: &sigPriv.PublicKey,
	}

	// Create approval with old timestamp
	approval := DecryptedApproval{
		RequestID: "req-replay",
		Action:    "approve",
		Domain:    "example.com",
		LeaseType: "domain",
		Timestamp: time.Now().Add(-10 * time.Minute).Format(time.RFC3339), // 10 min old
	}
	approvalJSON, _ := json.Marshal(approval)

	// Sign it
	hash := sha256.Sum256(approvalJSON)
	rr, ss, _ := ecdsa.Sign(rand.Reader, sigPriv, hash[:])
	sig := make([]byte, 64)
	rr.FillBytes(sig[:32])
	ss.FillBytes(sig[32:])

	signed := SignedPayload{
		Approval:  approvalJSON,
		Signature: sig,
	}
	signedJSON, _ := json.Marshal(signed)

	// Encrypt for the proxy's public key (phone uses ephemeral key + proxy's pub key for ECDH)
	ephPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	shared, _ := ephPriv.ECDH(proxyPriv.PublicKey())
	aesKey, _ := deriveAESKey(shared)

	block, _ := aes.NewCipher(aesKey)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	ciphertext := gcm.Seal(nil, nonce, signedJSON, nil)

	wsPayload := WSApprovalPayload{
		RequestID: "req-replay",
		Response: ApprovalResponse{
			EphemeralPublicKey: base64.StdEncoding.EncodeToString(ephPriv.PublicKey().Bytes()),
			Ciphertext:         base64.StdEncoding.EncodeToString(ciphertext),
			Nonce:              base64.StdEncoding.EncodeToString(nonce),
		},
	}
	payloadJSON, _ := json.Marshal(wsPayload)
	msg := WSMessage{Type: "approval_response", Payload: payloadJSON}
	msgJSON, _ := json.Marshal(msg)

	client.handleWSMessage(msgJSON)

	select {
	case <-pr.ResultCh:
		if pr.Result.Approved {
			t.Fatal("expected replay protection to reject old timestamp")
		}
		if pr.Result.Error == nil || !strings.Contains(pr.Result.Error.Error(), "too old") {
			t.Fatalf("expected 'too old' error, got: %v", pr.Result.Error)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for result")
	}
}

func TestHandleWSMessageUnknownType(t *testing.T) {
	client := &GatewayClient{
		pendingStore: NewPendingRequestStore(),
	}

	msg := WSMessage{Type: "unknown_type", Payload: json.RawMessage(`{}`)}
	msgJSON, _ := json.Marshal(msg)

	// Should not panic
	client.handleWSMessage(msgJSON)
}
