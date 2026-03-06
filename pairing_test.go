package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"image/png"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	"nhooyr.io/websocket"
)

func TestPairingURLConstruction(t *testing.T) {
	pubKey := make([]byte, 32)
	for i := range pubKey {
		pubKey[i] = byte(i)
	}

	url := buildPairingURL("prx_abc123", "https://declawapp.com", "483291", pubKey)

	if !strings.HasPrefix(url, "declaw://pair?") {
		t.Fatalf("expected declaw:// scheme, got %s", url)
	}
	if !strings.Contains(url, "proxy_id=prx_abc123") {
		t.Fatalf("expected proxy_id in URL: %s", url)
	}
	if !strings.Contains(url, "gateway=https://declawapp.com") {
		t.Fatalf("expected gateway in URL: %s", url)
	}
	if !strings.Contains(url, "token=483291") {
		t.Fatalf("expected token in URL: %s", url)
	}
	if !strings.Contains(url, "pk=") {
		t.Fatalf("expected pk in URL: %s", url)
	}
}

func TestSixDigitCodeGeneration(t *testing.T) {
	for i := 0; i < 100; i++ {
		code, err := generatePairingCode()
		if err != nil {
			t.Fatal(err)
		}
		if len(code) != 6 {
			t.Fatalf("expected 6-digit code, got %q", code)
		}
		for _, c := range code {
			if c < '0' || c > '9' {
				t.Fatalf("expected numeric code, got %q", code)
			}
		}
	}
}

func TestBcryptHashVerification(t *testing.T) {
	code, err := generatePairingCode()
	if err != nil {
		t.Fatal(err)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}

	// Correct code should verify
	if err := bcrypt.CompareHashAndPassword(hash, []byte(code)); err != nil {
		t.Fatalf("expected hash to match code: %v", err)
	}

	// Wrong code should fail
	if err := bcrypt.CompareHashAndPassword(hash, []byte("000000")); err == nil {
		t.Fatal("expected hash to NOT match wrong code")
	}
}

func TestQRImageGeneration(t *testing.T) {
	imgBytes, err := generateQRImage("https://example.com/test")
	if err != nil {
		t.Fatalf("generateQRImage: %v", err)
	}
	if len(imgBytes) == 0 {
		t.Fatal("expected non-empty QR image bytes")
	}

	// Verify it's a valid PNG
	_, err = png.Decode(bytes.NewReader(imgBytes))
	if err != nil {
		t.Fatalf("QR image is not a valid PNG: %v", err)
	}
}

// newMgmtWithPairingSetup creates a ManagementAPI wired to a mock gateway
// that accepts pairing token requests. Returns mgmt and cleanup func.
func newMgmtWithPairingSetup(t *testing.T) (*ManagementAPI, func()) {
	t.Helper()

	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))

	privKey, _, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	pendingStore := NewPendingRequestStore()
	client := &GatewayClient{
		gatewayURL:   gateway.URL,
		proxyID:      "test-proxy",
		apiKey:       "test-key",
		httpClient:   gateway.Client(),
		pendingStore: pendingStore,
		proxyPrivKey: privKey,
		wsConn:       &websocket.Conn{}, // non-nil to simulate connected
	}

	store := NewInMemoryGrantStore()
	mgmt := NewManagementAPI(store, NewDenyList(nil), "gated", PolicyConfig{})
	mgmt.declawClient = client
	mgmt.grantRequestStore = NewGrantRequestStore()

	return mgmt, gateway.Close
}

func TestInitiatePairingSuccess(t *testing.T) {
	mgmt, cleanup := newMgmtWithPairingSetup(t)
	defer cleanup()

	session, err := mgmt.InitiatePairing()
	if err != nil {
		t.Fatalf("InitiatePairing: %v", err)
	}

	if session.PairingURL == "" {
		t.Fatal("expected non-empty pairing URL")
	}
	if !strings.HasPrefix(session.PairingURL, "declaw://pair?") {
		t.Fatalf("expected declaw:// scheme, got %s", session.PairingURL)
	}
	if len(session.Code) != 6 {
		t.Fatalf("expected 6-digit code, got %q", session.Code)
	}
	if len(session.QRImage) == 0 {
		t.Fatal("expected non-empty QR image")
	}
	if session.ExpiresAt.Before(time.Now()) {
		t.Fatal("expected future expiration")
	}
	if session.Status() != "pending" {
		t.Fatalf("expected pending status, got %s", session.Status())
	}

	// Verify QR image is valid PNG
	_, err = png.Decode(bytes.NewReader(session.QRImage))
	if err != nil {
		t.Fatalf("QR image is not valid PNG: %v", err)
	}
}

func TestInitiatePairingNoDeClaw(t *testing.T) {
	mgmt := NewManagementAPI(NewInMemoryGrantStore(), NewDenyList(nil), "gated", PolicyConfig{})
	// declawClient is nil

	_, err := mgmt.InitiatePairing()
	if err == nil {
		t.Fatal("expected error when DeClaw not connected")
	}
	if !strings.Contains(err.Error(), "DeClaw is not connected") {
		t.Fatalf("expected DeClaw not connected error, got: %v", err)
	}
}

func TestInitiatePairingNoEncryptionKey(t *testing.T) {
	mgmt := NewManagementAPI(NewInMemoryGrantStore(), NewDenyList(nil), "gated", PolicyConfig{})
	mgmt.declawClient = &GatewayClient{
		wsConn: &websocket.Conn{}, // connected but no key
	}

	_, err := mgmt.InitiatePairing()
	if err == nil {
		t.Fatal("expected error when encryption key not configured")
	}
	if !strings.Contains(err.Error(), "encryption key") {
		t.Fatalf("expected encryption key error, got: %v", err)
	}
}

func TestCheckPairingStatusNoSession(t *testing.T) {
	mgmt := NewManagementAPI(NewInMemoryGrantStore(), NewDenyList(nil), "gated", PolicyConfig{})

	if mgmt.pairingSession != nil {
		t.Fatal("expected nil pairing session")
	}
}

func TestCheckPairingStatusPending(t *testing.T) {
	mgmt, cleanup := newMgmtWithPairingSetup(t)
	defer cleanup()

	_, err := mgmt.InitiatePairing()
	if err != nil {
		t.Fatalf("InitiatePairing: %v", err)
	}

	if mgmt.pairingSession.Status() != "pending" {
		t.Fatalf("expected pending, got %s", mgmt.pairingSession.Status())
	}
}

func TestCheckPairingStatusExpired(t *testing.T) {
	mgmt, cleanup := newMgmtWithPairingSetup(t)
	defer cleanup()

	_, err := mgmt.InitiatePairing()
	if err != nil {
		t.Fatalf("InitiatePairing: %v", err)
	}

	// Force expiry
	mgmt.pairingSession.ExpiresAt = time.Now().Add(-1 * time.Second)

	if mgmt.pairingSession.Status() != "expired" {
		t.Fatalf("expected expired, got %s", mgmt.pairingSession.Status())
	}
}

func TestPairingActivatesPhoneKeys(t *testing.T) {
	mgmt, cleanup := newMgmtWithPairingSetup(t)
	defer cleanup()

	_, err := mgmt.InitiatePairing()
	if err != nil {
		t.Fatalf("InitiatePairing: %v", err)
	}

	// Generate fake phone keys
	sigPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sigPubBytes := elliptic.Marshal(elliptic.P256(), sigPriv.PublicKey.X, sigPriv.PublicKey.Y)

	encPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	encPubBytes := encPriv.PublicKey().Bytes()

	// Simulate pair_response
	payload := WSPairPayload{
		PhoneSigningKey:    base64.StdEncoding.EncodeToString(sigPubBytes),
		PhoneEncryptionKey: base64.StdEncoding.EncodeToString(encPubBytes),
	}

	// Trigger the callback
	mgmt.declawClient.onPairResponse(payload)

	// Verify keys are set
	if mgmt.declawClient.phoneSigningKey == nil {
		t.Fatal("expected phoneSigningKey to be set")
	}
	if mgmt.declawClient.phoneEncryptionKey == nil {
		t.Fatal("expected phoneEncryptionKey to be set")
	}

	// Verify session status
	if mgmt.pairingSession.Status() != "success" {
		t.Fatalf("expected success, got %s", mgmt.pairingSession.Status())
	}
}

func TestCheckPairingStatusSuccess(t *testing.T) {
	mgmt, cleanup := newMgmtWithPairingSetup(t)
	defer cleanup()

	_, err := mgmt.InitiatePairing()
	if err != nil {
		t.Fatalf("InitiatePairing: %v", err)
	}

	// Generate fake phone keys and trigger callback
	sigPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sigPubBytes := elliptic.Marshal(elliptic.P256(), sigPriv.PublicKey.X, sigPriv.PublicKey.Y)

	encPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	encPubBytes := encPriv.PublicKey().Bytes()

	mgmt.declawClient.onPairResponse(WSPairPayload{
		PhoneSigningKey:    base64.StdEncoding.EncodeToString(sigPubBytes),
		PhoneEncryptionKey: base64.StdEncoding.EncodeToString(encPubBytes),
	})

	if mgmt.pairingSession.Status() != "success" {
		t.Fatalf("expected success, got %s", mgmt.pairingSession.Status())
	}
}

