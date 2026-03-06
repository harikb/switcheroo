package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/mdp/qrterminal/v3"
	qrcode "github.com/skip2/go-qrcode"
	"golang.org/x/crypto/bcrypt"
)

// generatePairingCode generates a random 6-digit numeric code.
func generatePairingCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// buildPairingURL constructs the declaw:// pairing URL.
func buildPairingURL(proxyID, gatewayURL, token string, proxyPubKey []byte) string {
	pubB64 := base64.RawURLEncoding.EncodeToString(proxyPubKey)
	return fmt.Sprintf("declaw://pair?proxy_id=%s&gateway=%s&token=%s&pk=%s",
		proxyID, gatewayURL, token, pubB64)
}

// runRegistration performs the --register flow.
func runRegistration(cfg *Config) {
	if cfg.DeClaw.GatewayURL == "" {
		slog.Error("declaw.gateway_url is required for registration")
		os.Exit(1)
	}

	client := &GatewayClient{
		gatewayURL: cfg.DeClaw.GatewayURL,
		httpClient: defaultHTTPClient(),
	}

	name, _ := os.Hostname()
	proxyID, apiKey, err := client.Register(name)
	if err != nil {
		slog.Error("registration failed", "error", err)
		os.Exit(1)
	}

	// Generate X25519 key pair
	priv, _, err := GenerateX25519KeyPair()
	if err != nil {
		slog.Error("generate key pair", "error", err)
		os.Exit(1)
	}

	// Save private key if key file path is configured
	if cfg.DeClaw.ProxyEncryptionKeyFile != "" {
		encoded := base64.StdEncoding.EncodeToString(priv.Bytes())
		if err := os.WriteFile(cfg.DeClaw.ProxyEncryptionKeyFile, []byte(encoded), 0600); err != nil {
			slog.Error("save private key", "error", err)
			os.Exit(1)
		}
		fmt.Printf("Encryption key saved to %s\n\n", cfg.DeClaw.ProxyEncryptionKeyFile)
	}

	fmt.Println("Registration successful!")
	fmt.Println()
	fmt.Println("Add these to your switcheroo.yaml under declaw:")
	fmt.Printf("  proxy_id: %q\n", proxyID)
	fmt.Printf("  proxy_api_key: %q\n", apiKey)
	fmt.Println()
	fmt.Println("Next: run switcheroo --pair to pair with your phone.")
}

// runPairing performs the --pair flow.
func runPairing(cfg *Config) {
	if cfg.DeClaw.ProxyID == "" || cfg.DeClaw.ProxyAPIKey == "" {
		slog.Error("declaw.proxy_id and declaw.proxy_api_key are required for pairing (run --register first)")
		os.Exit(1)
	}
	if cfg.DeClaw.GatewayURL == "" {
		slog.Error("declaw.gateway_url is required for pairing")
		os.Exit(1)
	}
	if cfg.DeClaw.ProxyEncryptionKeyFile == "" {
		slog.Error("declaw.proxy_encryption_key_file is required for pairing")
		os.Exit(1)
	}

	// Load proxy private key to get the public key
	proxyPriv, err := LoadX25519PrivateKey(cfg.DeClaw.ProxyEncryptionKeyFile)
	if err != nil {
		slog.Error("load proxy key", "error", err)
		os.Exit(1)
	}

	// Generate 6-digit pairing code
	code, err := generatePairingCode()
	if err != nil {
		slog.Error("generate pairing code", "error", err)
		os.Exit(1)
	}

	// Hash the code with bcrypt
	hash, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
	if err != nil {
		slog.Error("hash pairing code", "error", err)
		os.Exit(1)
	}

	// Send hash to gateway
	pendingStore := NewPendingRequestStore()
	client := NewGatewayClient(cfg.DeClaw, pendingStore)

	expiresAt := time.Now().Add(5 * time.Minute)
	if err := client.SetPairingToken(string(hash), expiresAt, code, proxyPriv.PublicKey().Bytes()); err != nil {
		slog.Error("set pairing token", "error", err)
		os.Exit(1)
	}

	// Build pairing URL
	pairingURL := buildPairingURL(cfg.DeClaw.ProxyID, cfg.DeClaw.GatewayURL, code, proxyPriv.PublicKey().Bytes())

	// Display QR code
	fmt.Println("Pairing mode — scan QR code with DeClaw app or enter code manually.")
	fmt.Println()
	qrterminal.GenerateWithConfig(pairingURL, qrterminal.Config{
		Level:     qrterminal.L,
		Writer:    os.Stdout,
		BlackChar: qrterminal.BLACK,
		WhiteChar: qrterminal.WHITE,
	})
	fmt.Println()
	fmt.Printf("  Manual code: %s\n", code)
	fmt.Printf("  Expires in: 5 minutes\n")
	fmt.Println()
	fmt.Println("  Waiting for phone to pair...")

	// Wait for pair_response via WebSocket
	pairDone := make(chan WSPairPayload, 1)
	client.onPairResponse = func(payload WSPairPayload) {
		pairDone <- payload
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	go client.ConnectWebSocket(ctx)

	select {
	case payload := <-pairDone:
		fmt.Println()
		fmt.Println("  Paired successfully!")
		fmt.Println()
		fmt.Println("  Phone signing key and encryption key received.")
		fmt.Println("  Add these to your switcheroo.yaml under declaw:")
		fmt.Printf("    phone_signing_key: %q\n", payload.PhoneSigningKey)
		fmt.Printf("    phone_encryption_key: %q\n", payload.PhoneEncryptionKey)
		fmt.Println()
		fmt.Println("  Then restart switcheroo.")
	case <-ctx.Done():
		fmt.Println()
		fmt.Println("  Pairing timed out. Run --pair again to retry.")
	}
}

func defaultHTTPClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second}
}

// PairingSession represents an in-progress or completed agentic pairing session.
type PairingSession struct {
	PairingURL string    `json:"pairing_url"`
	Code       string    `json:"code"`
	QRImage    []byte    `json:"-"` // PNG bytes, serialized separately as base64
	ExpiresAt  time.Time `json:"expires_at"`

	mu     sync.Mutex
	status string // "pending", "success", "expired"
	result *WSPairPayload
}

// Status returns the current pairing session status, checking for expiry.
func (ps *PairingSession) Status() string {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if ps.status == "pending" && time.Now().After(ps.ExpiresAt) {
		ps.status = "expired"
	}
	return ps.status
}

// generateQRImage generates a PNG QR code image for the given content.
func generateQRImage(content string) ([]byte, error) {
	return qrcode.Encode(content, qrcode.Medium, 256)
}

// InitiatePairing creates a new pairing session using the running proxy's DeClaw client.
// It generates a code, sends the hash to the gateway, builds the pairing URL,
// generates a QR PNG, and wires up the onPairResponse callback.
func (m *ManagementAPI) InitiatePairing() (*PairingSession, error) {
	if m.declawClient == nil || m.declawClient.wsConn == nil {
		return nil, &grantRequestError{
			Code:    "declaw_not_connected",
			Message: "DeClaw is not connected; pairing requires an active DeClaw connection",
			Status:  http.StatusServiceUnavailable,
		}
	}

	if m.declawClient.proxyPrivKey == nil {
		return nil, &grantRequestError{
			Code:    "no_encryption_key",
			Message: "Proxy encryption key is not configured; run --register first",
			Status:  http.StatusPreconditionFailed,
		}
	}

	// Generate 6-digit pairing code
	code, err := generatePairingCode()
	if err != nil {
		return nil, fmt.Errorf("generate pairing code: %w", err)
	}

	// Hash the code with bcrypt
	hash, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("hash pairing code: %w", err)
	}

	expiresAt := time.Now().Add(5 * time.Minute)
	if err := m.declawClient.SetPairingToken(string(hash), expiresAt, code, m.declawClient.proxyPrivKey.PublicKey().Bytes()); err != nil {
		return nil, fmt.Errorf("set pairing token: %w", err)
	}

	// Build pairing URL
	pairingURL := buildPairingURL(
		m.declawClient.proxyID,
		m.declawClient.gatewayURL,
		code,
		m.declawClient.proxyPrivKey.PublicKey().Bytes(),
	)

	// Generate QR PNG
	qrImage, err := generateQRImage(pairingURL)
	if err != nil {
		return nil, fmt.Errorf("generate QR image: %w", err)
	}

	session := &PairingSession{
		PairingURL: pairingURL,
		Code:       code,
		QRImage:    qrImage,
		ExpiresAt:  expiresAt,
		status:     "pending",
	}

	// Wire up the pair_response callback
	m.declawClient.onPairResponse = func(payload WSPairPayload) {
		sigKey, err := ParseP256PublicKey(payload.PhoneSigningKey)
		if err != nil {
			slog.Error("pairing: failed to parse phone signing key", "error", err)
			return
		}

		encKey, err := ParseX25519PublicKey(payload.PhoneEncryptionKey)
		if err != nil {
			slog.Error("pairing: failed to parse phone encryption key", "error", err)
			return
		}

		m.declawClient.phoneSigningKey = sigKey
		m.declawClient.phoneEncryptionKey = encKey

		session.mu.Lock()
		session.status = "success"
		session.result = &payload
		session.mu.Unlock()

		slog.Info("pairing: phone keys activated, proxy is now paired")
	}

	// Store the session (overwrites any previous session)
	m.pairingSession = session

	return session, nil
}
