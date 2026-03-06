package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"

	"golang.org/x/crypto/hkdf"
)

// ProposedConfig is the structured config proposal sent to the phone for inspection.
type ProposedConfig struct {
	AddRoute *ProposedRoute `json:"add_route,omitempty"`
}

// ProposedRoute describes a route being proposed by an agent.
type ProposedRoute struct {
	Path         string            `json:"path"`
	Upstream     string            `json:"upstream"`
	UpstreamAuth *ProposedAuth     `json:"upstream_auth,omitempty"`
	ExtraHeaders map[string]string `json:"extra_headers,omitempty"`
}

// ProposedAuth describes the auth configuration in a proposed route.
// Credential values are included in the E2E encrypted payload so the user can inspect them.
type ProposedAuth struct {
	Mode   string `json:"mode"`
	Header string `json:"header,omitempty"`
	Value  string `json:"value,omitempty"`
	Token  string `json:"token,omitempty"`
}

// RequestMetadata is the data encrypted and sent to the phone for approval.
type RequestMetadata struct {
	RequestID        string          `json:"request_id"`
	ProxyID          string          `json:"proxy_id"`
	Domain           string          `json:"domain"`
	Method           string          `json:"method"`
	URL              string          `json:"url"`
	AgentID          string          `json:"agent_id,omitempty"`
	Reason           string          `json:"reason,omitempty"`
	HasConfigChange  bool            `json:"has_config_change"`
	ConfigSummary    string          `json:"config_summary,omitempty"`
	ProposedConfig   *ProposedConfig `json:"proposed_config,omitempty"`
	HasAgentCreds    bool            `json:"has_agent_credentials"`
	ApprovalRequired *bool           `json:"approval_required,omitempty"`
}

// EncryptedPayload is the encrypted request metadata sent to the gateway.
type EncryptedPayload struct {
	EphemeralPublicKey string `json:"ephemeral_public_key"`
	Ciphertext         string `json:"ciphertext"`
	Nonce              string `json:"nonce"`
}

// ApprovalResponse is the encrypted approval from the phone, received via WebSocket.
type ApprovalResponse struct {
	Ciphertext         string `json:"ciphertext"`
	Nonce              string `json:"nonce"`
	EphemeralPublicKey string `json:"ephemeral_public_key"`
}

// DecryptedApproval is the plaintext approval decision from the phone.
type DecryptedApproval struct {
	RequestID       string `json:"request_id"`
	Action          string `json:"action"`
	LeaseType       string `json:"lease_type"`
	Domain          string `json:"domain"`
	PathPrefix      string `json:"path_prefix,omitempty"`
	DurationSeconds int    `json:"duration_seconds,omitempty"`
	ConfigApproved  *bool  `json:"config_approved,omitempty"`
	Timestamp       string `json:"timestamp"`
}

// SignedPayload contains the canonical approval JSON and its P256 ECDSA signature.
type SignedPayload struct {
	Approval  json.RawMessage `json:"approval"`
	Signature []byte          `json:"signature"`
}

// deriveAESKey performs ECDH key agreement and derives an AES-256 key using HKDF-SHA256.
func deriveAESKey(sharedSecret []byte) ([]byte, error) {
	hkdfReader := hkdf.New(sha256.New, sharedSecret, nil, []byte("DeClaw-v1"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, fmt.Errorf("hkdf: %w", err)
	}
	return key, nil
}

// EncryptForPhone encrypts request metadata for the phone using X25519 ECDH + AES-256-GCM.
func EncryptForPhone(metadata RequestMetadata, phoneEncryptionPubKey *ecdh.PublicKey) (EncryptedPayload, error) {
	// Generate ephemeral X25519 key pair
	ephPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return EncryptedPayload{}, fmt.Errorf("generate ephemeral key: %w", err)
	}

	// ECDH key agreement
	shared, err := ephPriv.ECDH(phoneEncryptionPubKey)
	if err != nil {
		return EncryptedPayload{}, fmt.Errorf("ecdh: %w", err)
	}

	// Derive AES key
	aesKey, err := deriveAESKey(shared)
	if err != nil {
		return EncryptedPayload{}, err
	}

	// Serialize metadata
	plaintext, err := json.Marshal(metadata)
	if err != nil {
		return EncryptedPayload{}, fmt.Errorf("marshal metadata: %w", err)
	}

	// AES-256-GCM encrypt
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return EncryptedPayload{}, fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return EncryptedPayload{}, fmt.Errorf("gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return EncryptedPayload{}, fmt.Errorf("nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	return EncryptedPayload{
		EphemeralPublicKey: base64.StdEncoding.EncodeToString(ephPriv.PublicKey().Bytes()),
		Ciphertext:         base64.StdEncoding.EncodeToString(ciphertext),
		Nonce:              base64.StdEncoding.EncodeToString(nonce),
	}, nil
}

// DecryptApproval decrypts an approval response from the phone using the proxy's X25519 private key.
func DecryptApproval(response ApprovalResponse, proxyPrivKey *ecdh.PrivateKey) (SignedPayload, error) {
	ephPubBytes, err := base64.StdEncoding.DecodeString(response.EphemeralPublicKey)
	if err != nil {
		return SignedPayload{}, fmt.Errorf("decode ephemeral key: %w", err)
	}
	ephPub, err := ecdh.X25519().NewPublicKey(ephPubBytes)
	if err != nil {
		return SignedPayload{}, fmt.Errorf("parse ephemeral key: %w", err)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(response.Ciphertext)
	if err != nil {
		return SignedPayload{}, fmt.Errorf("decode ciphertext: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(response.Nonce)
	if err != nil {
		return SignedPayload{}, fmt.Errorf("decode nonce: %w", err)
	}

	// ECDH
	shared, err := proxyPrivKey.ECDH(ephPub)
	if err != nil {
		return SignedPayload{}, fmt.Errorf("ecdh: %w", err)
	}

	// Derive AES key
	aesKey, err := deriveAESKey(shared)
	if err != nil {
		return SignedPayload{}, err
	}

	// Decrypt
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return SignedPayload{}, fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return SignedPayload{}, fmt.Errorf("gcm: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return SignedPayload{}, fmt.Errorf("decrypt: %w", err)
	}

	var signed SignedPayload
	if err := json.Unmarshal(plaintext, &signed); err != nil {
		return SignedPayload{}, fmt.Errorf("unmarshal signed payload: %w", err)
	}

	return signed, nil
}

// VerifyApprovalSignature verifies the P256 ECDSA signature and decodes the approval.
// The signature is expected to be raw r||s (64 bytes: 32-byte r + 32-byte s).
func VerifyApprovalSignature(signed SignedPayload, phoneSigningPubKey *ecdsa.PublicKey) (DecryptedApproval, error) {
	if len(signed.Signature) != 64 {
		return DecryptedApproval{}, fmt.Errorf("invalid signature length: expected 64, got %d", len(signed.Signature))
	}

	r := new(big.Int).SetBytes(signed.Signature[:32])
	s := new(big.Int).SetBytes(signed.Signature[32:])

	hash := sha256.Sum256(signed.Approval)
	if !ecdsa.Verify(phoneSigningPubKey, hash[:], r, s) {
		return DecryptedApproval{}, fmt.Errorf("signature verification failed")
	}

	var approval DecryptedApproval
	if err := json.Unmarshal(signed.Approval, &approval); err != nil {
		return DecryptedApproval{}, fmt.Errorf("unmarshal approval: %w", err)
	}

	return approval, nil
}

// GenerateX25519KeyPair generates a new X25519 key pair.
func GenerateX25519KeyPair() (*ecdh.PrivateKey, *ecdh.PublicKey, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return priv, priv.PublicKey(), nil
}

// LoadX25519PrivateKey loads an X25519 private key from a file (raw 32-byte key, base64 encoded).
func LoadX25519PrivateKey(path string) (*ecdh.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	keyBytes, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, fmt.Errorf("decode key: %w", err)
	}
	return ecdh.X25519().NewPrivateKey(keyBytes)
}

// ParseP256PublicKey parses a base64-encoded uncompressed P256 public key.
func ParseP256PublicKey(b64 string) (*ecdsa.PublicKey, error) {
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("decode key: %w", err)
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), data)
	if x == nil {
		return nil, fmt.Errorf("invalid P256 public key")
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}

// ParseX25519PublicKey parses a base64-encoded X25519 public key (32 bytes).
func ParseX25519PublicKey(b64 string) (*ecdh.PublicKey, error) {
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("decode key: %w", err)
	}
	return ecdh.X25519().NewPublicKey(data)
}
