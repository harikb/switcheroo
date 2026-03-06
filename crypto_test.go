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
	"os"
	"path/filepath"
	"testing"
)

var (
	aesNewCipher = aes.NewCipher
	cipherNewGCM = cipher.NewGCM
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	// Generate phone key pair (phone holds private, proxy knows public)
	_, phonePub, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Generate proxy key pair (proxy holds private, phone knows public)
	proxyPriv, _, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}

	metadata := RequestMetadata{
		RequestID: "req-123",
		ProxyID:   "prx_abc",
		Domain:    "api.example.com",
		Method:    "POST",
		URL:       "https://api.example.com/v1/data",
	}

	// Proxy encrypts for phone
	encrypted, err := EncryptForPhone(metadata, phonePub)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate phone decrypting (reverse: phone uses its private key + proxy's ephemeral pub)
	// We need to simulate the phone side creating an approval and encrypting it back
	// For this test, we encrypt an approval using phone's ephemeral key → proxy's pub key

	approval := DecryptedApproval{
		RequestID:       "req-123",
		Action:          "approve",
		LeaseType:       "domain",
		Domain:          "api.example.com",
		DurationSeconds: 300,
		Timestamp:       "2026-03-01T00:00:00Z",
	}
	approvalJSON, _ := json.Marshal(approval)

	// Sign with P256
	signingKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	hash := sha256.Sum256(approvalJSON)
	r, s, _ := ecdsa.Sign(rand.Reader, signingKey, hash[:])

	// Pad r and s to 32 bytes each
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	sig := make([]byte, 64)
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):64], sBytes)

	signed := SignedPayload{
		Approval:  approvalJSON,
		Signature: sig,
	}
	signedJSON, _ := json.Marshal(signed)

	// Phone encrypts approval for proxy using proxy's public key
	phoneEph, _ := ecdh.X25519().GenerateKey(rand.Reader)
	shared, _ := phoneEph.ECDH(proxyPriv.PublicKey())
	aesKey, _ := deriveAESKey(shared)

	// Encrypt
	ciphertext, nonce := aesGCMEncrypt(t, aesKey, signedJSON)

	response := ApprovalResponse{
		Ciphertext:         base64.StdEncoding.EncodeToString(ciphertext),
		Nonce:              base64.StdEncoding.EncodeToString(nonce),
		EphemeralPublicKey: base64.StdEncoding.EncodeToString(phoneEph.PublicKey().Bytes()),
	}

	// Proxy decrypts
	decrypted, err := DecryptApproval(response, proxyPriv)
	if err != nil {
		t.Fatalf("decrypt approval: %v", err)
	}

	// Verify signature
	result, err := VerifyApprovalSignature(decrypted, &signingKey.PublicKey)
	if err != nil {
		t.Fatalf("verify signature: %v", err)
	}

	if result.RequestID != "req-123" {
		t.Fatalf("expected req-123, got %s", result.RequestID)
	}
	if result.Action != "approve" {
		t.Fatalf("expected approve, got %s", result.Action)
	}

	// Verify original encryption worked (metadata is non-empty)
	if encrypted.Ciphertext == "" || encrypted.Nonce == "" || encrypted.EphemeralPublicKey == "" {
		t.Fatal("encrypted payload should have non-empty fields")
	}
}

func TestTamperedCiphertextFails(t *testing.T) {
	proxyPriv, _, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}

	phoneEph, _ := ecdh.X25519().GenerateKey(rand.Reader)
	shared, _ := phoneEph.ECDH(proxyPriv.PublicKey())
	aesKey, _ := deriveAESKey(shared)

	plaintext := []byte(`{"approval":"test","signature":"test"}`)
	ciphertext, nonce := aesGCMEncrypt(t, aesKey, plaintext)

	// Tamper with ciphertext
	ciphertext[0] ^= 0xff

	response := ApprovalResponse{
		Ciphertext:         base64.StdEncoding.EncodeToString(ciphertext),
		Nonce:              base64.StdEncoding.EncodeToString(nonce),
		EphemeralPublicKey: base64.StdEncoding.EncodeToString(phoneEph.PublicKey().Bytes()),
	}

	_, err = DecryptApproval(response, proxyPriv)
	if err == nil {
		t.Fatal("expected error for tampered ciphertext")
	}
}

func TestSignatureVerifyInvalid(t *testing.T) {
	approval := DecryptedApproval{
		RequestID: "req-456",
		Action:    "deny",
		Timestamp: "2026-03-01T00:00:00Z",
	}
	approvalJSON, _ := json.Marshal(approval)

	// Sign with one key
	signingKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	hash := sha256.Sum256(approvalJSON)
	r, s, _ := ecdsa.Sign(rand.Reader, signingKey, hash[:])

	sig := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):64], sBytes)

	signed := SignedPayload{
		Approval:  approvalJSON,
		Signature: sig,
	}

	// Verify with a different key — should fail
	wrongKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, err := VerifyApprovalSignature(signed, &wrongKey.PublicKey)
	if err == nil {
		t.Fatal("expected signature verification to fail with wrong key")
	}
}

func TestKeyGeneration(t *testing.T) {
	priv, pub, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if priv == nil || pub == nil {
		t.Fatal("keys should not be nil")
	}
	if len(priv.Bytes()) != 32 {
		t.Fatalf("expected 32-byte private key, got %d", len(priv.Bytes()))
	}
	if len(pub.Bytes()) != 32 {
		t.Fatalf("expected 32-byte public key, got %d", len(pub.Bytes()))
	}
}

func TestHKDFDeterminism(t *testing.T) {
	secret := make([]byte, 32)
	rand.Read(secret)

	key1, err := deriveAESKey(secret)
	if err != nil {
		t.Fatal(err)
	}
	key2, err := deriveAESKey(secret)
	if err != nil {
		t.Fatal(err)
	}

	if !equal(key1, key2) {
		t.Fatal("HKDF should be deterministic for the same input")
	}
}

func TestLoadX25519PrivateKey(t *testing.T) {
	priv, _, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "key.pem")
	os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(priv.Bytes())), 0600)

	loaded, err := LoadX25519PrivateKey(path)
	if err != nil {
		t.Fatalf("load key: %v", err)
	}

	if !equal(loaded.Bytes(), priv.Bytes()) {
		t.Fatal("loaded key should match original")
	}
}

func TestParseP256PublicKey(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	encoded := base64.StdEncoding.EncodeToString(elliptic.Marshal(elliptic.P256(), key.PublicKey.X, key.PublicKey.Y))

	parsed, err := ParseP256PublicKey(encoded)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}

	if parsed.X.Cmp(key.PublicKey.X) != 0 || parsed.Y.Cmp(key.PublicKey.Y) != 0 {
		t.Fatal("parsed key should match original")
	}
}

func TestParseX25519PublicKey(t *testing.T) {
	_, pub, _ := GenerateX25519KeyPair()
	encoded := base64.StdEncoding.EncodeToString(pub.Bytes())

	parsed, err := ParseX25519PublicKey(encoded)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}

	if !equal(parsed.Bytes(), pub.Bytes()) {
		t.Fatal("parsed key should match original")
	}
}

// Helper: AES-GCM encrypt for test use
func aesGCMEncrypt(t *testing.T, key, plaintext []byte) (ciphertextOut, nonceOut []byte) {
	t.Helper()
	block, err := aesNewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipherNewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonceOut = make([]byte, gcm.NonceSize())
	rand.Read(nonceOut)
	ciphertextOut = gcm.Seal(nil, nonceOut, plaintext, nil)
	return
}

func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
