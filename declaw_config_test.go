package main

import "testing"

func TestDeclawConfigDisabled(t *testing.T) {
	cfg := &DeclawConfig{Enabled: false}
	if err := ValidateDeclawConfig(cfg); err != nil {
		t.Fatalf("disabled config should not error: %v", err)
	}
}

func TestDeclawConfigEnabledRequiresGatewayURL(t *testing.T) {
	cfg := &DeclawConfig{Enabled: true}
	err := ValidateDeclawConfig(cfg)
	if err == nil {
		t.Fatal("expected error when enabled without gateway_url")
	}
}

func TestDeclawConfigEnabledWithGatewayURL(t *testing.T) {
	cfg := &DeclawConfig{
		Enabled:    true,
		GatewayURL: "https://declawapp.com",
	}
	if err := ValidateDeclawConfig(cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeclawConfigEmptyKeysOK(t *testing.T) {
	cfg := &DeclawConfig{
		Enabled:    true,
		GatewayURL: "https://declawapp.com",
		ProxyID:    "",
		ProxyAPIKey: "",
		PhoneSigningKey: "",
		PhoneEncryptionKey: "",
	}
	if err := ValidateDeclawConfig(cfg); err != nil {
		t.Fatalf("empty keys should be allowed: %v", err)
	}
}
