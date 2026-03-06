package main

import "fmt"

// DeclawConfig holds the configuration for DeClaw phone-based approval integration.
type DeclawConfig struct {
	Enabled                bool   `yaml:"enabled"`
	GatewayURL             string `yaml:"gateway_url"`
	ProxyID                string `yaml:"proxy_id"`
	ProxyAPIKey            string `yaml:"proxy_api_key"`
	ProxyEncryptionKeyFile string `yaml:"proxy_encryption_key_file"`
	PhoneSigningKey        string `yaml:"phone_signing_key"`
	PhoneEncryptionKey     string `yaml:"phone_encryption_key"`
}

// ValidateDeclawConfig validates the DeClaw configuration.
// If enabled, gateway_url is required. Other fields may be empty
// (filled by --register and --pair flows).
func ValidateDeclawConfig(cfg *DeclawConfig) error {
	if !cfg.Enabled {
		return nil
	}
	if cfg.GatewayURL == "" {
		return fmt.Errorf("declaw: gateway_url is required when enabled")
	}
	return nil
}
