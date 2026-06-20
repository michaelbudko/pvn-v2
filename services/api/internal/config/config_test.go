package config

import (
	"strings"
	"testing"
)

func TestValidateRejectsBlankServerPublicKeyWhenNotDryRun(t *testing.T) {
	cfg := Config{
		WGSubnet:       "10.88.0.0/24",
		WGEndpointHost: "api-v2.45.63.22.174.sslip.io",
		WGEndpointPort: 51821,
		WGAllowedIPs:   "0.0.0.0/0",
		WGDryRun:       false,
	}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "WG_SERVER_PUBLIC_KEY") {
		t.Fatalf("expected server key validation error, got %v", err)
	}
}

func TestValidateAllowsBlankServerPublicKeyInDryRun(t *testing.T) {
	cfg := Config{
		WGSubnet:       "10.88.0.0/24",
		WGEndpointHost: "api-v2.45.63.22.174.sslip.io",
		WGEndpointPort: 51821,
		WGAllowedIPs:   "0.0.0.0/0",
		WGDryRun:       true,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("dry-run config should allow blank server key: %v", err)
	}
}

func TestValidateRejectsInvalidServerPublicKey(t *testing.T) {
	cfg := Config{
		WGSubnet:          "10.88.0.0/24",
		WGEndpointHost:    "api-v2.45.63.22.174.sslip.io",
		WGEndpointPort:    51821,
		WGAllowedIPs:      "0.0.0.0/0",
		WGServerPublicKey: "not-a-key",
		WGDryRun:          false,
	}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "invalid WG_SERVER_PUBLIC_KEY") {
		t.Fatalf("expected invalid key error, got %v", err)
	}
}

func TestLoadReadsMVPNoLoginFlag(t *testing.T) {
	t.Setenv("PVN_MVP_NO_LOGIN", "true")
	t.Setenv("WG_DRY_RUN", "true")
	t.Setenv("WG_SERVER_PUBLIC_KEY", "")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.MVPNoLogin {
		t.Fatal("expected PVN_MVP_NO_LOGIN=true to enable MVP no-login mode")
	}
}
