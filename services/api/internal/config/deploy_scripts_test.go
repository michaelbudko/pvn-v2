package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWireGuardDeployScriptAllowsV2ForwardingAndNAT(t *testing.T) {
	path := filepath.Join("..", "..", "..", "..", "infra", "vps", "wireguard.sh")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	script := string(body)
	required := []string{
		"10.88.0.0/24",
		"MASQUERADE",
		"ufw route allow in on",
		"${WG_IFACE}",
		"${EGRESS_IFACE}",
	}
	for _, value := range required {
		if !strings.Contains(script, value) {
			t.Fatalf("wireguard.sh missing %q", value)
		}
	}
}
