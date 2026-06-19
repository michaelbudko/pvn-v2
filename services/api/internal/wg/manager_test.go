package wg

import (
	"context"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestDryRunUpsertPeerValidatesInputs(t *testing.T) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	manager := Manager{Interface: "wg-pvn-v2", DryRun: true}
	if err := manager.UpsertPeer(context.Background(), key.PublicKey().String(), "10.88.0.2"); err != nil {
		t.Fatalf("dry-run peer upsert failed: %v", err)
	}
	if err := manager.UpsertPeer(context.Background(), "", "10.88.0.2"); err == nil {
		t.Fatal("expected blank public key to fail")
	}
	if err := manager.UpsertPeer(context.Background(), key.PublicKey().String(), "not-an-ip"); err == nil {
		t.Fatal("expected invalid IP to fail")
	}
}
