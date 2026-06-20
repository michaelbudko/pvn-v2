package db

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"pvn-v2/services/api/internal/config"
)

func TestLoginWorksForSeedUser(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	defer store.Close()

	if err := store.UpsertUser(ctx, "test@example.com", "TestUser1!", "user"); err != nil {
		t.Fatal(err)
	}
	user, token, err := store.Login(ctx, "test@example.com", "TestUser1!")
	if err != nil {
		t.Fatal(err)
	}
	if user.Email != "test@example.com" || token == "" {
		t.Fatalf("unexpected login response: user=%+v token=%q", user, token)
	}
}

func TestUnauthorizedLoginFailsCleanly(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	defer store.Close()

	_, _, err := store.Login(ctx, "missing@example.com", "wrong")
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
}

func TestMVPNoLoginUserIsCreatedOrResolved(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	defer store.Close()

	first, err := store.MVPNoLoginUser(ctx)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.MVPNoLoginUser(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID == 0 || first.Email != MVPNoLoginEmail || first.ID != second.ID {
		t.Fatalf("unexpected MVP no-login user: first=%+v second=%+v", first, second)
	}
}

func TestCreateOrGetDeviceIsIdempotentForSameUserAndPublicKey(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	defer store.Close()
	user := seedUser(t, store, "alice@example.com")
	key := mustKey(t)

	first, firstConfig, err := store.CreateOrGetDevice(ctx, user.ID, "Alice PC", key.PublicKey().String())
	if err != nil {
		t.Fatal(err)
	}
	second, secondConfig, err := store.CreateOrGetDevice(ctx, user.ID, "Alice PC", key.PublicKey().String())
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != second.ID || first.AssignedIP != second.AssignedIP {
		t.Fatalf("duplicate create should return existing device: first=%+v second=%+v", first, second)
	}
	if firstConfig.ServerPublicKey == "" || firstConfig.Endpoint == "" || firstConfig.AllowedIPs == "" || firstConfig.ClientAddress == "" {
		t.Fatalf("config material must be complete: %+v", firstConfig)
	}
	if firstConfig != secondConfig {
		t.Fatalf("expected stable config material: first=%+v second=%+v", firstConfig, secondConfig)
	}
}

func TestDuplicatePublicKeyForDifferentUserReturnsConflict(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	defer store.Close()
	alice := seedUser(t, store, "alice@example.com")
	bob := seedUser(t, store, "bob@example.com")
	key := mustKey(t)

	if _, _, err := store.CreateOrGetDevice(ctx, alice.ID, "Alice PC", key.PublicKey().String()); err != nil {
		t.Fatal(err)
	}
	_, _, err := store.CreateOrGetDevice(ctx, bob.ID, "Bob PC", key.PublicKey().String())
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("expected ErrConflict, got %v", err)
	}
}

func TestServerPublicKeyCannotBeBlank(t *testing.T) {
	ctx := context.Background()
	cfg := testConfig(t)
	cfg.WGServerPublicKey = ""
	store := openStore(t, cfg)
	defer store.Close()
	user := seedUser(t, store, "alice@example.com")
	key := mustKey(t)

	_, _, err := store.CreateOrGetDevice(ctx, user.ID, "Alice PC", key.PublicKey().String())
	if !errors.Is(err, ErrMisconfigured) {
		t.Fatalf("expected ErrMisconfigured, got %v", err)
	}
}

func TestResetProfileWorks(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	defer store.Close()
	user := seedUser(t, store, "alice@example.com")
	key := mustKey(t)
	if _, _, err := store.CreateOrGetDevice(ctx, user.ID, "Alice PC", key.PublicKey().String()); err != nil {
		t.Fatal(err)
	}
	if err := store.ResetDevices(ctx, user.ID); err != nil {
		t.Fatal(err)
	}
	_, _, err := store.CurrentDevice(ctx, user.ID)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound after reset, got %v", err)
	}
}

func TestConfigMaterialHasNoBlankFields(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	defer store.Close()
	user := seedUser(t, store, "alice@example.com")
	key := mustKey(t)

	_, material, err := store.CreateOrGetDevice(ctx, user.ID, "Alice PC", key.PublicKey().String())
	if err != nil {
		t.Fatal(err)
	}
	values := []string{material.ClientAddress, material.ServerPublicKey, material.Endpoint, material.AllowedIPs}
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			t.Fatalf("config material contains blank field: %+v", material)
		}
	}
}

func TestConfigMaterialUsesV2IPv4FullTunnelDefaults(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	defer store.Close()
	user := seedUser(t, store, "alice@example.com")
	key := mustKey(t)

	_, material, err := store.CreateOrGetDevice(ctx, user.ID, "Alice PC", key.PublicKey().String())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(material.ClientAddress, "10.88.0.") || !strings.HasSuffix(material.ClientAddress, "/32") {
		t.Fatalf("expected v2 client /32 address in 10.88.0.0/24, got %q", material.ClientAddress)
	}
	if material.Endpoint != "api-v2.45.63.22.174.sslip.io:51821" {
		t.Fatalf("expected v2 endpoint port 51821, got %q", material.Endpoint)
	}
	if material.AllowedIPs != "0.0.0.0/0" {
		t.Fatalf("expected IPv4 full tunnel AllowedIPs, got %q", material.AllowedIPs)
	}
	if strings.Contains(material.AllowedIPs, "::/0") {
		t.Fatalf("IPv6 full tunnel must not be enabled until IPv6 routing exists: %q", material.AllowedIPs)
	}
}

func testStore(t *testing.T) *Store {
	t.Helper()
	return openStore(t, testConfig(t))
}

func openStore(t *testing.T, cfg config.Config) *Store {
	t.Helper()
	store, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(filepath.Join("..", "..", "migrations", "001_init.sql")); err != nil {
		t.Fatal(err)
	}
	return store
}

func testConfig(t *testing.T) config.Config {
	t.Helper()
	serverKey := mustKey(t)
	return config.Config{
		DatabasePath:      ":memory:",
		SessionTTL:        time.Hour,
		WGInterface:       "wg-pvn-v2",
		WGSubnet:          "10.88.0.0/24",
		WGEndpointHost:    "api-v2.45.63.22.174.sslip.io",
		WGEndpointPort:    51821,
		WGServerPublicKey: serverKey.PublicKey().String(),
		WGDNS:             "1.1.1.1",
		WGAllowedIPs:      "0.0.0.0/0",
		WGDryRun:          false,
	}
}

func seedUser(t *testing.T, store *Store, email string) User {
	t.Helper()
	ctx := context.Background()
	if err := store.UpsertUser(ctx, email, "TestUser1!", "user"); err != nil {
		t.Fatal(err)
	}
	user, _, err := store.Login(ctx, email, "TestUser1!")
	if err != nil {
		t.Fatal(err)
	}
	return user
}

func mustKey(t *testing.T) wgtypes.Key {
	t.Helper()
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return key
}
