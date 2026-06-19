package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"pvn-v2/services/api/internal/config"
	"pvn-v2/services/api/internal/db"
)

func TestHealthReturnsOK(t *testing.T) {
	handler, _ := testHandler(t)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/health", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"ok"`) {
		t.Fatalf("unexpected health response: code=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestUnauthorizedRequestsFailCleanly(t *testing.T) {
	handler, _ := testHandler(t)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/me", nil))
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "unauthorized") {
		t.Fatalf("unexpected unauthorized response: code=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestDeviceProfileHTTPFlowIsIdempotent(t *testing.T) {
	handler, store := testHandler(t)
	token := loginToken(t, handler, store)
	clientKey := mustKey(t).PublicKey().String()

	firstCode, firstBody := postDevice(t, handler, token, clientKey)
	secondCode, secondBody := postDevice(t, handler, token, clientKey)
	if firstCode != http.StatusCreated || secondCode != http.StatusCreated {
		t.Fatalf("expected created responses, got %d/%d bodies=%s %s", firstCode, secondCode, firstBody, secondBody)
	}
	var first, second struct {
		Device db.Device         `json:"device"`
		Config db.ConfigMaterial `json:"config"`
	}
	decode(t, firstBody, &first)
	decode(t, secondBody, &second)
	if first.Device.ID != second.Device.ID {
		t.Fatalf("expected idempotent same device, got %d/%d", first.Device.ID, second.Device.ID)
	}
	if first.Config.ServerPublicKey == "" || first.Config.ClientAddress == "" || first.Config.Endpoint == "" || first.Config.AllowedIPs == "" {
		t.Fatalf("blank config material: %+v", first.Config)
	}
}

func TestDeviceCreateSyncsWireGuardPeer(t *testing.T) {
	store := testStore(t)
	t.Cleanup(func() { _ = store.Close() })
	if err := store.UpsertUser(context.Background(), "alice@example.com", "TestUser1!", "user"); err != nil {
		t.Fatal(err)
	}
	peers := &recordingPeers{}
	handler := New(store, peers)
	token := loginAs(t, handler, "alice@example.com", "TestUser1!")
	clientKey := mustKey(t).PublicKey().String()

	if code, body := postDevice(t, handler, token, clientKey); code != http.StatusCreated {
		t.Fatalf("create failed: %d %s", code, body)
	}
	if len(peers.upserts) != 1 || !strings.Contains(peers.upserts[0], clientKey) || !strings.Contains(peers.upserts[0], "10.88.0.2") {
		t.Fatalf("expected peer upsert, got %#v", peers.upserts)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/devices/reset", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("reset failed: %d %s", rec.Code, rec.Body.String())
	}
	if len(peers.removes) != 1 || peers.removes[0] != clientKey {
		t.Fatalf("expected peer removal, got %#v", peers.removes)
	}
}

func TestDuplicatePublicKeyForAnotherUserReturns409(t *testing.T) {
	handler, store := testHandler(t)
	aliceToken := loginToken(t, handler, store)
	if err := store.UpsertUser(context.Background(), "bob@example.com", "TestUser1!", "user"); err != nil {
		t.Fatal(err)
	}
	bobToken := loginAs(t, handler, "bob@example.com", "TestUser1!")
	clientKey := mustKey(t).PublicKey().String()

	if code, body := postDevice(t, handler, aliceToken, clientKey); code != http.StatusCreated {
		t.Fatalf("alice create failed: %d %s", code, body)
	}
	code, body := postDevice(t, handler, bobToken, clientKey)
	if code != http.StatusConflict || strings.Contains(strings.ToLower(body), "sqlite") {
		t.Fatalf("expected clean 409, got %d %s", code, body)
	}
}

func TestResetProfileHTTP(t *testing.T) {
	handler, store := testHandler(t)
	token := loginToken(t, handler, store)
	if code, body := postDevice(t, handler, token, mustKey(t).PublicKey().String()); code != http.StatusCreated {
		t.Fatalf("create failed: %d %s", code, body)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/devices/reset", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("reset failed: %d %s", rec.Code, rec.Body.String())
	}
	req = httptest.NewRequest(http.MethodGet, "/api/devices/current", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected not found after reset, got %d %s", rec.Code, rec.Body.String())
	}
}

func TestRawSQLiteErrorsAreNotReturned(t *testing.T) {
	if !isDatabaseError(errors.New("SQL logic error: no such table: devices")) {
		t.Fatal("expected SQL error to be recognized")
	}
	rec := httptest.NewRecorder()
	writeStoreError(rec, errors.New("SQL logic error: no such table: devices"))
	body := rec.Body.String()
	if strings.Contains(strings.ToLower(body), "sql logic error") || strings.Contains(strings.ToLower(body), "no such table") {
		t.Fatalf("raw DB error leaked: %s", body)
	}
}

func testHandler(t *testing.T) (http.Handler, *db.Store) {
	t.Helper()
	store := testStore(t)
	t.Cleanup(func() { _ = store.Close() })
	if err := store.UpsertUser(context.Background(), "alice@example.com", "TestUser1!", "user"); err != nil {
		t.Fatal(err)
	}
	return New(store), store
}

func testStore(t *testing.T) *db.Store {
	t.Helper()
	serverKey := mustKey(t)
	store, err := db.Open(config.Config{
		DatabasePath:      ":memory:",
		SessionTTL:        time.Hour,
		WGInterface:       "wg-pvn-v2",
		WGSubnet:          "10.88.0.0/24",
		WGEndpointHost:    "api-v2.45.63.22.174.sslip.io",
		WGEndpointPort:    51821,
		WGServerPublicKey: serverKey.PublicKey().String(),
		WGDNS:             "1.1.1.1",
		WGAllowedIPs:      "0.0.0.0/0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(filepath.Join("..", "..", "migrations", "001_init.sql")); err != nil {
		t.Fatal(err)
	}
	return store
}

func loginToken(t *testing.T, handler http.Handler, store *db.Store) string {
	t.Helper()
	_ = store
	return loginAs(t, handler, "alice@example.com", "TestUser1!")
}

func loginAs(t *testing.T, handler http.Handler, email, password string) string {
	t.Helper()
	payload, _ := json.Marshal(map[string]string{"email": email, "password": password})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(payload)))
	if rec.Code != http.StatusOK {
		t.Fatalf("login failed: %d %s", rec.Code, rec.Body.String())
	}
	var response struct {
		Token string `json:"token"`
	}
	decode(t, rec.Body.String(), &response)
	if response.Token == "" {
		t.Fatal("login returned blank token")
	}
	return response.Token
}

func postDevice(t *testing.T, handler http.Handler, token, clientPublicKey string) (int, string) {
	t.Helper()
	payload, _ := json.Marshal(map[string]string{"name": "Windows PC", "client_public_key": clientPublicKey})
	req := httptest.NewRequest(http.MethodPost, "/api/devices", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func decode(t *testing.T, body string, target any) {
	t.Helper()
	if err := json.Unmarshal([]byte(body), target); err != nil {
		t.Fatalf("decode failed: %v body=%s", err, body)
	}
}

func mustKey(t *testing.T) wgtypes.Key {
	t.Helper()
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

type recordingPeers struct {
	upserts []string
	removes []string
}

func (r *recordingPeers) UpsertPeer(_ context.Context, publicKey, assignedIP string) error {
	r.upserts = append(r.upserts, publicKey+" "+assignedIP)
	return nil
}

func (r *recordingPeers) RemovePeer(_ context.Context, publicKey string) error {
	r.removes = append(r.removes, publicKey)
	return nil
}
