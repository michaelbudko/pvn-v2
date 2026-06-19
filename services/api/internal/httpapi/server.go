package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"pvn-v2/services/api/internal/db"
)

type Server struct {
	Store *db.Store
	Peers PeerManager
	mux   *http.ServeMux
}

type PeerManager interface {
	UpsertPeer(ctx context.Context, publicKey, assignedIP string) error
	RemovePeer(ctx context.Context, publicKey string) error
}

type noopPeerManager struct{}

func (noopPeerManager) UpsertPeer(context.Context, string, string) error { return nil }
func (noopPeerManager) RemovePeer(context.Context, string) error         { return nil }

func New(store *db.Store, peers ...PeerManager) http.Handler {
	peerManager := PeerManager(noopPeerManager{})
	if len(peers) > 0 && peers[0] != nil {
		peerManager = peers[0]
	}
	s := &Server{Store: store, Peers: peerManager, mux: http.NewServeMux()}
	s.routes()
	return s.withCORS(s.mux)
}

func (s *Server) routes() {
	s.mux.HandleFunc("/api/health", s.health)
	s.mux.HandleFunc("/api/auth/login", s.login)
	s.mux.HandleFunc("/api/me", s.authenticated(s.me))
	s.mux.HandleFunc("/api/devices", s.authenticated(s.devices))
	s.mux.HandleFunc("/api/devices/current", s.authenticated(s.currentDevice))
	s.mux.HandleFunc("/api/devices/reset", s.authenticated(s.resetDevice))
	s.mux.HandleFunc("/api/vpn/config", s.authenticated(s.vpnConfig))
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Second)
	defer cancel()
	if err := s.Store.Health(ctx); err != nil {
		writeError(w, http.StatusServiceUnavailable, "unhealthy")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var input struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	user, token, err := s.Store.Login(r.Context(), input.Email, input.Password)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": user, "token": token})
}

func (s *Server) me(w http.ResponseWriter, r *http.Request, user db.User) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": user})
}

func (s *Server) devices(w http.ResponseWriter, r *http.Request, user db.User) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var input struct {
		Name            string `json:"name"`
		ClientPublicKey string `json:"client_public_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	device, material, err := s.Store.CreateOrGetDevice(r.Context(), user.ID, input.Name, input.ClientPublicKey)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if err := s.Peers.UpsertPeer(r.Context(), device.ClientPublicKey, device.AssignedIP); err != nil {
		writeError(w, http.StatusServiceUnavailable, "VPN server peer sync failed")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"device": device, "config": material})
}

func (s *Server) currentDevice(w http.ResponseWriter, r *http.Request, user db.User) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	device, material, err := s.Store.CurrentDevice(r.Context(), user.ID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"device": device, "config": material})
}

func (s *Server) resetDevice(w http.ResponseWriter, r *http.Request, user db.User) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	devices, err := s.Store.DevicesForUser(r.Context(), user.ID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	for _, device := range devices {
		if err := s.Peers.RemovePeer(r.Context(), device.ClientPublicKey); err != nil {
			writeError(w, http.StatusServiceUnavailable, "VPN server peer removal failed")
			return
		}
	}
	if err := s.Store.ResetDevices(r.Context(), user.ID); err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "reset"})
}

func (s *Server) vpnConfig(w http.ResponseWriter, r *http.Request, user db.User) {
	s.currentDevice(w, r, user)
}

func (s *Server) authenticated(next func(http.ResponseWriter, *http.Request, db.User)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		header := strings.TrimSpace(r.Header.Get("Authorization"))
		token := strings.TrimPrefix(header, "Bearer ")
		if token == header {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		user, err := s.Store.UserForToken(r.Context(), token)
		if err != nil {
			writeStoreError(w, err)
			return
		}
		next(w, r, user)
	}
}

func (s *Server) withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, db.ErrUnauthorized):
		writeError(w, http.StatusUnauthorized, "unauthorized")
	case errors.Is(err, db.ErrNotFound):
		writeError(w, http.StatusNotFound, "not found")
	case errors.Is(err, db.ErrConflict):
		writeError(w, http.StatusConflict, "VPN profile already exists for another user")
	case errors.Is(err, db.ErrMisconfigured):
		writeError(w, http.StatusServiceUnavailable, "VPN server is not configured")
	case isDatabaseError(err):
		writeError(w, http.StatusInternalServerError, "database operation failed")
	default:
		writeError(w, http.StatusBadRequest, err.Error())
	}
}

func isDatabaseError(err error) bool {
	if err == nil {
		return false
	}
	lower := strings.ToLower(err.Error())
	return strings.Contains(lower, "sqlite") ||
		strings.Contains(lower, "sql logic error") ||
		strings.Contains(lower, "database is locked") ||
		strings.Contains(lower, "no such table")
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
