package db

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	_ "modernc.org/sqlite"

	"pvn-v2/services/api/internal/config"
)

var (
	ErrNotFound      = errors.New("not found")
	ErrUnauthorized  = errors.New("unauthorized")
	ErrConflict      = errors.New("conflict")
	ErrMisconfigured = errors.New("misconfigured")
)

type Store struct {
	DB  *sql.DB
	Cfg config.Config
}

type User struct {
	ID    int64  `json:"id"`
	Email string `json:"email"`
	Role  string `json:"role"`
}

type Device struct {
	ID              int64  `json:"id"`
	UserID          int64  `json:"user_id"`
	Name            string `json:"name"`
	ClientPublicKey string `json:"client_public_key"`
	AssignedIP      string `json:"assigned_ip"`
}

type ConfigMaterial struct {
	DeviceID        int64  `json:"device_id"`
	ClientAddress   string `json:"client_address"`
	ServerPublicKey string `json:"server_public_key"`
	Endpoint        string `json:"endpoint"`
	DNS             string `json:"dns"`
	AllowedIPs      string `json:"allowed_ips"`
}

func Open(cfg config.Config) (*Store, error) {
	database, err := sql.Open("sqlite", cfg.DatabasePath)
	if err != nil {
		return nil, err
	}
	database.SetMaxOpenConns(1)
	if _, err := database.Exec(`PRAGMA foreign_keys = ON`); err != nil {
		_ = database.Close()
		return nil, err
	}
	if _, err := database.Exec(`PRAGMA busy_timeout = 5000`); err != nil {
		_ = database.Close()
		return nil, err
	}
	if cfg.DatabasePath != ":memory:" {
		if _, err := database.Exec(`PRAGMA journal_mode = WAL`); err != nil {
			_ = database.Close()
			return nil, err
		}
		if _, err := database.Exec(`PRAGMA synchronous = NORMAL`); err != nil {
			_ = database.Close()
			return nil, err
		}
	}
	return &Store{DB: database, Cfg: cfg}, nil
}

func (s *Store) Close() error {
	return s.DB.Close()
}

func (s *Store) Health(ctx context.Context) error {
	var value int
	if err := s.DB.QueryRowContext(ctx, `SELECT 1`).Scan(&value); err != nil {
		return err
	}
	if value != 1 {
		return errors.New("database health check failed")
	}
	return nil
}

func (s *Store) Migrate(path string) error {
	body, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	_, err = s.DB.Exec(string(body))
	return err
}

func (s *Store) UpsertUser(ctx context.Context, email, password, role string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" || password == "" {
		return fmt.Errorf("email and password are required")
	}
	if role == "" {
		role = "user"
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_, err = s.DB.ExecContext(ctx, `
		INSERT INTO users(email,password_hash,role,created_at,updated_at)
		VALUES(?,?,?,?,?)
		ON CONFLICT(email) DO UPDATE SET password_hash=excluded.password_hash, role=excluded.role, updated_at=excluded.updated_at`,
		email, string(hash), role, now, now)
	return err
}

func (s *Store) Login(ctx context.Context, email, password string) (User, string, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	var user User
	var hash string
	err := s.DB.QueryRowContext(ctx, `SELECT id,email,role,password_hash FROM users WHERE email=?`, email).
		Scan(&user.ID, &user.Email, &user.Role, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, "", ErrUnauthorized
	}
	if err != nil {
		return User{}, "", err
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		return User{}, "", ErrUnauthorized
	}
	token, err := randomToken()
	if err != nil {
		return User{}, "", err
	}
	now := time.Now().UTC()
	_, err = s.DB.ExecContext(ctx, `INSERT INTO sessions(token,user_id,expires_at,created_at) VALUES(?,?,?,?)`,
		token, user.ID, now.Add(s.Cfg.SessionTTL).Format(time.RFC3339), now.Format(time.RFC3339))
	if err != nil {
		return User{}, "", err
	}
	return user, token, nil
}

func (s *Store) UserForToken(ctx context.Context, token string) (User, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return User{}, ErrUnauthorized
	}
	var user User
	var expires string
	err := s.DB.QueryRowContext(ctx, `
		SELECT users.id, users.email, users.role, sessions.expires_at
		FROM sessions
		JOIN users ON users.id = sessions.user_id
		WHERE sessions.token = ?`, token).
		Scan(&user.ID, &user.Email, &user.Role, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrUnauthorized
	}
	if err != nil {
		return User{}, err
	}
	expiresAt, err := time.Parse(time.RFC3339, expires)
	if err != nil || time.Now().UTC().After(expiresAt) {
		return User{}, ErrUnauthorized
	}
	return user, nil
}

func (s *Store) CreateOrGetDevice(ctx context.Context, userID int64, name, clientPublicKey string) (Device, ConfigMaterial, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "Windows PC"
	}
	clientPublicKey = strings.TrimSpace(clientPublicKey)
	if _, err := wgtypes.ParseKey(clientPublicKey); err != nil {
		return Device{}, ConfigMaterial{}, fmt.Errorf("invalid client public key")
	}
	if err := validateServerPublicKey(s.Cfg.WGServerPublicKey); err != nil {
		return Device{}, ConfigMaterial{}, err
	}

	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Device{}, ConfigMaterial{}, err
	}
	defer tx.Rollback()

	existing, err := deviceByPublicKey(ctx, tx, clientPublicKey)
	if err == nil {
		if existing.UserID != userID {
			return Device{}, ConfigMaterial{}, ErrConflict
		}
		material := s.material(existing)
		return existing, material, tx.Commit()
	}
	if !errors.Is(err, ErrNotFound) {
		return Device{}, ConfigMaterial{}, err
	}

	assignedIP, err := nextAssignedIP(ctx, tx, s.Cfg.WGSubnet)
	if err != nil {
		return Device{}, ConfigMaterial{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := tx.ExecContext(ctx, `
		INSERT INTO devices(user_id,name,client_public_key,assigned_ip,created_at,updated_at)
		VALUES(?,?,?,?,?,?)`,
		userID, name, clientPublicKey, assignedIP, now, now)
	if sqliteIsConstraint(err) {
		return Device{}, ConfigMaterial{}, ErrConflict
	}
	if err != nil {
		return Device{}, ConfigMaterial{}, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return Device{}, ConfigMaterial{}, err
	}
	device := Device{ID: id, UserID: userID, Name: name, ClientPublicKey: clientPublicKey, AssignedIP: assignedIP}
	return device, s.material(device), tx.Commit()
}

func (s *Store) CurrentDevice(ctx context.Context, userID int64) (Device, ConfigMaterial, error) {
	var device Device
	err := s.DB.QueryRowContext(ctx, `
		SELECT id,user_id,name,client_public_key,assigned_ip
		FROM devices
		WHERE user_id=?
		ORDER BY id DESC
		LIMIT 1`, userID).
		Scan(&device.ID, &device.UserID, &device.Name, &device.ClientPublicKey, &device.AssignedIP)
	if errors.Is(err, sql.ErrNoRows) {
		return Device{}, ConfigMaterial{}, ErrNotFound
	}
	if err != nil {
		return Device{}, ConfigMaterial{}, err
	}
	if err := validateServerPublicKey(s.Cfg.WGServerPublicKey); err != nil {
		return Device{}, ConfigMaterial{}, err
	}
	return device, s.material(device), nil
}

func (s *Store) DevicesForUser(ctx context.Context, userID int64) ([]Device, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT id,user_id,name,client_public_key,assigned_ip
		FROM devices
		WHERE user_id=?`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var devices []Device
	for rows.Next() {
		var device Device
		if err := rows.Scan(&device.ID, &device.UserID, &device.Name, &device.ClientPublicKey, &device.AssignedIP); err != nil {
			return nil, err
		}
		devices = append(devices, device)
	}
	return devices, rows.Err()
}

func (s *Store) ResetDevices(ctx context.Context, userID int64) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM devices WHERE user_id=?`, userID)
	return err
}

func (s *Store) material(device Device) ConfigMaterial {
	return ConfigMaterial{
		DeviceID:        device.ID,
		ClientAddress:   device.AssignedIP + "/32",
		ServerPublicKey: strings.TrimSpace(s.Cfg.WGServerPublicKey),
		Endpoint:        fmt.Sprintf("%s:%d", strings.TrimSpace(s.Cfg.WGEndpointHost), s.Cfg.WGEndpointPort),
		DNS:             strings.TrimSpace(s.Cfg.WGDNS),
		AllowedIPs:      strings.TrimSpace(s.Cfg.WGAllowedIPs),
	}
}

type txQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func deviceByPublicKey(ctx context.Context, q txQueryer, publicKey string) (Device, error) {
	var device Device
	err := q.QueryRowContext(ctx, `
		SELECT id,user_id,name,client_public_key,assigned_ip
		FROM devices
		WHERE client_public_key=?`, publicKey).
		Scan(&device.ID, &device.UserID, &device.Name, &device.ClientPublicKey, &device.AssignedIP)
	if errors.Is(err, sql.ErrNoRows) {
		return Device{}, ErrNotFound
	}
	return device, err
}

func nextAssignedIP(ctx context.Context, q txQueryer, subnet string) (string, error) {
	ip, ipNet, err := net.ParseCIDR(subnet)
	if err != nil {
		return "", err
	}
	base := ip.To4()
	ones, bits := ipNet.Mask.Size()
	if base == nil || ones == 0 || bits != 32 {
		return "", fmt.Errorf("only IPv4 subnets are supported")
	}
	used := map[string]bool{}
	rows, err := queryRows(ctx, q, `SELECT assigned_ip FROM devices`)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	for rows.Next() {
		var assigned string
		if err := rows.Scan(&assigned); err != nil {
			return "", err
		}
		used[assigned] = true
	}
	for i := 2; i < 254; i++ {
		candidate := net.IPv4(base[0], base[1], base[2], byte(i)).String()
		if ipNet.Contains(net.ParseIP(candidate)) && !used[candidate] {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("VPN subnet has no available client addresses")
}

type rowQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func queryRows(ctx context.Context, q txQueryer, query string) (*sql.Rows, error) {
	if rq, ok := q.(rowQueryer); ok {
		return rq.QueryContext(ctx, query)
	}
	return nil, fmt.Errorf("queryer does not support rows")
}

func validateServerPublicKey(publicKey string) error {
	if strings.TrimSpace(publicKey) == "" {
		return fmt.Errorf("%w: server public key is not configured", ErrMisconfigured)
	}
	if _, err := wgtypes.ParseKey(publicKey); err != nil {
		return fmt.Errorf("%w: invalid server public key", ErrMisconfigured)
	}
	return nil
}

func sqliteIsConstraint(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "constraint")
}

func randomToken() (string, error) {
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf[:]), nil
}
