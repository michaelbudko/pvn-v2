package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Config struct {
	APIHost           string
	APIPort           string
	DatabasePath      string
	SessionTTL        time.Duration
	WGInterface       string
	WGSubnet          string
	WGEndpointHost    string
	WGEndpointPort    int
	WGServerPublicKey string
	WGDNS             string
	WGAllowedIPs      string
	WGDryRun          bool
	MVPNoLogin        bool
}

func Load() (Config, error) {
	ttlHours := getInt("SESSION_TTL_HOURS", 720)
	cfg := Config{
		APIHost:           get("API_HOST", "127.0.0.1"),
		APIPort:           get("API_PORT", "8081"),
		DatabasePath:      get("DATABASE_PATH", "./pvn-v2.db"),
		SessionTTL:        time.Duration(ttlHours) * time.Hour,
		WGInterface:       get("WG_INTERFACE", "wg-pvn-v2"),
		WGSubnet:          get("WG_SUBNET", "10.88.0.0/24"),
		WGEndpointHost:    get("WG_ENDPOINT_HOST", "api-v2.45.63.22.174.sslip.io"),
		WGEndpointPort:    getInt("WG_ENDPOINT_PORT", 51821),
		WGServerPublicKey: get("WG_SERVER_PUBLIC_KEY", ""),
		WGDNS:             get("WG_DNS", "1.1.1.1"),
		WGAllowedIPs:      get("WG_ALLOWED_IPS", "0.0.0.0/0"),
		WGDryRun:          getBool("WG_DRY_RUN", false),
		MVPNoLogin:        getBool("PVN_MVP_NO_LOGIN", false),
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) Addr() string {
	return net.JoinHostPort(c.APIHost, c.APIPort)
}

func (c Config) Validate() error {
	if _, _, err := net.ParseCIDR(c.WGSubnet); err != nil {
		return fmt.Errorf("invalid WG_SUBNET: %w", err)
	}
	if c.WGEndpointPort <= 0 || c.WGEndpointPort > 65535 {
		return fmt.Errorf("invalid WG_ENDPOINT_PORT")
	}
	serverKey := strings.TrimSpace(c.WGServerPublicKey)
	if !c.WGDryRun && serverKey == "" {
		return fmt.Errorf("WG_SERVER_PUBLIC_KEY must be set when WG_DRY_RUN=false")
	}
	if serverKey != "" {
		if _, err := wgtypes.ParseKey(serverKey); err != nil {
			return fmt.Errorf("invalid WG_SERVER_PUBLIC_KEY: %w", err)
		}
	}
	if strings.TrimSpace(c.WGEndpointHost) == "" {
		return fmt.Errorf("WG_ENDPOINT_HOST must be set")
	}
	if strings.TrimSpace(c.WGAllowedIPs) == "" {
		return fmt.Errorf("WG_ALLOWED_IPS must be set")
	}
	return nil
}

func get(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func getInt(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func getBool(key string, fallback bool) bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	switch value {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}
