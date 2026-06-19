package wg

import (
	"context"
	"fmt"
	"net"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Manager struct {
	Interface string
	DryRun    bool
}

func (m Manager) UpsertPeer(ctx context.Context, publicKey, assignedIP string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	key, allowedIP, err := parsePeer(publicKey, assignedIP)
	if err != nil {
		return err
	}
	if m.DryRun {
		return nil
	}
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("open wireguard control client: %w", err)
	}
	defer client.Close()
	return client.ConfigureDevice(m.Interface, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{{
			PublicKey:         key,
			ReplaceAllowedIPs: true,
			AllowedIPs:        []net.IPNet{allowedIP},
		}},
	})
}

func (m Manager) RemovePeer(ctx context.Context, publicKey string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	key, err := wgtypes.ParseKey(strings.TrimSpace(publicKey))
	if err != nil {
		return fmt.Errorf("invalid peer public key: %w", err)
	}
	if m.DryRun {
		return nil
	}
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("open wireguard control client: %w", err)
	}
	defer client.Close()
	return client.ConfigureDevice(m.Interface, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{{
			PublicKey: key,
			Remove:    true,
		}},
	})
}

func parsePeer(publicKey, assignedIP string) (wgtypes.Key, net.IPNet, error) {
	key, err := wgtypes.ParseKey(strings.TrimSpace(publicKey))
	if err != nil {
		return wgtypes.Key{}, net.IPNet{}, fmt.Errorf("invalid peer public key: %w", err)
	}
	ip := net.ParseIP(strings.TrimSpace(assignedIP)).To4()
	if ip == nil {
		return wgtypes.Key{}, net.IPNet{}, fmt.Errorf("invalid assigned IPv4 address")
	}
	return key, net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}, nil
}
