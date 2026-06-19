#!/usr/bin/env bash
set -euo pipefail

WG_IFACE="${WG_IFACE:-wg-pvn-v2}"
WG_PORT="${WG_PORT:-51821}"
WG_ADDR="${WG_ADDR:-10.88.0.1/24}"
WG_CONF="/etc/wireguard/${WG_IFACE}.conf"
WG_PRIV="/etc/wireguard/${WG_IFACE}.key"
WG_PUB="/etc/wireguard/${WG_IFACE}.pub"
EGRESS_IFACE="${EGRESS_IFACE:-$(ip route show default | awk '/default/ {print $5; exit}')}"

if [[ -z "${EGRESS_IFACE}" ]]; then
  echo "Could not detect default egress interface." >&2
  exit 1
fi

install -d -m 0700 /etc/wireguard

if [[ ! -f "${WG_PRIV}" ]]; then
  umask 077
  wg genkey > "${WG_PRIV}"
  wg pubkey < "${WG_PRIV}" > "${WG_PUB}"
fi

cat > "${WG_CONF}" <<EOF
[Interface]
Address = ${WG_ADDR}
ListenPort = ${WG_PORT}
PrivateKey = $(cat "${WG_PRIV}")
PostUp = iptables -t nat -A POSTROUTING -s 10.88.0.0/24 -o ${EGRESS_IFACE} -j MASQUERADE
PostDown = iptables -t nat -D POSTROUTING -s 10.88.0.0/24 -o ${EGRESS_IFACE} -j MASQUERADE
EOF

chmod 600 "${WG_CONF}" "${WG_PRIV}"

cat >/etc/sysctl.d/99-pvn-v2.conf <<EOF
net.ipv4.ip_forward=1
EOF
sysctl --system >/dev/null

systemctl enable "wg-quick@${WG_IFACE}"
systemctl restart "wg-quick@${WG_IFACE}"

ufw allow "${WG_PORT}/udp" || true
ufw allow 80/tcp || true
ufw allow 443/tcp || true

echo "PVN v2 WireGuard interface ready:"
echo "interface=${WG_IFACE}"
echo "port=${WG_PORT}"
echo "subnet=10.88.0.0/24"
echo "public_key=$(cat "${WG_PUB}")"
