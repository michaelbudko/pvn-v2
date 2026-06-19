#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y \
  ca-certificates \
  caddy \
  curl \
  git \
  golang \
  iptables \
  sqlite3 \
  ufw \
  wireguard \
  wireguard-tools

install -d -m 0755 /opt/pvn-v2 /etc/pvn-v2

systemctl enable caddy
systemctl restart caddy

echo "PVN v2 base packages installed."
