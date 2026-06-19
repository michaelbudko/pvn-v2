#!/usr/bin/env bash
set -euo pipefail

SRC_DIR="${SRC_DIR:-/opt/pvn-v2-src}"
APP_DIR="${APP_DIR:-/opt/pvn-v2}"
ENV_DIR="/etc/pvn-v2"
ENV_FILE="${ENV_DIR}/api.env"
DOMAIN="${PVN_V2_API_DOMAIN:-api-v2.45.63.22.174.sslip.io}"
WG_IFACE="${WG_IFACE:-wg-pvn-v2}"
WG_PORT="${WG_PORT:-51821}"
WG_PUBLIC_KEY_FILE="/etc/wireguard/${WG_IFACE}.pub"

if [[ ! -d "${SRC_DIR}/services/api" ]]; then
  echo "Source directory not found: ${SRC_DIR}/services/api" >&2
  exit 1
fi

if [[ ! -f "${WG_PUBLIC_KEY_FILE}" ]]; then
  echo "WireGuard public key missing. Run infra/vps/wireguard.sh first." >&2
  exit 1
fi

install -d -m 0755 "${APP_DIR}" "${ENV_DIR}"

cd "${SRC_DIR}/services/api"
go mod tidy
go test ./...
go build -buildvcs=false -o api ./cmd/api
go build -buildvcs=false -o seed-user ./cmd/seed-user

systemctl stop pvn-v2-api 2>/dev/null || true
install -m 0755 api "${APP_DIR}/api.new"
mv "${APP_DIR}/api.new" "${APP_DIR}/api"
cp -R migrations "${APP_DIR}/migrations"

cat > "${ENV_FILE}" <<EOF
API_HOST=127.0.0.1
API_PORT=8081
DATABASE_PATH=${APP_DIR}/pvn-v2.db
SESSION_TTL_HOURS=720
WG_INTERFACE=${WG_IFACE}
WG_SUBNET=10.88.0.0/24
WG_ENDPOINT_HOST=${DOMAIN}
WG_ENDPOINT_PORT=${WG_PORT}
WG_DNS=1.1.1.1
WG_ALLOWED_IPS=0.0.0.0/0
WG_DRY_RUN=false
WG_SERVER_PUBLIC_KEY=$(cat "${WG_PUBLIC_KEY_FILE}")
EOF
chmod 0600 "${ENV_FILE}"

if [[ -n "${DEV_SEED_USER:-}" && -n "${DEV_SEED_PASSWORD:-}" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "${ENV_FILE}"
  set +a
  ./seed-user -email "${DEV_SEED_USER}" -password "${DEV_SEED_PASSWORD}" -role user
else
  echo "Seed user skipped. Set DEV_SEED_USER and DEV_SEED_PASSWORD to create one."
fi

cp "${SRC_DIR}/infra/vps/pvn-v2-api.service" /etc/systemd/system/pvn-v2-api.service
systemctl daemon-reload
systemctl enable pvn-v2-api
systemctl restart pvn-v2-api

if ! grep -q "BEGIN PVN v2" /etc/caddy/Caddyfile; then
  cat >> /etc/caddy/Caddyfile <<EOF

# BEGIN PVN v2
${DOMAIN} {
  reverse_proxy 127.0.0.1:8081
}
# END PVN v2
EOF
fi
caddy fmt --overwrite /etc/caddy/Caddyfile
systemctl reload caddy

curl -fsS "http://127.0.0.1:8081/api/health"
echo
curl -fsS "https://${DOMAIN}/api/health"
echo
systemctl --no-pager --full status pvn-v2-api | head -n 20
