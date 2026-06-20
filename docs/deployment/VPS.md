# PVN v2 VPS Deployment

PVN v2 deploys beside v1. It uses:

- API service: `pvn-v2-api`
- API domain: `api-v2.45.63.22.174.sslip.io`
- API port: `127.0.0.1:8081`
- WireGuard interface: `wg-pvn-v2`
- WireGuard UDP port: `51821`
- VPN subnet: `10.88.0.0/24`
- Database: `/opt/pvn-v2/pvn-v2.db`
- Environment file: `/etc/pvn-v2/api.env`
- MVP auth mode: `PVN_MVP_NO_LOGIN=true`

`PVN_MVP_NO_LOGIN=true` is a single-user MVP testing shortcut. It makes the API
resolve protected routes to `mvp@pvn-v2.local` without requiring a bearer token.
Do not treat this as production authentication.

Run on the VPS:

```bash
sudo bash /opt/pvn-v2-src/infra/vps/install.sh
sudo bash /opt/pvn-v2-src/infra/vps/wireguard.sh
sudo DEV_SEED_USER='user@example.com' DEV_SEED_PASSWORD='change-me' bash /opt/pvn-v2-src/infra/vps/deploy-api.sh
```

Do not commit seed passwords. Pass them only through the shell environment.

Rollback:

```bash
sudo systemctl disable --now pvn-v2-api
sudo systemctl disable --now wg-quick@wg-pvn-v2
sudo rm -f /etc/systemd/system/pvn-v2-api.service
```

Remove only the PVN v2 block from `/etc/caddy/Caddyfile`, then run:

```bash
sudo systemctl daemon-reload
sudo systemctl reload caddy
```
