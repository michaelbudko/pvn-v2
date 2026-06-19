# PVN v2

PVN v2 is a simple Windows VPN app.

The product is only considered working when a real Windows E2E test proves:

- baseline public IP is not `45.63.22.174`
- after `GO`, public IP is `45.63.22.174`
- after `STOP`, public IP is not `45.63.22.174`
- reconnect works without manual cleanup
- internet works after disconnect

Unit tests, mocks, CI checks, and installer builds are required, but they are not proof that the VPN works.

## Layout

- `apps/windows-ui`: branded Windows UI shell.
- `apps/windows-service`: privileged local helper service that owns tunnel lifecycle.
- `services/api`: backend control API.
- `infra/vps`: VPS deployment scripts.
- `scripts/e2e`: real Windows VPN E2E scripts.
- `release/download-site`: minimal download page.
- `docs`: architecture, testing, and deployment notes.

## Current Scope

MVP only:

- login
- one `GO` button
- one `STOP` button
- local helper service
- official WireGuard tunnel/service mode
- one VPS exit node
- real public-IP E2E gate

No billing, mobile app, browser extension, custom VPN protocol, custom driver, multi-server UI, or speculative features.

