# ADR-001: PVN v2 Architecture

Date: 2026-06-19

## Status

Accepted for MVP implementation.

## Context

PVN v1 proved that a VPN client can pass unit tests and still fail real users. The key failure was false confidence: local command success and UI state were treated as VPN success before a real public-IP change was proven.

PVN v2 must be smaller and stricter. The normal user flow is:

1. Install PVN.
2. Open PVN.
3. Click `GO`.
4. Public IP becomes `45.63.22.174`.
5. Click `STOP`.
6. Public IP returns to a non-VPN address.
7. Reconnect works without manual cleanup.

## Decision

Use Option B:

- A branded Windows UI app.
- A privileged PVN Windows helper service.
- Official WireGuard for Windows tunnel/service mode as the VPN engine.
- A small backend control API on the VPS.
- A real Windows E2E test as the release gate.

## Windows UI Technology

Use Tauri + React for the MVP UI.

Reasons:

- The UI is intentionally small: status, `GO`, `STOP`, and Advanced diagnostics.
- Existing local toolchain already supports Tauri builds and NSIS installers.
- Tauri does not own privileged networking; it only calls the helper service.

Rejected for MVP:

- WPF/WinUI rewrite. It does not reduce VPN tunnel risk by itself.

## Windows Service Technology

Use Rust for the helper service.

Reasons:

- Strong single-binary deployment.
- Good Windows API access when needed.
- Shared implementation style with Tauri backend code.
- Simple testable tunnel-controller boundary.

The service exposes a minimal localhost-only HTTP API on `127.0.0.1`.

## Service Security

The helper service:

- listens only on `127.0.0.1`
- stores its machine-wide bearer token at `C:\ProgramData\PVN v2\helper-token`
- generates that token from the installer or first service startup if it is missing
- allows read-only `status` and `diagnostics` without a token
- requires the bearer token for `connect`, `disconnect`, `reset`, and `auth-check`
- parses the `Authorization` header case-insensitively so standard HTTP clients do not fail on header casing
- exposes only `status`, `auth-check`, `connect`, `disconnect`, `reset`, and `diagnostics`
- never accepts arbitrary commands
- never logs private keys, backend tokens, or full WireGuard configs
- only manages PVN-owned tunnel/profile state

This is acceptable for MVP. A future hardening step can replace localhost HTTP with a named pipe and tighter ACLs.

## WireGuard Control

Use official WireGuard for Windows tunnel/service commands:

- `wireguard.exe /installtunnelservice <pvn-v2.conf>`
- `wireguard.exe /uninstalltunnelservice pvn-v2`

The WireGuard GUI is never launched. PVN manages one canonical tunnel name:

- `pvn-v2`

Before installing the full-tunnel route, the helper adds a PVN-owned `/32`
host route for the WireGuard endpoint so UDP handshakes to the VPS do not get
captured by the tunnel default route. Cleanup removes only the route PVN
created.

The service may clean up PVN-owned legacy names only. It must not touch unrelated user tunnels.

## Backend

Use Go + SQLite for the MVP backend.

Responsibilities:

- health
- MVP login
- device/profile provisioning
- client public key registration
- VPN IP assignment
- config material return
- reset profile

The backend is intentionally not a billing/account platform.

## VPS Deployment

Deploy as separate v2 services so v1 is not broken:

- systemd service: `pvn-v2-api`
- API domain: `https://api-v2.45.63.22.174.sslip.io`
- database: `/opt/pvn-v2/pvn-v2.db`
- environment: `/etc/pvn-v2/api.env`
- WireGuard interface: `wg-pvn-v2`
- UDP port: `51821`
- subnet: `10.88.0.0/24`

## E2E Proof

The real E2E test must run on Windows and prove:

- before connect public IP is not `45.63.22.174`
- after `GO` public IP is `45.63.22.174`
- after `STOP` public IP is not `45.63.22.174`
- reconnect works without manual cleanup
- internet works after disconnect

No mocked test can replace this gate.

## Intentionally Not Included

- mobile app
- browser extension
- proxy-only mode
- custom VPN protocol
- custom kernel driver
- Firebase
- Stripe
- Kubernetes
- multi-server UI
- split tunneling
- kill switch
- auto-updater
- billing/accounts
- marketing site beyond a minimal download page
