# Windows VPN E2E Testing

This test is the release gate for PVN v2. CI tests can prove config validation, service command construction, and builds. They do not prove the PC is actually using the VPN.

The real E2E test proves:

- baseline public IP is not `45.63.22.174`
- after GO/connect, public IP is `45.63.22.174`
- a PVN-owned WireGuard tunnel is active
- internet still works while connected
- after STOP/disconnect, public IP is not `45.63.22.174`
- internet still works after disconnect
- reconnect works without deleting a tunnel manually

Run in PowerShell as Administrator:

```powershell
cd C:\Users\MB\Documents\VpnProxy\pvn-v2
$env:PVN_V2_E2E_EMAIL="test@example.com"
$env:PVN_V2_E2E_PASSWORD="do-not-commit-this"
$env:PVN_V2_E2E_API_URL="https://api-v2.45.63.22.174.sslip.io"
.\scripts\e2e\windows-vpn-e2e.ps1
```

To install a freshly built installer before the test:

```powershell
.\scripts\e2e\windows-vpn-e2e.ps1 -InstallerPath "C:\path\to\PVN-v2-Windows-Setup.exe"
```

Logs are written to `artifacts/e2e/`. They include public IPs, tunnel state, and safe command exit codes. They must not include passwords, tokens, private keys, or WireGuard configs.

If internet breaks, restart Windows. The script never runs `netsh reset`, disables adapters, or touches non-PVN tunnels. It only removes PVN-owned tunnel names.

VPS-side verification while connected:

```bash
sudo wg show wg-pvn-v2
```

Expected: the connected peer has a recent handshake and transfer counters increasing.
