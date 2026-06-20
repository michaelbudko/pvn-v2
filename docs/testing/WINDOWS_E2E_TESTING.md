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

The installer must create and start the canonical helper service:

- service name: `PVNv2Helper`
- display name: `PVN v2 Helper`
- helper token path: `C:\ProgramData\PVN v2\helper-token`
- `/status` must work without a helper token
- `/auth-check` verifies the UI/helper token path before VPN connect
- protected commands use the helper token and must not return helper 401 after a clean install

Verify after install:

```powershell
Get-Service | Where-Object { $_.Name -match "pvn|vpn" -or $_.DisplayName -match "pvn|vpn" }
```

If PVN v2 is already installed and `PVNv2Helper` is running, run:

```powershell
cd C:\Users\MB\Documents\VpnProxy\pvn-v2
$env:PVN_V2_E2E_API_URL="https://api-v2.45.63.22.174.sslip.io"
.\scripts\e2e\windows-vpn-e2e.ps1
```

PVN v2 MVP no-login mode does not require `PVN_V2_E2E_EMAIL` or
`PVN_V2_E2E_PASSWORD`. The backend must have `PVN_MVP_NO_LOGIN=true`.

To install a freshly built installer before the test, run PowerShell as Administrator:

```powershell
.\scripts\e2e\windows-vpn-e2e.ps1 -InstallerPath "C:\path\to\PVN-v2-Windows-Setup.exe"
```

Logs are written to `artifacts/e2e/`. They include public IPs, tunnel state, and safe command exit codes. They must not include passwords, tokens, private keys, or WireGuard configs.

The E2E script fails before VPN verification if:

- `http://127.0.0.1:47621/status` returns `401`
- `http://127.0.0.1:47621/auth-check` returns `401`
- the `PVNv2Helper` service is missing or stopped and cannot be started

Hard reset if helper auth stays broken after repair:

```powershell
Stop-Service PVNv2Helper -ErrorAction SilentlyContinue
sc.exe delete PVNv2Helper
Remove-Item -Recurse -Force "C:\ProgramData\PVN v2"
```

Then reinstall the latest `PVN-v2-Windows-Setup.exe` as Administrator.

If internet breaks, restart Windows. The script never runs `netsh reset`, disables adapters, or touches non-PVN tunnels. It only removes PVN-owned tunnel names.

VPS-side verification while connected:

```bash
sudo wg show wg-pvn-v2
```

Expected: the connected peer has a recent handshake and transfer counters increasing.
