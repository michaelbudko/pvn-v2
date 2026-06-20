# Windows Releases

The release workflow is named `PVN v2 Windows Client Release`.

Final installer filename:

```text
PVN-v2-Windows-Setup.exe
```

Latest release URL:

```text
https://github.com/michaelbudko/pvn-v2/releases/latest/download/PVN-v2-Windows-Setup.exe
```

Code signing is supported but not faked. If signing secrets are absent, the workflow prints:

```text
Code signing skipped: signing secrets not configured.
```

Required GitHub Secrets for signing:

- `WINDOWS_CODESIGN_CERT_BASE64`: base64-encoded `.pfx`
- `WINDOWS_CODESIGN_CERT_PASSWORD`: `.pfx` password
- `WINDOWS_CODESIGN_TIMESTAMP_URL`: optional, defaults to `http://timestamp.digicert.com`

The workflow signs and verifies:

- helper service executable
- main PVN v2 executable
- NSIS installer

Canonical Windows helper service:

- service name: `PVNv2Helper`
- display name: `PVN v2 Helper`
- binary: installed under the PVN v2 app `resources` directory
- helper token: `C:\ProgramData\PVN v2\helper-token`
- `/status` and `/diagnostics` are read-only and unauthenticated
- `/connect`, `/disconnect`, and `/reset` require the helper token

After installing PVN v2, this command should show the helper service:

```powershell
Get-Service | Where-Object { $_.Name -match "pvn|vpn" -or $_.DisplayName -match "pvn|vpn" }
```

Local verification:

```powershell
Get-AuthenticodeSignature .\PVN-v2-Windows-Setup.exe | Format-List
```

WireGuard dependency behavior:

- PVN v2 uses official WireGuard for Windows tunnel-service commands.
- The installer checks for official WireGuard.
- If missing, the installer tries `winget install --id WireGuard.WireGuard -e --source winget`.
- PVN v2 never opens the WireGuard GUI.
- The helper service manages only PVN-owned tunnel `pvn-v2`.
