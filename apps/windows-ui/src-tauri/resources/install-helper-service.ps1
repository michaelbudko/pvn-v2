param(
  [Parameter(Mandatory = $true)]
  [string]$ServiceExe,
  [string]$ServiceName = "PVNv2Helper",
  [string]$DisplayName = "PVN v2 Helper"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $ServiceExe)) {
  throw "PVN v2 helper service executable not found: $ServiceExe"
}

$programData = Join-Path $env:ProgramData "PVNv2"
New-Item -ItemType Directory -Force -Path $programData | Out-Null

$tokenPath = Join-Path $programData "service-token.txt"
if (-not (Test-Path -LiteralPath $tokenPath)) {
  $bytes = New-Object byte[] 32
  $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
  $rng.GetBytes($bytes)
  [Convert]::ToBase64String($bytes) | Set-Content -NoNewline -Encoding ASCII -Path $tokenPath
}

& icacls $programData /grant "Users:(OI)(CI)RX" /T /C | Out-Null

$binaryPath = "`"$ServiceExe`" --service"
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
  if ($existing.Status -ne "Stopped") {
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    $existing.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(20))
  }
  & sc.exe config $ServiceName binPath= $binaryPath start= auto DisplayName= $DisplayName | Out-Null
  if ($LASTEXITCODE -ne 0) {
    throw "Failed to update $ServiceName service registration."
  }
} else {
  New-Service -Name $ServiceName -BinaryPathName $binaryPath -DisplayName $DisplayName -StartupType Automatic -Description "PVN v2 local VPN helper service" | Out-Null
}

Start-Service -Name $ServiceName
$service = Get-Service -Name $ServiceName
$service.WaitForStatus("Running", [TimeSpan]::FromSeconds(30))

Write-Host "$ServiceName installed and running."
