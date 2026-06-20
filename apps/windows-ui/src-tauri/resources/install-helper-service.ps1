param(
  [Parameter(Mandatory = $true)]
  [string]$ServiceExe,
  [string]$ServicePayload = "",
  [string]$ServiceName = "PVNv2Helper",
  [string]$DisplayName = "PVN v2 Helper",
  [switch]$ResetToken
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $ServiceExe)) {
  throw "PVN v2 helper service executable not found: $ServiceExe"
}
if (-not [string]::IsNullOrWhiteSpace($ServicePayload) -and -not (Test-Path -LiteralPath $ServicePayload)) {
  throw "PVN v2 helper service payload not found: $ServicePayload"
}

$programData = Join-Path $env:ProgramData "PVN v2"
Write-Host "step=ensure_programdata path=$programData"
New-Item -ItemType Directory -Force -Path $programData | Out-Null

function Set-PvnHelperAcl {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Path,
    [Parameter(Mandatory = $true)]
    [bool]$IsDirectory
  )

  & icacls.exe $Path /inheritance:r | Out-Null
  if ($LASTEXITCODE -ne 0) {
    throw "Failed to disable inheritance on $Path."
  }

  $grants = if ($IsDirectory) {
    @(
      "*S-1-5-18:(OI)(CI)F",
      "*S-1-5-32-544:(OI)(CI)F",
      "*S-1-5-32-545:(OI)(CI)RX"
    )
  } else {
    @(
      "*S-1-5-18:F",
      "*S-1-5-32-544:F",
      "*S-1-5-32-545:R"
    )
  }

  foreach ($grant in $grants) {
    & icacls.exe $Path /grant:r $grant | Out-Null
    if ($LASTEXITCODE -ne 0) {
      throw "Failed to apply ACL grant $grant on $Path."
    }
  }
}

Set-PvnHelperAcl -Path $programData -IsDirectory $true

$tokenPath = Join-Path $programData "helper-token"
Write-Host "step=ensure_token path=$tokenPath reset=$ResetToken"
if ($ResetToken -and (Test-Path -LiteralPath $tokenPath)) {
  Remove-Item -LiteralPath $tokenPath -Force
}
if (-not (Test-Path -LiteralPath $tokenPath)) {
  $bytes = New-Object byte[] 32
  $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
  $rng.GetBytes($bytes)
  [Convert]::ToBase64String($bytes) | Set-Content -NoNewline -Encoding ASCII -Path $tokenPath
}
Set-PvnHelperAcl -Path $tokenPath -IsDirectory $false

$binaryPath = "`"$ServiceExe`" --service"
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
  Write-Host "step=stop_existing_service status=$($existing.Status)"
  if ($existing.Status -ne "Stopped") {
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    $existing.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(20))
  }
}

if (-not [string]::IsNullOrWhiteSpace($ServicePayload)) {
  Write-Host "step=copy_service_payload source=$ServicePayload destination=$ServiceExe"
  Copy-Item -LiteralPath $ServicePayload -Destination $ServiceExe -Force
}

if ($existing) {
  Write-Host "step=update_service_registration service=$ServiceName"
  $serviceNameForCmd = $ServiceName.Replace('"', '\"')
  $serviceExeForCmd = $ServiceExe.Replace('"', '\"')
  $cmd = 'sc.exe config "' + $serviceNameForCmd + '" binPath= "\"' + $serviceExeForCmd + '\" --service" start= auto'
  $scOutput = & cmd.exe /d /c $cmd 2>&1
  if ($LASTEXITCODE -ne 0) {
    throw "Failed to update $ServiceName service registration: $scOutput"
  }
} else {
  Write-Host "step=create_service service=$ServiceName"
  New-Service -Name $ServiceName -BinaryPathName $binaryPath -DisplayName $DisplayName -StartupType Automatic -Description "PVN v2 local VPN helper service" | Out-Null
}

Write-Host "step=start_service service=$ServiceName"
Start-Service -Name $ServiceName
$service = Get-Service -Name $ServiceName
$service.WaitForStatus("Running", [TimeSpan]::FromSeconds(30))

Write-Host "step=verify_status_endpoint"
$statusOk = $false
for ($i = 0; $i -lt 20; $i++) {
  try {
    $response = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:47621/status" -TimeoutSec 3
    if ($response.StatusCode -eq 200) {
      $statusOk = $true
      break
    }
  } catch {
    Start-Sleep -Milliseconds 500
  }
}
if (-not $statusOk) {
  throw "PVN helper service started, but /status did not return 200."
}

Write-Host "$ServiceName installed and running."
