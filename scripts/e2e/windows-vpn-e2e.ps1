param(
  [string]$InstallerPath = "",
  [string]$ExpectedPublicIp = "45.63.22.174"
)

$ErrorActionPreference = "Stop"

function Test-IsAdministrator {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdministrator)) {
  Write-Error "Run this E2E test in PowerShell as Administrator."
  exit 1
}

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$ArtifactDir = Join-Path $RepoRoot "artifacts\e2e"
New-Item -ItemType Directory -Force -Path $ArtifactDir | Out-Null
$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$LogPath = Join-Path $ArtifactDir "windows-vpn-e2e-$Timestamp.log"

function Write-Log {
  param([string]$Message)
  $line = "$(Get-Date -Format o) $Message"
  $line | Tee-Object -FilePath $LogPath -Append
}

function Get-RequiredEnv {
  param([string]$Name)
  $value = [Environment]::GetEnvironmentVariable($Name)
  if ([string]::IsNullOrWhiteSpace($value)) {
    throw "$Name is required"
  }
  return $value
}

function Get-PublicIp {
  return (Invoke-RestMethod -Uri "https://api.ipify.org" -TimeoutSec 15).Trim()
}

function Test-Internet {
  try {
    $null = Invoke-WebRequest -Uri "https://example.com" -TimeoutSec 15 -UseBasicParsing
    return $true
  } catch {
    return $false
  }
}

function Get-WireGuardExe {
  $candidates = @(
    "$env:ProgramFiles\WireGuard\wireguard.exe",
    "${env:ProgramFiles(x86)}\WireGuard\wireguard.exe"
  )
  foreach ($candidate in $candidates) {
    if ($candidate -and (Test-Path $candidate)) {
      return $candidate
    }
  }
  $cmd = Get-Command wireguard.exe -ErrorAction SilentlyContinue
  if ($cmd) {
    return $cmd.Source
  }
  return $null
}

function Remove-OwnedTunnels {
  $wg = Get-WireGuardExe
  if (-not $wg) {
    Write-Log "WireGuard executable not found during pre-cleanup."
    return
  }
  foreach ($name in @("pvn-v2")) {
    $output = & $wg /uninstalltunnelservice $name 2>&1 | Out-String
    Write-Log "cleanup tunnel=$name exit=$LASTEXITCODE output=$($output.Trim())"
  }
}

function Test-TunnelActive {
  param([string]$Name = "pvn-v2")
  $serviceName = "WireGuardTunnel`$$Name"
  $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
  return ($service -and $service.Status -eq "Running")
}

function Wait-PublicIp {
  param(
    [bool]$ShouldEqual,
    [string]$Expected,
    [int]$Seconds = 75
  )
  $deadline = (Get-Date).AddSeconds($Seconds)
  do {
    $ip = Get-PublicIp
    Write-Log "observed_public_ip=$ip"
    if ($ShouldEqual -and $ip -eq $Expected) {
      return $ip
    }
    if (-not $ShouldEqual -and $ip -ne $Expected) {
      return $ip
    }
    Start-Sleep -Seconds 3
  } while ((Get-Date) -lt $deadline)
  throw "Timed out waiting for public IP condition. expected=$Expected should_equal=$ShouldEqual last=$ip"
}

function Invoke-PvnService {
  param(
    [ValidateSet("GET", "POST")] [string]$Method,
    [string]$Path,
    [object]$Body = $null
  )
  $headers = @{ Authorization = "Bearer $script:ServiceToken" }
  $uri = "http://127.0.0.1:47621$Path"
  if ($Method -eq "GET") {
    return Invoke-RestMethod -Uri $uri -Method Get -Headers $headers -TimeoutSec 130
  }
  $json = "{}"
  if ($null -ne $Body) {
    $json = $Body | ConvertTo-Json -Depth 5
  }
  return Invoke-RestMethod -Uri $uri -Method Post -Headers $headers -Body $json -ContentType "application/json" -TimeoutSec 130
}

function Login-Backend {
  param([string]$ApiUrl, [string]$Email, [string]$Password)
  $body = @{ email = $Email; password = $Password } | ConvertTo-Json
  return Invoke-RestMethod -Uri "$($ApiUrl.TrimEnd('/'))/api/auth/login" -Method Post -Body $body -ContentType "application/json" -TimeoutSec 20
}

function Connect-Pvn {
  param([string]$ApiUrl, [string]$BackendToken)
  $status = Invoke-PvnService -Method POST -Path "/connect" -Body @{ api_url = $ApiUrl; backend_token = $BackendToken }
  Write-Log "connect_status=$($status.state) verification=$($status.last_verification)"
  $connectedIp = Wait-PublicIp -ShouldEqual $true -Expected $ExpectedPublicIp
  if (-not (Test-TunnelActive)) {
    throw "PVN tunnel service is not active after connect."
  }
  if (-not (Test-Internet)) {
    throw "Internet check failed after connect."
  }
  return $connectedIp
}

function Disconnect-Pvn {
  $status = Invoke-PvnService -Method POST -Path "/disconnect" -Body @{}
  Write-Log "disconnect_status=$($status.state) verification=$($status.last_verification)"
  $disconnectedIp = Wait-PublicIp -ShouldEqual $false -Expected $ExpectedPublicIp
  if (Test-TunnelActive) {
    throw "PVN tunnel service is still active after disconnect."
  }
  if (-not (Test-Internet)) {
    throw "Internet check failed after disconnect."
  }
  return $disconnectedIp
}

try {
  Write-Log "PVN v2 Windows E2E started."

  if ($InstallerPath) {
    if (-not (Test-Path $InstallerPath)) {
      throw "Installer not found: $InstallerPath"
    }
    Write-Log "Installing PVN v2 from $InstallerPath"
    $process = Start-Process -FilePath $InstallerPath -ArgumentList "/S" -Wait -PassThru
    Write-Log "installer_exit=$($process.ExitCode)"
    if ($process.ExitCode -ne 0) {
      throw "Installer failed with exit code $($process.ExitCode)"
    }
  }

  $ApiUrl = [Environment]::GetEnvironmentVariable("PVN_V2_E2E_API_URL")
  if ([string]::IsNullOrWhiteSpace($ApiUrl)) {
    $ApiUrl = "https://api-v2.45.63.22.174.sslip.io"
  }
  $Email = Get-RequiredEnv "PVN_V2_E2E_EMAIL"
  $Password = Get-RequiredEnv "PVN_V2_E2E_PASSWORD"

  $health = Invoke-RestMethod -Uri "$($ApiUrl.TrimEnd('/'))/api/health" -TimeoutSec 20
  Write-Log "api_health=$($health.status)"

  $tokenPath = Join-Path $env:ProgramData "PVNv2\service-token.txt"
  if (-not (Test-Path $tokenPath)) {
    throw "PVN helper service token not found. Install PVN v2 first."
  }
  $script:ServiceToken = (Get-Content -LiteralPath $tokenPath -Raw).Trim()
  if ([string]::IsNullOrWhiteSpace($script:ServiceToken)) {
    throw "PVN helper service token is blank."
  }

  Remove-OwnedTunnels
  $null = Invoke-PvnService -Method POST -Path "/reset" -Body @{}

  $baselineIp = Get-PublicIp
  Write-Log "baseline_public_ip=$baselineIp"
  if ($baselineIp -eq $ExpectedPublicIp) {
    throw "Baseline public IP is already the expected VPN exit IP."
  }
  if (-not (Test-Internet)) {
    throw "Internet check failed before connect."
  }

  $login = Login-Backend -ApiUrl $ApiUrl -Email $Email -Password $Password
  if ([string]::IsNullOrWhiteSpace($login.token)) {
    throw "Backend login returned blank token."
  }

  $connectedIp = Connect-Pvn -ApiUrl $ApiUrl -BackendToken $login.token
  $disconnectedIp = Disconnect-Pvn
  $reconnectedIp = Connect-Pvn -ApiUrl $ApiUrl -BackendToken $login.token
  $finalIp = Disconnect-Pvn

  $summary = [ordered]@{
    ran = $true
    baseline_public_ip = $baselineIp
    connected_public_ip = $connectedIp
    disconnected_public_ip = $disconnectedIp
    reconnected_public_ip = $reconnectedIp
    final_public_ip = $finalIp
    expected_ip_reached = ($connectedIp -eq $ExpectedPublicIp -and $reconnectedIp -eq $ExpectedPublicIp)
    reconnect_without_manual_cleanup = $true
    internet_works_after_disconnect = (Test-Internet)
    log = $LogPath
  }
  Write-Log "summary=$($summary | ConvertTo-Json -Compress)"
  $summary | ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $ArtifactDir "windows-vpn-e2e-$Timestamp.json")
  Write-Host "PVN v2 E2E passed. Log: $LogPath"
} catch {
  Write-Log "FAILED: $($_.Exception.Message)"
  Write-Error $_.Exception.Message
  exit 1
}
