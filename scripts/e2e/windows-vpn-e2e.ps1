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

$IsAdministrator = Test-IsAdministrator

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$ArtifactDir = Join-Path $RepoRoot "artifacts\e2e"
New-Item -ItemType Directory -Force -Path $ArtifactDir | Out-Null
$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$LogPath = Join-Path $ArtifactDir "windows-vpn-e2e-$Timestamp.log"
$PvnHelperServiceName = "PVNv2Helper"
$PvnHelperServiceDisplayName = "PVN v2 Helper"

function Write-Log {
  param([string]$Message)
  $line = "$(Get-Date -Format o) $Message"
  $line | Tee-Object -FilePath $LogPath -Append
}

function Invoke-Curl4 {
  param([Parameter(Mandatory = $true)] [string]$Url)

  $output = & cmd.exe /d /c "curl.exe -4 --fail --silent --show-error --max-time 15 $Url 2>&1" | Out-String
  $exitCode = $LASTEXITCODE
  $trimmed = $output.Trim()
  if ($exitCode -ne 0) {
    if ($trimmed -match "Could not resolve host|Name or service not known") {
      throw "DNS failure during IPv4 check url=$Url exit=$exitCode detail=$trimmed"
    }
    if ($trimmed -match "timed out|Failed to connect|Could not connect|Connection refused") {
      throw "TCP failure during IPv4 check url=$Url exit=$exitCode detail=$trimmed"
    }
    throw "IPv4 curl failed url=$Url exit=$exitCode detail=$trimmed"
  }
  if ([string]::IsNullOrWhiteSpace($trimmed)) {
    throw "IPv4 curl returned empty response url=$Url"
  }
  return $trimmed
}

function Get-PublicIp {
  return Invoke-Curl4 -Url "https://api.ipify.org"
}

function Test-Internet {
  try {
    $null = Invoke-Curl4 -Url "https://ipv4.icanhazip.com"
    return $true
  } catch {
    Write-Log "internet_check_failed=$($_.Exception.Message)"
    return $false
  }
}

function Write-NetworkSnapshot {
  param([string]$Label)

  try {
    $routes = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction Stop |
      Select-Object ifIndex, InterfaceAlias, NextHop, RouteMetric, ifMetric |
      ConvertTo-Json -Compress
    Write-Log "network_${Label}_default_routes=$routes"
  } catch {
    Write-Log "network_${Label}_default_routes_error=$($_.Exception.Message)"
  }

  try {
    $dns = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop |
      Select-Object InterfaceAlias, ServerAddresses |
      ConvertTo-Json -Compress
    Write-Log "network_${Label}_dns=$dns"
  } catch {
    Write-Log "network_${Label}_dns_error=$($_.Exception.Message)"
  }

  try {
    $adapters = Get-NetAdapter -ErrorAction Stop |
      Where-Object { $_.Status -eq "Up" -or $_.Name -match "PVN|WireGuard|pvn" -or $_.InterfaceDescription -match "WireGuard" } |
      Select-Object Name, InterfaceDescription, Status, ifIndex |
      ConvertTo-Json -Compress
    Write-Log "network_${Label}_adapters=$adapters"
  } catch {
    Write-Log "network_${Label}_adapters_error=$($_.Exception.Message)"
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
    $escapedWg = $wg.Replace('"', '\"')
    $output = & cmd.exe /d /c "`"$escapedWg`" /uninstalltunnelservice $name 2>&1" | Out-String
    $exitCode = $LASTEXITCODE
    Write-Log "cleanup tunnel=$name exit=$exitCode output=$($output.Trim())"
  }
}

function Test-TunnelActive {
  param([string]$Name = "pvn-v2")
  $serviceName = "WireGuardTunnel`$$Name"
  $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
  return ($service -and $service.Status -eq "Running")
}

function Get-PvnHelperService {
  return Get-Service -Name $PvnHelperServiceName -ErrorAction SilentlyContinue
}

function Assert-PvnHelperService {
  $service = Get-PvnHelperService
  if (-not $service) {
    throw "PVN v2 helper service is not installed. Run PVN-v2-Windows-Setup.exe first."
  }
  Write-Log "helper_service_name=$($service.Name) display=$($service.DisplayName) status=$($service.Status)"
  if ($service.Status -ne "Running") {
    try {
      Start-Service -Name $PvnHelperServiceName
      $service.WaitForStatus("Running", [TimeSpan]::FromSeconds(30))
      Write-Log "helper_service_started=$PvnHelperServiceName"
    } catch {
      throw "PVN v2 helper service is installed but did not start: $($_.Exception.Message)"
    }
  }
}

function Wait-PublicIp {
  param(
    [bool]$ShouldEqual,
    [string]$Expected,
    [int]$Seconds = 75
  )
  $deadline = (Get-Date).AddSeconds($Seconds)
  $lastError = ""
  do {
    try {
      $ip = Get-PublicIp
      Write-Log "observed_public_ip=$ip"
      if ($ShouldEqual -and $ip -eq $Expected) {
        return $ip
      }
      if (-not $ShouldEqual -and $ip -ne $Expected) {
        return $ip
      }
    } catch {
      $lastError = $_.Exception.Message
      Write-Log "public_ip_check_failed=$lastError"
    }
    Start-Sleep -Seconds 3
  } while ((Get-Date) -lt $deadline)
  if (-not [string]::IsNullOrWhiteSpace($lastError)) {
    throw "Timed out waiting for public IP condition because IPv4 public IP checks failed. expected=$Expected should_equal=$ShouldEqual last_error=$lastError"
  }
  throw "Timed out waiting for public IP condition. expected=$Expected should_equal=$ShouldEqual last=$ip"
}

function Invoke-PvnService {
  param(
    [ValidateSet("GET", "POST")] [string]$Method,
    [string]$Path,
    [object]$Body = $null
  )
  $headers = @{}
  if (-not ($Method -eq "GET" -and ($Path -eq "/status" -or $Path -eq "/diagnostics"))) {
    $headers.Authorization = "Bearer $script:ServiceToken"
  }
  $uri = "http://127.0.0.1:47621$Path"
  try {
    if ($Method -eq "GET") {
      return Invoke-RestMethod -Uri $uri -Method Get -Headers $headers -TimeoutSec 130
    }
    $json = "{}"
    if ($null -ne $Body) {
      $json = $Body | ConvertTo-Json -Depth 5
    }
    return Invoke-RestMethod -Uri $uri -Method Post -Headers $headers -Body $json -ContentType "application/json" -TimeoutSec 130
  } catch {
    $detail = $_.Exception.Message
    $statusCode = $null
    try {
      if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
        $statusCode = [int]$_.Exception.Response.StatusCode
      }
    } catch {
      $statusCode = $null
    }
    if ($Path -eq "/status" -and $statusCode -eq 401) {
      throw "PVN helper /status returned 401. /status must be unauthenticated."
    }
    if ($Path -eq "/auth-check" -and $statusCode -eq 401) {
      throw "PVN helper auth preflight returned 401. UI and helper service are not using the same token/auth path."
    }
    if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
      $detail = "$detail body=$($_.ErrorDetails.Message)"
    }
    Write-Log "helper_request_failed method=$Method path=$Path error=$detail"
    throw $detail
  }
}

function Connect-Pvn {
  param([string]$ApiUrl)
  $status = Invoke-PvnService -Method POST -Path "/connect" -Body @{ api_url = $ApiUrl }
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
    if (-not $IsAdministrator) {
      throw "Run this E2E test in PowerShell as Administrator when using -InstallerPath."
    }
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
  $health = Invoke-RestMethod -Uri "$($ApiUrl.TrimEnd('/'))/api/health" -TimeoutSec 20
  Write-Log "api_health=$($health.status)"

  Assert-PvnHelperService

  $status = Invoke-PvnService -Method GET -Path "/status"
  Write-Log "unauthenticated_status=$($status.state)"

  $tokenPath = Join-Path $env:ProgramData "PVN v2\helper-token"
  if (-not (Test-Path $tokenPath)) {
    throw "PVN v2 helper service token not found. Run PVN-v2-Windows-Setup.exe first."
  }
  $script:ServiceToken = (Get-Content -LiteralPath $tokenPath -Raw).Trim()
  if ([string]::IsNullOrWhiteSpace($script:ServiceToken)) {
    throw "PVN helper service token is blank."
  }
  $auth = Invoke-PvnService -Method GET -Path "/auth-check"
  Write-Log "connect_auth_preflight=$($auth.ok)"

  if ($IsAdministrator) {
    Remove-OwnedTunnels
  } else {
    Write-Log "direct_wireguard_cleanup=skipped_not_admin"
  }
  $null = Invoke-PvnService -Method POST -Path "/reset" -Body @{}

  $baselineIp = Get-PublicIp
  Write-Log "baseline_public_ip=$baselineIp"
  if ($baselineIp -eq $ExpectedPublicIp) {
    throw "Baseline public IP is already the expected VPN exit IP."
  }
  if (-not (Test-Internet)) {
    throw "Internet check failed before connect."
  }
  Write-NetworkSnapshot -Label "before_connect"

  $connectedIp = Connect-Pvn -ApiUrl $ApiUrl
  Write-NetworkSnapshot -Label "after_connect"
  $disconnectedIp = Disconnect-Pvn
  Write-NetworkSnapshot -Label "after_disconnect"
  $reconnectedIp = Connect-Pvn -ApiUrl $ApiUrl
  Write-NetworkSnapshot -Label "after_reconnect"
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
  Write-NetworkSnapshot -Label "failure"
  Write-Log "FAILED: $($_.Exception.Message)"
  Write-Error $_.Exception.Message
  exit 1
}
