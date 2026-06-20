param(
  [Parameter(Mandatory = $true)]
  [string]$ServiceExe,
  [string]$ServicePayload = "",
  [string]$ServiceName = "PVNv2Helper",
  [string]$DisplayName = "PVN v2 Helper"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $ServiceExe)) {
  throw "PVN v2 helper service executable not found: $ServiceExe"
}
if (-not [string]::IsNullOrWhiteSpace($ServicePayload) -and -not (Test-Path -LiteralPath $ServicePayload)) {
  throw "PVN v2 helper service payload not found: $ServicePayload"
}

$programData = Join-Path $env:ProgramData "PVN v2"
New-Item -ItemType Directory -Force -Path $programData | Out-Null

function Set-PvnHelperAcl {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Path,
    [Parameter(Mandatory = $true)]
    [bool]$IsDirectory
  )

  $acl = Get-Acl -LiteralPath $Path
  $acl.SetAccessRuleProtection($true, $false)
  foreach ($existingRule in @($acl.Access)) {
    $acl.RemoveAccessRuleAll($existingRule)
  }

  foreach ($identity in @("NT AUTHORITY\SYSTEM", "BUILTIN\Administrators")) {
    $rule = if ($IsDirectory) {
      New-Object Security.AccessControl.FileSystemAccessRule($identity, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    } else {
      New-Object Security.AccessControl.FileSystemAccessRule($identity, "FullControl", "None", "None", "Allow")
    }
    $acl.AddAccessRule($rule) | Out-Null
  }

  $usersRule = if ($IsDirectory) {
    New-Object Security.AccessControl.FileSystemAccessRule("BUILTIN\Users", "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")
  } else {
    New-Object Security.AccessControl.FileSystemAccessRule("BUILTIN\Users", "Read", "None", "None", "Allow")
  }
  $acl.AddAccessRule($usersRule) | Out-Null

  Set-Acl -LiteralPath $Path -AclObject $acl
}

Set-PvnHelperAcl -Path $programData -IsDirectory $true

$tokenPath = Join-Path $programData "helper-token"
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
  if ($existing.Status -ne "Stopped") {
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    $existing.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(20))
  }
}

if (-not [string]::IsNullOrWhiteSpace($ServicePayload)) {
  Copy-Item -LiteralPath $ServicePayload -Destination $ServiceExe -Force
}

if ($existing) {
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
