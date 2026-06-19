param(
  [Parameter(Mandatory = $true)]
  [string[]]$Paths
)

$ErrorActionPreference = "Stop"

$certBase64 = [Environment]::GetEnvironmentVariable("WINDOWS_CODESIGN_CERT_BASE64")
$certPassword = [Environment]::GetEnvironmentVariable("WINDOWS_CODESIGN_CERT_PASSWORD")
$timestampUrl = [Environment]::GetEnvironmentVariable("WINDOWS_CODESIGN_TIMESTAMP_URL")
if ([string]::IsNullOrWhiteSpace($timestampUrl)) {
  $timestampUrl = "http://timestamp.digicert.com"
}

if ([string]::IsNullOrWhiteSpace($certBase64) -or [string]::IsNullOrWhiteSpace($certPassword)) {
  Write-Host "Code signing skipped: signing secrets not configured."
  exit 0
}

function Get-SignTool {
  $cmd = Get-Command signtool.exe -ErrorAction SilentlyContinue
  if ($cmd) {
    return $cmd.Source
  }
  $kits = "${env:ProgramFiles(x86)}\Windows Kits\10\bin"
  if (Test-Path $kits) {
    $candidate = Get-ChildItem -Path $kits -Recurse -Filter signtool.exe |
      Where-Object { $_.FullName -match "\\x64\\signtool.exe$" } |
      Sort-Object FullName -Descending |
      Select-Object -First 1
    if ($candidate) {
      return $candidate.FullName
    }
  }
  throw "signtool.exe not found."
}

$signtool = Get-SignTool
$certPath = Join-Path $env:RUNNER_TEMP "pvn-v2-codesign.pfx"
if ([string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) {
  $certPath = Join-Path $env:TEMP "pvn-v2-codesign.pfx"
}
[IO.File]::WriteAllBytes($certPath, [Convert]::FromBase64String($certBase64))

try {
  foreach ($path in $Paths) {
    if (-not (Test-Path $path)) {
      throw "Signing target not found: $path"
    }
    Write-Host "Signing $path"
    & $signtool sign /fd SHA256 /td SHA256 /tr $timestampUrl /f $certPath /p $certPassword $path
    if ($LASTEXITCODE -ne 0) {
      throw "signtool sign failed for $path"
    }
    & $signtool verify /pa /v $path
    if ($LASTEXITCODE -ne 0) {
      throw "signtool verify failed for $path"
    }
  }
  Write-Host "Code signing completed and verified."
} finally {
  Remove-Item -LiteralPath $certPath -Force -ErrorAction SilentlyContinue
}
