param(
  [string]$ServiceName = "PVNv2Helper"
)

$ErrorActionPreference = "Stop"

$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if (-not $service) {
  Write-Host "$ServiceName is not installed."
  exit 0
}

if ($service.Status -ne "Stopped") {
  Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
  try {
    $service.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(20))
  } catch {
  }
}

& sc.exe delete $ServiceName | Out-Null
if ($LASTEXITCODE -ne 0) {
  throw "Failed to delete $ServiceName service."
}

Write-Host "$ServiceName removed."
