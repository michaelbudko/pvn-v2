!macro NSIS_HOOK_PREINSTALL
  Call PVN_EnsureWireGuard
!macroend

!macro NSIS_HOOK_POSTINSTALL
  Call PVN_InstallHelperService
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  Call un.PVN_UninstallHelperService
!macroend

Function PVN_IsWireGuardInstalled
  IfFileExists "$PROGRAMFILES64\WireGuard\wireguard.exe" 0 +3
    Push "1"
    Return

  IfFileExists "$PROGRAMFILES32\WireGuard\wireguard.exe" 0 +3
    Push "1"
    Return

  IfFileExists "$PROGRAMFILES\WireGuard\wireguard.exe" 0 +3
    Push "1"
    Return

  nsExec::ExecToStack 'where wireguard.exe'
  Pop $0
  Pop $1
  StrCmp $0 "0" 0 +3
    Push "1"
    Return

  Push "0"
FunctionEnd

Function PVN_EnsureWireGuard
  DetailPrint "Checking for official WireGuard for Windows..."
  Call PVN_IsWireGuardInstalled
  Pop $0
  StrCmp $0 "1" wireguard_ready

  DetailPrint "WireGuard not found. Installing official WireGuard for Windows with winget..."
  nsExec::ExecToLog 'winget install --id WireGuard.WireGuard -e --source winget --silent --accept-package-agreements --accept-source-agreements'
  Pop $0
  DetailPrint "WireGuard winget install exit code: $0"

  Call PVN_IsWireGuardInstalled
  Pop $1
  StrCmp $1 "1" wireguard_ready

  MessageBox MB_ICONSTOP|MB_OK "WireGuard could not be installed automatically. Install WireGuard from the official website, restart Windows, then install PVN again."
  Abort "WireGuard dependency is required."

wireguard_ready:
  DetailPrint "WireGuard is installed. Continuing PVN installation."
FunctionEnd

Function PVN_InstallHelperService
  DetailPrint "Installing PVN helper service..."
  IfFileExists "$INSTDIR\resources\pvn-v2-service.exe" service_exists
    MessageBox MB_ICONSTOP|MB_OK "PVN helper service executable is missing. Reinstall PVN."
    Abort "PVN helper service is required."

service_exists:
  nsExec::ExecToLog 'powershell -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\resources\install-helper-service.ps1" -ServiceExe "$INSTDIR\resources\pvn-v2-service.exe"'
  Pop $0
  DetailPrint "PVN helper service install exit code: $0"
  StrCmp $0 "0" 0 service_failed
  Return

service_failed:
  MessageBox MB_ICONSTOP|MB_OK "PVN helper service could not be installed. Reinstall PVN as Administrator."
  Abort "PVN helper service install failed."
FunctionEnd

Function un.PVN_UninstallHelperService
  DetailPrint "Stopping PVN helper service..."
  IfFileExists "$INSTDIR\resources\uninstall-helper-service.ps1" 0 +3
    nsExec::ExecToLog 'powershell -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\resources\uninstall-helper-service.ps1"'
    Pop $0
  nsExec::ExecToLog 'sc.exe delete PVNv2Helper'
  Pop $0
FunctionEnd
