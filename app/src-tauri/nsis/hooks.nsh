; PassBook - NSIS installer hooks.
;
; Tauri includes this file into the installer it generates and calls whichever
; of these macros exist. The job here is one thing: the app carries its own
; copy of the PassBook commands, and this is what makes them reachable from a
; terminal as well as from the window.
;
; Neither hook is allowed to fail the install. A PATH entry is a convenience;
; an installer that aborts three quarters of the way through because it could
; not add one is not.

!macro NSIS_HOOK_POSTINSTALL
  DetailPrint "Adding the PassBook commands to PATH"
  nsExec::ExecToLog '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$INSTDIR\nsis\path.ps1" -Action add -Directory "$INSTDIR\bin"'
  Pop $0
  DetailPrint "PATH: $0"
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  DetailPrint "Removing the PassBook commands from PATH"
  nsExec::ExecToLog '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$INSTDIR\nsis\path.ps1" -Action remove -Directory "$INSTDIR\bin"'
  Pop $0
  DetailPrint "PATH: $0"
!macroend
