; WebView2 Fixed Version >= 120 runs renderers in AppContainer on Windows 10.
; Grant read/execute to the two application-package SIDs only on the bundled
; runtime. Never grant access to the app data directory or vault files.
; https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/distribution

!macro LexFlowGrantWebView2Acl SID
  ClearErrors
  ExecWait '"$SYSDIR\icacls.exe" "$INSTDIR\binaries\windows-webview2" /grant "*${SID}:(OI)(CI)(RX)"' $0
  ${If} ${Errors}
    MessageBox MB_ICONSTOP|MB_OK "Impossibile configurare i permessi di WebView2. Installazione interrotta." /SD IDOK
    SetErrorLevel 1
    Abort
  ${EndIf}
  ${If} $0 != 0
    MessageBox MB_ICONSTOP|MB_OK "Configurazione dei permessi WebView2 non riuscita (codice $0). Installazione interrotta." /SD IDOK
    SetErrorLevel 1
    Abort
  ${EndIf}
!macroend

!macro NSIS_HOOK_POSTINSTALL
  Push $0
  !insertmacro LexFlowGrantWebView2Acl "S-1-15-2-2"
  !insertmacro LexFlowGrantWebView2Acl "S-1-15-2-1"
  Pop $0
!macroend
