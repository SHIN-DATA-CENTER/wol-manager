; Closing a running WoL Manager before its files are replaced or removed.
;
; The GUI owns the named mutex MUTEX_NAME and waits on the auto-reset event QUIT_EVENT. Setting
; that event makes it save its state and exit, even when it is hidden in the notification area
; (the "close to tray" setting is ignored for this request). Both names live in the per-session
; Local\ namespace, so only the GUI of the current session can be reached this way. Copies that
; run in other sessions, and running wolm.exe processes, are found afterwards by opening the
; executables for writing, which fails while an image is mapped by a process.
;
; In:   $CheckFiles  1 = also test $INSTDIR\bin\wolm.exe and $INSTDIR\wol-manager.exe.
;                    Use 0 in a non-elevated process that cannot write $INSTDIR anyway
;                    (the elevated child repeats the full check).
; Out:  returns when nothing is running. Otherwise asks the user (silent: no prompt) and on
;       failure sets the exit code (1 = user cancelled, 3 = still running / in use) and aborts.
; Uses: $0 $1 $2 $3 $R9 (callers do not keep values in them across the call).

!define /ifndef SYNCHRONIZE 0x00100000
!define /ifndef EVENT_MODIFY_STATE 0x0002
!define /ifndef ERROR_ACCESS_DENIED 5

; Sets $FileInUse to PATH when PATH exists and cannot be opened for writing.
!macro _WOL_PROBE_FILE_IN_USE PATH
  ${If} ${FileExists} "${PATH}"
    ClearErrors
    FileOpen $0 "${PATH}" a
    ${If} ${Errors}
      StrCpy $FileInUse "${PATH}"
    ${Else}
      FileClose $0
    ${EndIf}
  ${EndIf}
!macroend

!macro WOL_ENSURE_APP_CLOSED_FUNCTION UN
Function ${UN}EnsureAppClosed
  StrCpy $R9 0                              ; 1 once the user agreed to close the GUI

  check_gui:
  ; OpenMutexW succeeds while the GUI runs; ERROR_ACCESS_DENIED also means "exists".
  System::Call 'kernel32::OpenMutexW(i ${SYNCHRONIZE}, i 0, w "${MUTEX_NAME}") p.r0 ?e'
  Pop $1
  ${If} $0 P<> 0
    System::Call 'kernel32::CloseHandle(p r0)'
  ${ElseIf} $1 <> ${ERROR_ACCESS_DENIED}
    Goto check_files
  ${EndIf}

  ${If} $R9 == 0
    MessageBox MB_OKCANCEL|MB_ICONINFORMATION "$(MSG_APP_RUNNING)" /SD IDOK IDOK request_quit
    SetErrorLevel 1
    Abort
  ${EndIf}

  request_quit:
  StrCpy $R9 1
  DetailPrint "$(DETAIL_CLOSING_APP)"
  System::Call 'kernel32::OpenEventW(i ${EVENT_MODIFY_STATE}, i 0, w "${QUIT_EVENT}") p.r2'
  ${If} $2 P<> 0
    System::Call 'kernel32::SetEvent(p r2)'
    System::Call 'kernel32::CloseHandle(p r2)'
  ${EndIf}
  ; Wait up to 10 seconds (40 x 250 ms) for the mutex to disappear.
  StrCpy $3 0
  ${Do}
    Sleep 250
    IntOp $3 $3 + 1
    System::Call 'kernel32::OpenMutexW(i ${SYNCHRONIZE}, i 0, w "${MUTEX_NAME}") p.r0 ?e'
    Pop $1
    ${If} $0 P<> 0
      System::Call 'kernel32::CloseHandle(p r0)'
    ${ElseIf} $1 <> ${ERROR_ACCESS_DENIED}
      Goto check_files
    ${EndIf}
  ${LoopUntil} $3 >= 40
  MessageBox MB_RETRYCANCEL|MB_ICONEXCLAMATION "$(MSG_APP_NOT_CLOSED)" /SD IDCANCEL IDRETRY request_quit
  SetErrorLevel 3
  Abort

  check_files:
  ${If} $CheckFiles == 1
    ; Right after a quit request the image may stay mapped for a moment after the mutex is
    ; gone (the GUI flushes its settings), so allow up to 5 seconds before asking.
    StrCpy $3 0
    ${Do}
      StrCpy $FileInUse ""
      !insertmacro _WOL_PROBE_FILE_IN_USE "$INSTDIR\${CLI_SUBDIR}\${CLI_EXE}"
      !insertmacro _WOL_PROBE_FILE_IN_USE "$INSTDIR\${GUI_EXE}"
      ${If} $FileInUse == ""
      ${OrIf} $R9 != 1
      ${OrIf} $3 >= 20
        ${ExitDo}
      ${EndIf}
      Sleep 250
      IntOp $3 $3 + 1
    ${Loop}
    ${If} $FileInUse != ""
      MessageBox MB_RETRYCANCEL|MB_ICONEXCLAMATION "$(MSG_FILE_IN_USE)" /SD IDCANCEL IDRETRY check_gui
      SetErrorLevel 3
      Abort
    ${EndIf}
  ${EndIf}
FunctionEnd
!macroend

!insertmacro WOL_ENSURE_APP_CLOSED_FUNCTION ""
!insertmacro WOL_ENSURE_APP_CLOSED_FUNCTION "un."
