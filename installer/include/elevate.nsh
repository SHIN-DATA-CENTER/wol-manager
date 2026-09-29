; Elevation for "All users" (installer and uninstaller).
;
; The installer always starts with RequestExecutionLevel user. For "All users" a non-elevated
; installer runs an elevated, silent copy of itself (/S /AllUsers /ElevatedChild) through the
; "runas" verb, waits for it and checks the result. This keeps "Just me" installs unelevated,
; which matters with Windows 11 Administrator Protection (an elevated process runs as a
; separate, hidden account with its own profile, HKCU and PATH).
;
; The child is started with ShellExecuteExW through the stock System plug-in, not with
; ExecShellWait, because its exit code must be passed on: 3 (WoL Manager running or a file in
; use, e.g. in another session) must stay 3 for a script that runs "setup /S /AllUsers" from a
; non-elevated shell. The registry check below stays as a second test.
;
; Must be included after the sections: it uses ${SecPath} and ${SecDesktop}.

!define /ifndef SEE_MASK_NOCLOSEPROCESS 0x00000040
!define /ifndef SEE_MASK_NOASYNC 0x00000100
!define /ifndef SEE_MASK_FLAG_NO_UI 0x00000400
!define /ifndef ERROR_CANCELLED 1223
!define /math _WOL_SEI_MASK0 ${SEE_MASK_NOCLOSEPROCESS} | ${SEE_MASK_NOASYNC}
!define /math _WOL_SEI_MASK ${_WOL_SEI_MASK0} | ${SEE_MASK_FLAG_NO_UI}
!undef _WOL_SEI_MASK0
; SHELLEXECUTEINFOW below is laid out for 32-bit pointers (the x86-unicode installer stub).
!if ${NSIS_PTR_SIZE} != 4
  !error "elevate.nsh: SHELLEXECUTEINFOW is laid out for the 32-bit (x86-unicode) stub only"
!endif

; Installer: called from SecProgram when $Mode == AllUsers and $Elevated != 1.
; Sets $Delegated = 1 on success. Otherwise aborts with exit code 5 (UAC declined), 3 (the child
; found WoL Manager running or a file in use) or 2 (any other failure).
; Uses $R0-$R8 (and EnsureAppClosed's registers on a retry).
Function DelegateToElevatedChild
  StrCpy $R0 ""
  ${IfNot} ${SectionIsSelected} ${SecPath}
    StrCpy $R0 "$R0 /NoPath"
  ${EndIf}
  ${If} ${SectionIsSelected} ${SecDesktop}
    StrCpy $R0 "$R0 /DesktopShortcut"
  ${EndIf}
  ${If} $OptOutsidePF == 1
    StrCpy $R0 "$R0 /AllowOutsideProgramFiles"
  ${EndIf}
  ; /D= must be the last argument and must not be quoted, even with spaces.
  StrCpy $R0 "/S /AllUsers /ElevatedChild$R0 /D=$INSTDIR"

  ; A reinstall of the same version leaves DisplayVersion and InstallLocation unchanged, but
  ; the child always rewrites the uninstaller: its time tells whether the child got that far.
  ClearErrors
  GetFileTime "$INSTDIR\${UNINSTALLER_EXE}" $R1 $R2
  ${If} ${Errors}
    StrCpy $R1 ""
    StrCpy $R2 ""
  ${EndIf}

  run_child:
  DetailPrint "$(DETAIL_ELEVATING)"
  ; The strings live in buffers owned by this function (freed below), so that the pointers in
  ; SHELLEXECUTEINFOW stay valid during the call. They are passed as register sources, never
  ; spliced into the call text, where quote characters would end them early.
  StrCpy $R3 "runas"
  StrCpy $R4 $EXEPATH
  System::Call '*(&w6 R3) p .R3'
  System::Call '*(&w${NSIS_MAX_STRLEN} R4) p .R4'
  System::Call '*(&w${NSIS_MAX_STRLEN} R0) p .R5'
  ; SHELLEXECUTEINFOW: cbSize, fMask, hwnd, lpVerb, lpFile, lpParameters, lpDirectory, nShow,
  ; hInstApp, lpIDList, lpClass, hkeyClass, dwHotKey, hIcon, hProcess (offset 56).
  System::Call '*(&l4, i ${_WOL_SEI_MASK}, p $HWNDPARENT, p R3, p R4, p R5, p 0, i ${SW_SHOWNORMAL}, p 0, p 0, p 0, p 0, i 0, p 0, p 0) p .R6'
  System::Call 'shell32::ShellExecuteExW(p R6) i .R7 ?e'
  Pop $R8                                   ; GetLastError()
  System::Call '*$R6(&v56, p .s)'           ; hProcess -> stack
  System::Free $R6
  Pop $R6                                   ; hProcess
  System::Free $R3
  System::Free $R4
  System::Free $R5

  ${If} $R7 == 0
    ${If} $R8 == ${ERROR_CANCELLED}
      ; The UAC prompt was declined.
      MessageBox MB_RETRYCANCEL|MB_ICONEXCLAMATION "$(MSG_UAC_DENIED)" /SD IDCANCEL IDRETRY run_child
      SetErrorLevel 5
      Abort "$(MSG_UAC_DENIED_SHORT)"
    ${EndIf}
    StrCpy $ChildRc $R8
    DetailPrint "$(DETAIL_CHILD_START_FAILED)"
    Goto child_failed
  ${EndIf}
  ${If} $R6 P= 0
    ; No process handle: the child cannot be waited for.
    StrCpy $ChildRc "?"
    DetailPrint "$(DETAIL_CHILD_START_FAILED)"
    Goto child_failed
  ${EndIf}

  System::Call 'kernel32::WaitForSingleObject(p R6, i -1) i'
  System::Call 'kernel32::GetExitCodeProcess(p R6, *i .s) i .R7'
  Pop $ChildRc
  System::Call 'kernel32::CloseHandle(p R6)'
  ${If} $R7 == 0
    StrCpy $ChildRc "?"
  ${EndIf}
  DetailPrint "$(DETAIL_CHILD_EXIT)"

  ${If} $ChildRc == 3
    ; EnsureAppClosed in the child: WoL Manager did not close, or a file is in use (a copy in
    ; another session, or a running wolm command). Offer to try again, like a per-user install.
    DetailPrint "$(MSG_CHILD_IN_USE)"
    MessageBox MB_RETRYCANCEL|MB_ICONEXCLAMATION "$(MSG_CHILD_IN_USE)" /SD IDCANCEL IDRETRY retry_child
    SetErrorLevel 3
    Abort
    retry_child:
    StrCpy $CheckFiles 0
    Call EnsureAppClosed                    ; the GUI may have been started again meanwhile
    Goto run_child
  ${ElseIf} $ChildRc != 0
    Goto child_failed                       ; 740, "?" and everything else: exit 2
  ${EndIf}

  ; Exit code 0: also check the result (SetRegView 64 from .onInit is still in effect, so this
  ; reads the 64-bit HKLM view).
  ReadRegStr $R3 HKLM "${UNINST_KEY}" "DisplayVersion"
  ReadRegStr $R4 HKLM "${UNINST_KEY}" "InstallLocation"
  ${If} $R3 != "${VERSION}"
  ${OrIf} $R4 != $INSTDIR
    Goto child_failed
  ${EndIf}
  ClearErrors
  GetFileTime "$INSTDIR\${UNINSTALLER_EXE}" $R3 $R4
  ${If} ${Errors}
    Goto child_failed
  ${EndIf}
  ${If} $R3 == $R1
  ${AndIf} $R4 == $R2
    Goto child_failed
  ${EndIf}

  DetailPrint "$(DETAIL_ELEVATED_OK)"
  StrCpy $Delegated 1
  Return

  child_failed:
  DetailPrint "$(MSG_CHILD_FAILED)"
  MessageBox MB_OK|MB_ICONSTOP "$(MSG_CHILD_FAILED)" /SD IDOK
  SetErrorLevel 2
  Abort
FunctionEnd

; Uninstaller: called from un.onInit for an "All users" installation when not elevated.
; Closes the GUI of this session first (the elevated copy may run as a different account and
; could not signal it), then starts the installed uninstall.exe elevated and exits.
; The installed copy is used rather than $EXEPATH, which is a temporary copy in the user's
; writable %TEMP%. No _?= is passed, so the elevated uninstaller copies itself to its own temp
; folder and can delete uninstall.exe. Its exit code cannot be passed back; scripts that need
; it must start the uninstaller from an elevated process.
Function un.RelaunchElevated
  StrCpy $CheckFiles 0
  Call un.EnsureAppClosed
  StrCpy $R0 "/AllUsers /ElevatedChild"
  ${If} ${Silent}
    StrCpy $R0 "$R0 /S"
  ${EndIf}

  run_elevated:
  ClearErrors
  ExecShellWait "runas" "$INSTDIR\${UNINSTALLER_EXE}" "$R0"
  ${If} ${Errors}
    MessageBox MB_RETRYCANCEL|MB_ICONEXCLAMATION "$(MSG_UN_UAC_DENIED)" /SD IDCANCEL IDRETRY run_elevated
    SetErrorLevel 5
    Quit
  ${EndIf}
  SetErrorLevel 0
  Quit
FunctionEnd
