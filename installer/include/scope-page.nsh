; Installation scope page (nsDialogs): "Just me" or "All users".
;
; Shows, for the selected option, whether WoL Manager is already installed there and whether
; this setup is an upgrade, a reinstall or a downgrade. Installing into both scopes is refused
; (the same rule gives exit code 4 for silent installs). The page is skipped when /CurrentUser
; or /AllUsers was given on the command line.

Var ScopeRadioUser
Var ScopeRadioAll
Var ScopeInfo

; Push "1.2.3-rc.1+build" -> Pop "1.2.3" (numeric core used by VersionCompare).
Function VersionCore
  Exch $0
  Push $1
  Push $2
  StrCpy $1 0
  ${Do}
    StrCpy $2 $0 1 $1
    ${If} $2 == ""
      ${ExitDo}
    ${EndIf}
    ${If} $2 == "-"
    ${OrIf} $2 == "+"
      StrCpy $0 $0 $1
      ${ExitDo}
    ${EndIf}
    IntOp $1 $1 + 1
  ${Loop}
  Pop $2
  Pop $1
  Exch $0
FunctionEnd

; Compares the installed version $InfoVer with ${VERSION}.
; Sets $VerCmp to "upgrade", "same" or "downgrade".
Function CompareInstalledVersion
  Push $0
  Push $1
  Push $2
  Push $InfoVer
  Call VersionCore
  Pop $0                                    ; installed core
  Push "${VERSION}"
  Call VersionCore
  Pop $1                                    ; new core
  ${VersionCompare} $0 $1 $2                ; 0 equal, 1 installed newer, 2 new newer
  ${If} $2 == 1
    StrCpy $VerCmp "downgrade"
  ${ElseIf} $2 == 2
    StrCpy $VerCmp "upgrade"
  ${ElseIf} $InfoVer == "${VERSION}"
    StrCpy $VerCmp "same"
  ${ElseIf} $1 == "${VERSION}"
    StrCpy $VerCmp "upgrade"                ; pre-release -> release of the same core
  ${ElseIf} $0 == $InfoVer
    StrCpy $VerCmp "downgrade"              ; release -> pre-release of the same core
  ${Else}
    StrCpy $VerCmp "upgrade"                ; two pre-releases of the same core
  ${EndIf}
  Pop $2
  Pop $1
  Pop $0
FunctionEnd

; Loads the state of scope $0 ("AllUsers" / "CurrentUser") into $InfoVer/$InfoDir and of the
; other scope into $OtherVer/$OtherDir.
Function LoadScopeInfo
  ${If} $0 == "AllUsers"
    StrCpy $InfoVer $ExistAllVer
    StrCpy $InfoDir $ExistAllDir
    StrCpy $OtherVer $ExistUserVer
    StrCpy $OtherDir $ExistUserDir
  ${Else}
    StrCpy $InfoVer $ExistUserVer
    StrCpy $InfoDir $ExistUserDir
    StrCpy $OtherVer $ExistAllVer
    StrCpy $OtherDir $ExistAllDir
  ${EndIf}
FunctionEnd

Function ScopeSelectedMode
  ${NSD_GetState} $ScopeRadioAll $0
  ${If} $0 == ${BST_CHECKED}
    StrCpy $0 "AllUsers"
  ${Else}
    StrCpy $0 "CurrentUser"
  ${EndIf}
FunctionEnd

Function ScopeUpdateInfo
  Call ScopeSelectedMode
  Call LoadScopeInfo
  ${If} $InfoDir != ""
    Call CompareInstalledVersion
    ${If} $VerCmp == "downgrade"
      ${NSD_SetText} $ScopeInfo "$(SCOPE_INFO_DOWNGRADE)"
    ${ElseIf} $VerCmp == "same"
      ${NSD_SetText} $ScopeInfo "$(SCOPE_INFO_SAME)"
    ${Else}
      ${NSD_SetText} $ScopeInfo "$(SCOPE_INFO_UPGRADE)"
    ${EndIf}
  ${ElseIf} $OtherDir != ""
    ${NSD_SetText} $ScopeInfo "$(SCOPE_INFO_OTHER)"
  ${Else}
    ${NSD_SetText} $ScopeInfo "$(SCOPE_INFO_NEW)"
  ${EndIf}
FunctionEnd

Function ScopeRadioClicked
  Pop $0                                    ; clicked control (unused)
  Call ScopeUpdateInfo
FunctionEnd

Function ScopePageCreate
  ${If} $ScopeForced == 1
    Abort                                   ; scope given on the command line
  ${EndIf}
  !insertmacro MUI_HEADER_TEXT "$(SCOPE_TITLE)" "$(SCOPE_SUBTITLE)"

  nsDialogs::Create 1018
  Pop $0
  ${If} $0 == error
    Abort
  ${EndIf}

  ${NSD_CreateLabel} 0 0 100% 10u "$(SCOPE_PROMPT)"
  Pop $0

  ${NSD_CreateRadioButton} 6u 14u -6u 11u "$(SCOPE_USER)"
  Pop $ScopeRadioUser
  ${NSD_AddStyle} $ScopeRadioUser ${WS_GROUP}
  ${NSD_OnClick} $ScopeRadioUser ScopeRadioClicked
  ${NSD_CreateLabel} 18u 26u -18u 18u "$(SCOPE_USER_DESC)"
  Pop $0

  ${NSD_CreateRadioButton} 6u 47u -6u 11u "$(SCOPE_ALL)"
  Pop $ScopeRadioAll
  ${NSD_OnClick} $ScopeRadioAll ScopeRadioClicked
  ${NSD_CreateLabel} 18u 59u -18u 18u "$(SCOPE_ALL_DESC)"
  Pop $0

  ${NSD_CreateLabel} 0 82u 100% 26u ""
  Pop $ScopeInfo

  ${If} $Elevated == 1
    ${NSD_CreateLabel} 0 110u 100% 30u "$(SCOPE_ELEVATED_WARN)"
    Pop $0
  ${EndIf}

  ${If} $Mode == "AllUsers"
    ${NSD_Check} $ScopeRadioAll
  ${Else}
    ${NSD_Check} $ScopeRadioUser
  ${EndIf}
  Call ScopeUpdateInfo

  nsDialogs::Show
FunctionEnd

Function ScopePageLeave
  Call ScopeSelectedMode
  Call LoadScopeInfo
  ${If} $InfoDir == ""
  ${AndIf} $OtherDir != ""
    MessageBox MB_OK|MB_ICONEXCLAMATION "$(MSG_OTHER_SCOPE)"
    Abort                                   ; stay on the page
  ${EndIf}
  Call CheckUpgradeDir                      ; a /D= other than the existing folder (keeps $0)
  ${If} $UpgradeDirOk != 1
    Abort                                   ; stay on the page
  ${EndIf}
  ${If} $InfoDir != ""
    Call CompareInstalledVersion
    ${If} $VerCmp == "downgrade"
      MessageBox MB_YESNO|MB_ICONQUESTION|MB_DEFBUTTON2 "$(MSG_DOWNGRADE)" IDYES downgrade_ok
      Abort
      downgrade_ok:
    ${EndIf}
  ${EndIf}
  StrCpy $Mode $0
  Call ApplyMode
FunctionEnd
