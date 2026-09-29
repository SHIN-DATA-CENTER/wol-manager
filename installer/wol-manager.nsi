; WoL Manager installer (NSIS 3.12 or later, Unicode, stock plugins only).
;
; Built by scripts\build.ps1, which passes the values below as /D defines, e.g.
;   makensis /V3 /INPUTCHARSET UTF8 /WX /DVERSION=0.1.0 /DVERSION_NUM=0.1.0.0
;            /DSTAGE_DIR=<dist\stage\...> /DOUTFILE=<dist\...-setup-x64.exe> /DAPP_ICON=<app.ico>
;            /DMUTEX_NAME=Local\... /DQUIT_EVENT=Local\....quit /DAPPDATA_DIRNAME=wol-manager
;            /DUNINST_KEY_NAME=wol-manager /DUNINSTALLER_EXE=uninstall.exe (and the names below)
;            installer\wol-manager.nsi
; The values come from [workspace.metadata.wol] in Cargo.toml (= crates/wol-core/src/consts.rs,
; checked by crates/wol-core/tests/consts.rs, which also keeps these files free of the literal
; uninstaller, CLI and bin folder names).
;
; Design (implementation plan, section 9.3):
; - RequestExecutionLevel user. "All users" is installed by an elevated, silent copy of this
;   installer (runas + /ElevatedChild), so "Just me" never runs elevated.
; - No InstallDir attribute: in .onInit $INSTDIR is non-empty only when /D= was given, and it is
;   saved before anything else touches it.
; - PATH is changed only through "wolm path add|remove" (NSIS_MAX_STRLEN = 1024 would truncate
;   a long PATH). Only nsExec::ExecToStack is used: the log variant of nsExec crashes Unicode
;   installers in NSIS <= 3.12 (bug #1323; enforced by scripts/check-repo-hygiene.ps1).
;   The decision is made on the exit code alone; wolm's --json output is ASCII.
; - The uninstaller deletes only the files it knows and uses a non-recursive RMDir.
; - An upgrade installs over the existing installation of the same scope, in its folder. A /D=
;   folder that differs from it is refused (silent: exit 2): a second copy would orphan the
;   first one, its files and its PATH entry, with no uninstaller left.
; - On an upgrade the PATH component follows the real state of PATH ("wolm path status" of the
;   installed copy), because the GUI or the user may have changed it since the last setup.
;
; - "All users" outside Program Files: such a folder usually lets every user change its files
;   (e.g. "Authenticated Users: Modify" under C:\), while administrators run them (the elevated
;   uninstaller runs wolm, the folder is on the system PATH). The wizard asks, a silent setup
;   needs /AllowOutsideProgramFiles, and the folder is then locked down (LockDownInstDir).
;
; Installer switches:   /S /CurrentUser /AllUsers /NoPath /DesktopShortcut
;                       /AllowOutsideProgramFiles /D=<dir>
;                       (/D= last and unquoted; /ElevatedChild is internal)
; Uninstaller switches: /S /CurrentUser /AllUsers /PURGE (/PURGE only for CurrentUser)
; Exit codes: 0 success, 1 cancelled, 2 failed, 3 WoL Manager running or a file in use,
;             4 installed for the other scope (with an explicit scope switch), 5 UAC declined,
;             740 /ElevatedChild started without elevation.

Unicode True

; ---------------------------------------------------------------- build-time values
!macro _WOL_REQUIRE NAME
  !ifndef ${NAME}
    !error "${NAME} is not defined. Build with scripts\build.ps1 (makensis /D${NAME}=...)."
  !endif
!macroend
!insertmacro _WOL_REQUIRE VERSION
!insertmacro _WOL_REQUIRE VERSION_NUM
!insertmacro _WOL_REQUIRE STAGE_DIR
!insertmacro _WOL_REQUIRE OUTFILE
!insertmacro _WOL_REQUIRE APP_ICON
!insertmacro _WOL_REQUIRE MUTEX_NAME
!insertmacro _WOL_REQUIRE QUIT_EVENT
!insertmacro _WOL_REQUIRE APPDATA_DIRNAME
!insertmacro _WOL_REQUIRE UNINST_KEY_NAME

!if "${APPDATA_DIRNAME}" == ""
  !error "APPDATA_DIRNAME must not be empty (the uninstaller deletes $APPDATA\<name> on /PURGE)"
!endif
!if "${UNINST_KEY_NAME}" == ""
  !error "UNINST_KEY_NAME must not be empty"
!endif

!define /ifndef PRODUCT_NAME "WoL Manager"
!define /ifndef PUBLISHER "SHIN DATA CENTER"
!define /ifndef INSTALL_DIR_NAME "WoL Manager"
!define /ifndef GUI_EXE "wol-manager.exe"
!define /ifndef CLI_EXE "wolm.exe"
!define /ifndef CLI_SUBDIR "bin"
; Its presence marks an installed copy for the app (portable markers are ignored there).
!define /ifndef UNINSTALLER_EXE "uninstall.exe"
!define /ifndef PROJECT_URL "https://github.com/SHIN-DATA-CENTER/wol-manager"

!define UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${UNINST_KEY_NAME}"
!define SHORTCUT_NAME "${PRODUCT_NAME}.lnk"

!searchparse /noerrors "${VERSION_NUM}" "" VER_MAJOR "." VER_MINOR "." VER_PATCH "." VER_BUILD
!ifndef VER_BUILD
  !error "VERSION_NUM must have four numeric parts, e.g. 0.1.0.0 (got '${VERSION_NUM}')"
!endif

; ---------------------------------------------------------------- includes
!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "Sections.nsh"
!include "FileFunc.nsh"
!include "WordFunc.nsh"
!include "x64.nsh"
!include "WinVer.nsh"
!include "WinCore.nsh"
!include "Integration.nsh"
!include "nsDialogs.nsh"

; ---------------------------------------------------------------- attributes
Name "${PRODUCT_NAME}"
OutFile "${OUTFILE}"
RequestExecutionLevel user
ManifestDPIAware true
SetCompressor /SOLID lzma
AllowSkipFiles off
BrandingText "${PRODUCT_NAME} ${VERSION}"
ShowInstDetails show
ShowUninstDetails show
; No InstallDir / InstallDirRegKey on purpose (see the header).

; ---------------------------------------------------------------- variables
; Declared before the language files, whose strings reference some of them.
Var Mode          ; "CurrentUser" | "AllUsers"
Var PathScope     ; "user" | "machine" (wolm path --scope)
Var Elevated      ; 1 when this process runs with an administrator token
Var IsChild       ; 1 with /ElevatedChild
Var ScopeForced   ; 1 when /CurrentUser or /AllUsers was given
Var CmdInstDir    ; /D= value (empty when not given)
Var OptNoPath     ; /NoPath
Var OptDesktop    ; /DesktopShortcut
Var OptOutsidePF  ; /AllowOutsideProgramFiles, or confirmed on the directory page
Var OptPurge      ; /PURGE (uninstaller)
Var DirMode       ; scope for which $INSTDIR was last defaulted
Var PreselMode    ; scope for which the components were last preselected
Var ExistUserDir  ; existing "Just me" installation (HKCU)
Var ExistUserVer
Var ExistAllDir   ; existing "All users" installation (HKLM, 64-bit view)
Var ExistAllVer
Var ExistSameDir  ; existing installation in the selected scope (upgrade in place)
Var InfoVer       ; message arguments
Var InfoDir
Var OtherVer
Var OtherDir
Var VerCmp        ; "upgrade" | "same" | "downgrade"
Var Delegated     ; 1 when the elevated child did the installation
Var CheckFiles    ; argument of EnsureAppClosed
Var FileInUse     ; message argument
Var PathRc        ; exit code of wolm path
Var UpgradeDirOk  ; result of CheckUpgradeDir (1 = go on)
Var ChildRc       ; exit code (or start error) of the elevated child

; ---------------------------------------------------------------- pages
!define MUI_ICON "${APP_ICON}"
!define MUI_UNICON "${APP_ICON}"
!define MUI_ABORTWARNING
!define MUI_UNABORTWARNING
!define MUI_COMPONENTSPAGE_SMALLDESC

!insertmacro MUI_PAGE_WELCOME
Page custom ScopePageCreate ScopePageLeave
!define MUI_PAGE_CUSTOMFUNCTION_PRE ComponentsPre
!insertmacro MUI_PAGE_COMPONENTS
!define MUI_PAGE_CUSTOMFUNCTION_PRE DirectoryPre
!define MUI_PAGE_CUSTOMFUNCTION_LEAVE DirectoryLeave
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!define MUI_FINISHPAGE_TEXT "$(FINISH_TEXT)"
!define MUI_FINISHPAGE_RUN
!define MUI_FINISHPAGE_RUN_FUNCTION LaunchApp
!define MUI_PAGE_CUSTOMFUNCTION_SHOW FinishShow
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!define MUI_PAGE_CUSTOMFUNCTION_PRE un.ComponentsPre
!insertmacro MUI_UNPAGE_COMPONENTS
!insertmacro MUI_UNPAGE_INSTFILES

; English first: it is the fallback for other UI languages.
!insertmacro MUI_LANGUAGE "English"
!insertmacro MUI_LANGUAGE "Japanese"
!include "${__FILEDIR__}\lang\English.nsh"
!include "${__FILEDIR__}\lang\Japanese.nsh"

; ---------------------------------------------------------------- version resource
VIProductVersion "${VERSION_NUM}"
VIFileVersion "${VERSION_NUM}"
VIAddVersionKey /LANG=${LANG_ENGLISH} "ProductName" "${PRODUCT_NAME}"
VIAddVersionKey /LANG=${LANG_ENGLISH} "CompanyName" "${PUBLISHER}"
VIAddVersionKey /LANG=${LANG_ENGLISH} "FileDescription" "${PRODUCT_NAME} Setup"
VIAddVersionKey /LANG=${LANG_ENGLISH} "FileVersion" "${VERSION}"
VIAddVersionKey /LANG=${LANG_ENGLISH} "ProductVersion" "${VERSION}"
VIAddVersionKey /LANG=${LANG_ENGLISH} "LegalCopyright" "Copyright (c) ${PUBLISHER}. Apache License 2.0."

; ---------------------------------------------------------------- shared macros
!include "${__FILEDIR__}\include\running-app.nsh"

; Runs "wolm path <ACTION>" for $INSTDIR\bin in $PathScope. Exit code -> $PathRc, output -> $0.
; wolm exit codes: 0 changed, 1 no change (already present / not present), other = error.
!macro WOL_WOLM_PATH ACTION
  nsExec::ExecToStack /TIMEOUT=120000 '"$INSTDIR\${CLI_SUBDIR}\${CLI_EXE}" path ${ACTION} --scope $PathScope --json --lang en "$INSTDIR\${CLI_SUBDIR}"'
  Pop $PathRc
  Pop $0
!macroend

!macro WOL_PATH_REMOVE
  ${If} ${FileExists} "$INSTDIR\${CLI_SUBDIR}\${CLI_EXE}"
    !insertmacro WOL_WOLM_PATH remove
    ${If} $PathRc == 0
      DetailPrint "$(DETAIL_PATH_REMOVED)"
    ${ElseIf} $PathRc == 1
      DetailPrint "$(DETAIL_PATH_ABSENT)"
    ${Else}
      DetailPrint "$(DETAIL_PATH_REMOVE_FAILED)"
      DetailPrint "$0"
    ${EndIf}
  ${Else}
    DetailPrint "$(DETAIL_WOLM_MISSING)"
  ${EndIf}
!macroend

; ================================================================ installer sections
Section "!$(SEC_PROGRAM)" SecProgram
  SectionIn RO

  ${If} $Mode == "AllUsers"
  ${AndIf} $Elevated != 1
    ; Close the GUI of this session (the elevated child may be another account), then let the
    ; elevated child do the whole installation. The other sections skip on $Delegated.
    StrCpy $CheckFiles 0
    Call EnsureAppClosed
    Call DelegateToElevatedChild
    Return
  ${EndIf}

  StrCpy $CheckFiles 1
  Call EnsureAppClosed

  ; "All users" outside Program Files: only administrators may change the programs. Done
  ; before any file is written, so that every file inherits it.
  Call IsAllUsersOutsidePF
  ${If} $1 == 1
    Call LockDownInstDir
  ${EndIf}

  ; A silent install answers a file error prompt with its default, which would only set the
  ; error flag: check it so that a failed copy never ends with exit code 0.
  ClearErrors
  SetOutPath "$INSTDIR"
  File "${STAGE_DIR}\${GUI_EXE}"
  File "${STAGE_DIR}\LICENSE.txt"
  File "${STAGE_DIR}\THIRD-PARTY-NOTICES.txt"
  SetOutPath "$INSTDIR\${CLI_SUBDIR}"
  File "${STAGE_DIR}\${CLI_SUBDIR}\${CLI_EXE}"
  SetOutPath "$INSTDIR"
  WriteUninstaller "$INSTDIR\${UNINSTALLER_EXE}"
  ${If} ${Errors}
    DetailPrint "$(MSG_FILES_FAILED)"
    MessageBox MB_OK|MB_ICONSTOP "$(MSG_FILES_FAILED)" /SD IDOK
    SetErrorLevel 2
    Abort
  ${EndIf}

  CreateShortcut "$SMPROGRAMS\${SHORTCUT_NAME}" "$INSTDIR\${GUI_EXE}" "" "$INSTDIR\${GUI_EXE}" 0

  ; Add/Remove Programs entry (SHCTX = HKLM for AllUsers, HKCU for CurrentUser; 64-bit view).
  ClearErrors
  WriteRegStr SHCTX "${UNINST_KEY}" "DisplayName" "${PRODUCT_NAME}"
  WriteRegStr SHCTX "${UNINST_KEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr SHCTX "${UNINST_KEY}" "Publisher" "${PUBLISHER}"
  WriteRegStr SHCTX "${UNINST_KEY}" "DisplayIcon" "$INSTDIR\${GUI_EXE},0"
  WriteRegStr SHCTX "${UNINST_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr SHCTX "${UNINST_KEY}" "InstallMode" "$Mode"
  WriteRegStr SHCTX "${UNINST_KEY}" "UninstallString" '"$INSTDIR\${UNINSTALLER_EXE}" /$Mode'
  WriteRegStr SHCTX "${UNINST_KEY}" "QuietUninstallString" '"$INSTDIR\${UNINSTALLER_EXE}" /$Mode /S'
  WriteRegStr SHCTX "${UNINST_KEY}" "URLInfoAbout" "${PROJECT_URL}"
  WriteRegDWORD SHCTX "${UNINST_KEY}" "VersionMajor" ${VER_MAJOR}
  WriteRegDWORD SHCTX "${UNINST_KEY}" "VersionMinor" ${VER_MINOR}
  WriteRegDWORD SHCTX "${UNINST_KEY}" "NoModify" 1
  WriteRegDWORD SHCTX "${UNINST_KEY}" "NoRepair" 1
  ${If} ${Errors}
    DetailPrint "$(MSG_FILES_FAILED)"
    MessageBox MB_OK|MB_ICONSTOP "$(MSG_FILES_FAILED)" /SD IDOK
    SetErrorLevel 2
    Abort
  ${EndIf}
SectionEnd

Section "$(SEC_PATH)" SecPath
  ${If} $Delegated == 1
    Return
  ${EndIf}
  !insertmacro WOL_WOLM_PATH add
  ; PathEntryAdded records the choice for the next upgrade (PreselectComponents falls back to it
  ; when the installed wolm cannot report the state), so it is also set when the entry was
  ; already there (by hand, by the GUI or by a previous installation).
  ${If} $PathRc == 0
    WriteRegDWORD SHCTX "${UNINST_KEY}" "PathEntryAdded" 1
    DetailPrint "$(DETAIL_PATH_ADDED)"
  ${ElseIf} $PathRc == 1
    WriteRegDWORD SHCTX "${UNINST_KEY}" "PathEntryAdded" 1
    DetailPrint "$(DETAIL_PATH_PRESENT)"
  ${Else}
    ; Never fail the installation because of PATH; the message shows the full command that
    ; adds it later (wolm is not on PATH yet, and "path add" defaults to the user PATH).
    ${If} $PathScope == "machine"
      DetailPrint "$(DETAIL_PATH_ADD_FAILED_MACHINE)"
    ${Else}
      DetailPrint "$(DETAIL_PATH_ADD_FAILED)"
    ${EndIf}
    DetailPrint "$0"
  ${EndIf}
SectionEnd

Section /o "$(SEC_DESKTOP)" SecDesktop
  ${If} $Delegated == 1
    Return
  ${EndIf}
  CreateShortcut "$DESKTOP\${SHORTCUT_NAME}" "$INSTDIR\${GUI_EXE}" "" "$INSTDIR\${GUI_EXE}" 0
SectionEnd

Section "-PostInstall" SecPost
  ${If} $Delegated == 1
    Return
  ${EndIf}
  ; Upgrade: remove what was deselected this time.
  ${IfNot} ${SectionIsSelected} ${SecPath}
    ${If} $ExistSameDir != ""
      !insertmacro WOL_PATH_REMOVE
    ${EndIf}
    WriteRegDWORD SHCTX "${UNINST_KEY}" "PathEntryAdded" 0
  ${EndIf}
  ${IfNot} ${SectionIsSelected} ${SecDesktop}
    ${UnpinShortcut} "$DESKTOP\${SHORTCUT_NAME}"
    Delete "$DESKTOP\${SHORTCUT_NAME}"
  ${EndIf}
  ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
  IntFmt $0 "0x%08X" $0
  WriteRegDWORD SHCTX "${UNINST_KEY}" "EstimatedSize" "$0"
SectionEnd

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SecProgram} "$(DESC_PROGRAM)"
  !insertmacro MUI_DESCRIPTION_TEXT ${SecPath} "$(DESC_PATH)"
  !insertmacro MUI_DESCRIPTION_TEXT ${SecDesktop} "$(DESC_DESKTOP)"
!insertmacro MUI_FUNCTION_DESCRIPTION_END

; ================================================================ uninstaller sections
Section "un.$(UN_SEC_PROGRAM)" UnSecProgram
  SectionIn RO
  StrCpy $CheckFiles 1
  Call un.EnsureAppClosed

  ; 1. PATH first, while wolm.exe still exists. Always, for this scope: the entry may also have
  ;    been added by the GUI or by hand, and it is dead once the folder is gone. 1 = not present.
  !insertmacro WOL_PATH_REMOVE

  ; 2. Shortcuts.
  ${UnpinShortcut} "$SMPROGRAMS\${SHORTCUT_NAME}"
  Delete "$SMPROGRAMS\${SHORTCUT_NAME}"
  ${UnpinShortcut} "$DESKTOP\${SHORTCUT_NAME}"
  Delete "$DESKTOP\${SHORTCUT_NAME}"

  ; 3. Known files only, then non-recursive RMDir (never RMDir /r $INSTDIR).
  Delete /REBOOTOK "$INSTDIR\${GUI_EXE}"
  Delete /REBOOTOK "$INSTDIR\${CLI_SUBDIR}\${CLI_EXE}"
  Delete "$INSTDIR\LICENSE.txt"
  Delete "$INSTDIR\THIRD-PARTY-NOTICES.txt"
  Delete "$INSTDIR\${UNINSTALLER_EXE}"
  RMDir "$INSTDIR\${CLI_SUBDIR}"
  RMDir "$INSTDIR"

  ; 4. Add/Remove Programs entry.
  DeleteRegKey SHCTX "${UNINST_KEY}"
SectionEnd

Section /o "un.$(UN_SEC_PURGE)" UnSecPurge
  ; Offered only for "Just me" (hidden otherwise): with SetShellVarContext all, $APPDATA would be
  ; ProgramData, and an elevated account is not necessarily the owner of the settings.
  ${If} $Mode == "CurrentUser"
    RMDir /r "$APPDATA\${APPDATA_DIRNAME}"
    RMDir /r "$LOCALAPPDATA\${APPDATA_DIRNAME}"
    DetailPrint "$(DETAIL_SETTINGS_REMOVED)"
  ${EndIf}
SectionEnd

Section "-un.Report"
  ${If} $Mode != "CurrentUser"
    DetailPrint "$(DETAIL_SETTINGS_KEPT_ALL)"
  ${ElseIfNot} ${SectionIsSelected} ${UnSecPurge}
    DetailPrint "$(DETAIL_SETTINGS_KEPT)"
  ${EndIf}
SectionEnd

!insertmacro MUI_UNFUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${UnSecProgram} "$(UN_DESC_PROGRAM)"
  !insertmacro MUI_DESCRIPTION_TEXT ${UnSecPurge} "$(UN_DESC_PURGE)"
!insertmacro MUI_UNFUNCTION_DESCRIPTION_END

; ================================================================ functions
!include "${__FILEDIR__}\include\elevate.nsh"
!include "${__FILEDIR__}\include\scope-page.nsh"

; Sets the shell context, the PATH scope and $INSTDIR: the existing installation of this scope
; (upgrade in place; CheckUpgradeDir has refused a different /D=) > /D= > the folder the user
; already chose for this scope > the per-scope default.
Function ApplyMode
  ${If} $Mode == "AllUsers"
    SetShellVarContext all
    StrCpy $PathScope "machine"
    StrCpy $ExistSameDir $ExistAllDir
  ${Else}
    SetShellVarContext current
    StrCpy $PathScope "user"
    StrCpy $ExistSameDir $ExistUserDir
  ${EndIf}

  ${If} $ExistSameDir != ""
    StrCpy $INSTDIR $ExistSameDir
    StrCpy $DirMode $Mode
  ${ElseIf} $CmdInstDir != ""
    StrCpy $INSTDIR $CmdInstDir
  ${ElseIf} $DirMode != $Mode
    ${If} $Mode == "AllUsers"
      StrCpy $INSTDIR "$PROGRAMFILES64\${INSTALL_DIR_NAME}"
    ${Else}
      GetKnownFolderPath $0 ${FOLDERID_UserProgramFiles}
      ${If} $0 == ""
        StrCpy $0 "$LOCALAPPDATA\Programs"
      ${EndIf}
      StrCpy $INSTDIR "$0\${INSTALL_DIR_NAME}"
    ${EndIf}
    StrCpy $DirMode $Mode
  ${EndIf}
FunctionEnd

; Removes trailing backslashes: DEST = SRC without them. Uses $R9.
!macro _WOL_TRIM_BACKSLASHES DEST SRC
  StrCpy ${DEST} "${SRC}"
  ${Do}
    StrCpy $R9 ${DEST} 1 -1
    ${If} $R9 != "\"
      ${ExitDo}
    ${EndIf}
    StrCpy ${DEST} ${DEST} -1
  ${Loop}
!macroend

; An existing installation is upgraded in its own folder and never moved (plan 9.3). A /D= that
; names another folder is therefore refused: installing a second copy would leave the first one,
; its files and its PATH entry (which stays ahead of the new one) without an uninstaller.
; In:  $InfoDir/$InfoVer = installation of the chosen scope (LoadScopeInfo), $CmdInstDir.
; Out: $UpgradeDirOk = 1 to go on (no conflict, or the user agreed to upgrade in the existing
;      folder), 0 when refused (always when silent). Keeps all registers.
Function CheckUpgradeDir
  StrCpy $UpgradeDirOk 1
  ${If} $InfoDir == ""
  ${OrIf} $CmdInstDir == ""
    Return
  ${EndIf}
  Push $R0
  Push $R1
  Push $R9
  !insertmacro _WOL_TRIM_BACKSLASHES $R0 $InfoDir
  !insertmacro _WOL_TRIM_BACKSLASHES $R1 $CmdInstDir
  ${If} $R0 != $R1                          ; == and != ignore case
    MessageBox MB_YESNO|MB_ICONEXCLAMATION|MB_DEFBUTTON2 "$(MSG_UPGRADE_OTHER_DIR)" /SD IDNO IDYES upgrade_dir_ok
    StrCpy $UpgradeDirOk 0
    upgrade_dir_ok:
  ${EndIf}
  Pop $R9
  Pop $R1
  Pop $R0
FunctionEnd

; Component defaults for the current scope: command-line switches first; the elevated child
; follows the parent's choice exactly; an upgrade keeps the current state.
Function PreselectComponents
  StrCpy $PreselMode $Mode

  ${If} $OptNoPath == 1
    !insertmacro UnselectSection ${SecPath}
  ${ElseIf} $IsChild == 1
    !insertmacro SelectSection ${SecPath}
  ${Else}
    !insertmacro SelectSection ${SecPath}
    ${If} $ExistSameDir != ""
      ; Upgrade: follow the real PATH, not only the flag of the last setup. The GUI's PATH switch
      ; (per-user installations) and "wolm path add|remove" change PATH without updating it, and
      ; SecPost removes the entry when the component is not selected.
      ; "wolm path status": 0 = on PATH, 1 = not on PATH (read only, no elevation needed).
      StrCpy $1 ""
      ${If} ${FileExists} "$ExistSameDir\${CLI_SUBDIR}\${CLI_EXE}"
        nsExec::ExecToStack /TIMEOUT=30000 '"$ExistSameDir\${CLI_SUBDIR}\${CLI_EXE}" path status --scope $PathScope --json --lang en "$ExistSameDir\${CLI_SUBDIR}"'
        Pop $1                              ; exit code, "error" or "timeout"
        Pop $2                              ; output (unused)
      ${EndIf}
      ${If} $1 == 1
        !insertmacro UnselectSection ${SecPath}
      ${ElseIf} $1 != 0
        ; wolm missing or failed: fall back to the flag written by the last setup.
        ClearErrors
        ReadRegDWORD $0 SHCTX "${UNINST_KEY}" "PathEntryAdded"
        ${IfNot} ${Errors}
        ${AndIf} $0 == 0
          !insertmacro UnselectSection ${SecPath}
        ${EndIf}
      ${EndIf}
    ${EndIf}
  ${EndIf}

  ${If} $OptDesktop == 1
    !insertmacro SelectSection ${SecDesktop}
  ${ElseIf} $IsChild != 1
  ${AndIf} $ExistSameDir != ""
  ${AndIf} ${FileExists} "$DESKTOP\${SHORTCUT_NAME}"
    !insertmacro SelectSection ${SecDesktop}
  ${Else}
    !insertmacro UnselectSection ${SecDesktop}
  ${EndIf}
FunctionEnd

Function ComponentsPre
  ${If} $PreselMode != $Mode
    Call PreselectComponents
  ${EndIf}
FunctionEnd

Function DirectoryPre
  ; Upgrade in place: the folder of the existing installation is kept (see CheckUpgradeDir).
  ${If} $ExistSameDir != ""
    Abort
  ${EndIf}
FunctionEnd

; $1 = 1 when $INSTDIR is $0 or below it (case-insensitive).
Function IsInstDirUnder
  StrCpy $1 0
  StrLen $2 $0
  StrCpy $3 $INSTDIR $2
  ${If} $3 == $0
    StrCpy $3 $INSTDIR 1 $2
    ${If} $3 == ""
    ${OrIf} $3 == "\"
      StrCpy $1 1
    ${EndIf}
  ${EndIf}
FunctionEnd

Function DirectoryLeave
  ${If} $Mode == "CurrentUser"
    StrCpy $0 $PROGRAMFILES64
    Call IsInstDirUnder
    ${If} $1 != 1
      StrCpy $0 $PROGRAMFILES32
      Call IsInstDirUnder
    ${EndIf}
    ${If} $1 != 1
      StrCpy $0 $WINDIR
      Call IsInstDirUnder
    ${EndIf}
    ${If} $1 == 1
      MessageBox MB_OK|MB_ICONEXCLAMATION "$(MSG_DIR_USER_PF)"
      Abort
    ${EndIf}
  ${Else}
    Call IsAllUsersOutsidePF
    ${If} $1 == 1
      MessageBox MB_YESNO|MB_ICONEXCLAMATION|MB_DEFBUTTON2 "$(MSG_DIR_ALL_OUTSIDE_PF)" IDYES dir_ok
      Abort
      dir_ok:
      StrCpy $OptOutsidePF 1                ; also passed on to the elevated child
    ${EndIf}
  ${EndIf}
FunctionEnd

; $1 = 1 for an "All users" installation outside $PROGRAMFILES64 (see the header). Uses $0-$3.
Function IsAllUsersOutsidePF
  ${If} $Mode != "AllUsers"
    StrCpy $1 0
    Return
  ${EndIf}
  StrCpy $0 $PROGRAMFILES64
  Call IsInstDirUnder
  ${If} $1 == 1
    StrCpy $1 0
  ${Else}
    StrCpy $1 1
  ${EndIf}
FunctionEnd

; Makes Administrators the owner of $INSTDIR and of everything already in it, resets the
; children to inherited permissions and gives $INSTDIR a protected DACL: Administrators and
; SYSTEM full control, Users read and execute. Aborts the installation (exit code 2) when that
; fails (e.g. FAT32 / exFAT, which have no permissions). Uses $0 and $1.
Function LockDownInstDir
  DetailPrint "$(DETAIL_DIR_LOCKING)"
  CreateDirectory "$INSTDIR"
  nsExec::ExecToStack /TIMEOUT=120000 '"$SYSDIR\icacls.exe" "$INSTDIR" /setowner *S-1-5-32-544 /T /C /Q'
  Pop $0
  Pop $1
  ${If} $0 == 0
    nsExec::ExecToStack /TIMEOUT=120000 '"$SYSDIR\icacls.exe" "$INSTDIR" /reset /T /C /Q'
    Pop $0
    Pop $1
  ${EndIf}
  ${If} $0 == 0
    nsExec::ExecToStack /TIMEOUT=120000 '"$SYSDIR\icacls.exe" "$INSTDIR" /inheritance:r /grant:r *S-1-5-32-544:(OI)(CI)F *S-1-5-18:(OI)(CI)F *S-1-5-32-545:(OI)(CI)RX /Q'
    Pop $0
    Pop $1
  ${EndIf}
  ${If} $0 != 0
    DetailPrint "$1"
    MessageBox MB_OK|MB_ICONSTOP "$(MSG_DIR_LOCK_FAILED)" /SD IDOK
    SetErrorLevel 2
    Abort
  ${EndIf}
FunctionEnd

Function FinishShow
  ; Never start the GUI from an elevated installer: it would run elevated, possibly as another
  ; account. After an "All users" delegation this (parent) process is not elevated.
  ${If} $Elevated == 1
    SendMessage $mui.FinishPage.Run ${BM_SETCHECK} ${BST_UNCHECKED} 0
    ShowWindow $mui.FinishPage.Run ${SW_HIDE}
  ${EndIf}
FunctionEnd

Function LaunchApp
  SetOutPath "$INSTDIR"
  Exec '"$INSTDIR\${GUI_EXE}"'
FunctionEnd

Function .onInit
  SetRegView 64                             ; before any HKLM access
  StrCpy $CmdInstDir $INSTDIR               ; non-empty only with /D=

  ; x64 Windows 10+, or ARM64 Windows 11 (x64 emulation).
  ${IfNot} ${AtLeastWin10}
    MessageBox MB_OK|MB_ICONSTOP "$(MSG_REQ_OS)" /SD IDOK
    SetErrorLevel 1
    Quit
  ${EndIf}
  ${IfNot} ${IsNativeAMD64}
    ${IfNot} ${IsNativeARM64}
    ${OrIfNot} ${AtLeastWin11}
      MessageBox MB_OK|MB_ICONSTOP "$(MSG_REQ_OS)" /SD IDOK
      SetErrorLevel 1
      Quit
    ${EndIf}
  ${EndIf}

  UserInfo::GetAccountType
  Pop $0
  ${If} $0 == "Admin"
    StrCpy $Elevated 1
  ${Else}
    StrCpy $Elevated 0
  ${EndIf}

  ${GetParameters} $R0
  StrCpy $R1 0
  StrCpy $R2 0
  ClearErrors
  ${GetOptions} $R0 "/AllUsers" $0
  ${IfNot} ${Errors}
    StrCpy $R1 1
  ${EndIf}
  ClearErrors
  ${GetOptions} $R0 "/CurrentUser" $0
  ${IfNot} ${Errors}
    StrCpy $R2 1
  ${EndIf}
  StrCpy $IsChild 0
  ClearErrors
  ${GetOptions} $R0 "/ElevatedChild" $0
  ${IfNot} ${Errors}
    StrCpy $IsChild 1
  ${EndIf}
  StrCpy $OptNoPath 0
  ClearErrors
  ${GetOptions} $R0 "/NoPath" $0
  ${IfNot} ${Errors}
    StrCpy $OptNoPath 1
  ${EndIf}
  StrCpy $OptDesktop 0
  ClearErrors
  ${GetOptions} $R0 "/DesktopShortcut" $0
  ${IfNot} ${Errors}
    StrCpy $OptDesktop 1
  ${EndIf}
  StrCpy $OptOutsidePF 0
  ClearErrors
  ${GetOptions} $R0 "/AllowOutsideProgramFiles" $0
  ${IfNot} ${Errors}
    StrCpy $OptOutsidePF 1
  ${EndIf}

  ${If} $IsChild == 1
  ${AndIf} $Elevated != 1
    SetErrorLevel 740                       ; ERROR_ELEVATION_REQUIRED
    Quit
  ${EndIf}
  ${If} $R1 == 1
  ${AndIf} $R2 == 1
    MessageBox MB_OK|MB_ICONSTOP "$(MSG_BAD_SWITCHES)" /SD IDOK
    SetErrorLevel 2
    Quit
  ${EndIf}

  ; Existing installations (the AllUsers key is read from the 64-bit view).
  ReadRegStr $ExistAllDir HKLM "${UNINST_KEY}" "InstallLocation"
  ReadRegStr $ExistAllVer HKLM "${UNINST_KEY}" "DisplayVersion"
  ReadRegStr $ExistUserDir HKCU "${UNINST_KEY}" "InstallLocation"
  ReadRegStr $ExistUserVer HKCU "${UNINST_KEY}" "DisplayVersion"

  ; Scope: switch > existing installation (AllUsers first) > CurrentUser.
  StrCpy $ScopeForced 0
  ${If} $R1 == 1
    StrCpy $Mode "AllUsers"
    StrCpy $ScopeForced 1
  ${ElseIf} $R2 == 1
    StrCpy $Mode "CurrentUser"
    StrCpy $ScopeForced 1
  ${ElseIf} $ExistAllDir != ""
    StrCpy $Mode "AllUsers"
  ${ElseIf} $ExistUserDir != ""
    StrCpy $Mode "CurrentUser"
  ${Else}
    StrCpy $Mode "CurrentUser"
  ${EndIf}

  ; An explicit scope must not create a second installation next to one in the other scope.
  ; (The elevated child cannot see the parent user's HKCU; the parent already checked.)
  ${If} $ScopeForced == 1
  ${AndIf} $IsChild != 1
    StrCpy $0 $Mode
    Call LoadScopeInfo
    ${If} $InfoDir == ""
    ${AndIf} $OtherDir != ""
      MessageBox MB_OK|MB_ICONSTOP "$(MSG_OTHER_SCOPE)" /SD IDOK
      SetErrorLevel 4
      Quit
    ${EndIf}
  ${EndIf}

  ; Upgrade in place: a /D= that names another folder is refused. The scope is final here when
  ; silent or given on the command line; otherwise ScopePageLeave does this check.
  ${If} ${Silent}
  ${OrIf} $ScopeForced == 1
    StrCpy $0 $Mode
    Call LoadScopeInfo
    Call CheckUpgradeDir
    ${If} $UpgradeDirOk != 1
      ${If} ${Silent}
        SetErrorLevel 2
      ${Else}
        SetErrorLevel 1                     ; the user answered No
      ${EndIf}
      Quit
    ${EndIf}
  ${EndIf}

  StrCpy $Delegated 0
  StrCpy $CheckFiles 1
  Call ApplyMode
  Call PreselectComponents

  ; A silent "All users" installation outside Program Files needs the explicit switch (the
  ; wizard asks on the directory page and passes it on to the elevated child). An upgrade in
  ; place keeps the folder that was accepted before.
  ${If} ${Silent}
  ${AndIf} $OptOutsidePF != 1
  ${AndIf} $ExistSameDir == ""
    Call IsAllUsersOutsidePF
    ${If} $1 == 1
      MessageBox MB_OK|MB_ICONSTOP "$(MSG_DIR_ALL_OUTSIDE_PF_SILENT)" /SD IDOK
      SetErrorLevel 2
      Quit
    ${EndIf}
  ${EndIf}
FunctionEnd

Function un.ComponentsPre
  ; Only "Just me" has a choice (remove my settings).
  ${If} $Mode != "CurrentUser"
    Abort
  ${EndIf}
FunctionEnd

Function un.onInit
  SetRegView 64                             ; before any HKLM access

  UserInfo::GetAccountType
  Pop $0
  ${If} $0 == "Admin"
    StrCpy $Elevated 1
  ${Else}
    StrCpy $Elevated 0
  ${EndIf}

  ${GetParameters} $R0
  StrCpy $Mode ""
  ClearErrors
  ${GetOptions} $R0 "/AllUsers" $0
  ${IfNot} ${Errors}
    StrCpy $Mode "AllUsers"
  ${EndIf}
  ClearErrors
  ${GetOptions} $R0 "/CurrentUser" $0
  ${IfNot} ${Errors}
    StrCpy $Mode "CurrentUser"
  ${EndIf}
  StrCpy $IsChild 0
  ClearErrors
  ${GetOptions} $R0 "/ElevatedChild" $0
  ${IfNot} ${Errors}
    StrCpy $IsChild 1
  ${EndIf}
  StrCpy $OptPurge 0
  ClearErrors
  ${GetOptions} $R0 "/PURGE" $0
  ${IfNot} ${Errors}
    StrCpy $OptPurge 1
  ${EndIf}

  ; Without a switch: "All users" when the HKLM entry points at this folder.
  ${If} $Mode == ""
    ReadRegStr $0 HKLM "${UNINST_KEY}" "InstallLocation"
    ${If} $0 != ""
    ${AndIf} $0 == $INSTDIR
      StrCpy $Mode "AllUsers"
    ${Else}
      StrCpy $Mode "CurrentUser"
    ${EndIf}
  ${EndIf}

  ${If} $Mode == "AllUsers"
    SetShellVarContext all
    StrCpy $PathScope "machine"
    ${If} $Elevated != 1
      ${If} $IsChild == 1
        SetErrorLevel 740
        Quit
      ${EndIf}
      Call un.RelaunchElevated              ; does not return
    ${EndIf}
    ; No "remove my settings" for all users (see UnSecPurge).
    SectionSetText ${UnSecPurge} ""
    !insertmacro UnselectSection ${UnSecPurge}
  ${Else}
    SetShellVarContext current
    StrCpy $PathScope "user"
    ${If} $OptPurge == 1
      !insertmacro SelectSection ${UnSecPurge}
    ${EndIf}
  ${EndIf}
FunctionEnd
