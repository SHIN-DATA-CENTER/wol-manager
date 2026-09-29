; English strings for installer\wol-manager.nsi.
; Every LangString here must also exist in Japanese.nsh (makensis /WX fails on a missing one).
; Variables used in strings ($InfoVer, $OtherDir, ...) are declared in wol-manager.nsi and filled
; in right before the string is shown.

; ---------------------------------------------------------------- components
LangString SEC_PROGRAM ${LANG_ENGLISH} "${PRODUCT_NAME} (required)"
LangString SEC_PATH ${LANG_ENGLISH} "Add the wolm command to PATH"
LangString SEC_DESKTOP ${LANG_ENGLISH} "Desktop shortcut"
LangString DESC_PROGRAM ${LANG_ENGLISH} "The ${PRODUCT_NAME} application, the wolm command-line tool (${CLI_SUBDIR}\${CLI_EXE}) and a Start menu shortcut."
LangString DESC_PATH ${LANG_ENGLISH} "Adds the ${CLI_SUBDIR} folder to your PATH (the system PATH when installing for all users), so that wolm can be run from any newly opened terminal."
LangString DESC_DESKTOP ${LANG_ENGLISH} "Creates a ${PRODUCT_NAME} shortcut on the desktop."

; ---------------------------------------------------------------- scope page
LangString SCOPE_TITLE ${LANG_ENGLISH} "Choose Installation Scope"
LangString SCOPE_SUBTITLE ${LANG_ENGLISH} "Choose who can use ${PRODUCT_NAME} on this computer."
LangString SCOPE_PROMPT ${LANG_ENGLISH} "Install ${PRODUCT_NAME} ${VERSION} for:"
LangString SCOPE_USER ${LANG_ENGLISH} "Just me (no administrator rights needed)"
LangString SCOPE_USER_DESC ${LANG_ENGLISH} "Installs into your user profile (%LOCALAPPDATA%\Programs) and adds wolm to your user PATH."
LangString SCOPE_ALL ${LANG_ENGLISH} "All users of this computer (requires administrator approval)"
LangString SCOPE_ALL_DESC ${LANG_ENGLISH} "Installs into Program Files and adds wolm to the system PATH. Windows asks for approval once, when the installation starts."
LangString SCOPE_INFO_NEW ${LANG_ENGLISH} "${PRODUCT_NAME} is not installed for this option yet."
LangString SCOPE_INFO_UPGRADE ${LANG_ENGLISH} "Version $InfoVer is installed in $InfoDir.$\r$\nIt will be upgraded to ${VERSION}."
LangString SCOPE_INFO_SAME ${LANG_ENGLISH} "Version $InfoVer is already installed in $InfoDir.$\r$\nIt will be reinstalled."
LangString SCOPE_INFO_DOWNGRADE ${LANG_ENGLISH} "Version $InfoVer is installed in $InfoDir.$\r$\nInstalling ${VERSION} will downgrade it."
LangString SCOPE_INFO_OTHER ${LANG_ENGLISH} "${PRODUCT_NAME} $OtherVer is already installed for the other option (in $OtherDir). Choose that option to upgrade it, or uninstall it first."
LangString SCOPE_ELEVATED_WARN ${LANG_ENGLISH} "This installer is running with administrator rights. A $\"Just me$\" installation is made for the account that runs the installer, which may not be your usual account (for example with Administrator Protection, or when another administrator approved the prompt)."

; ---------------------------------------------------------------- message boxes
LangString MSG_REQ_OS ${LANG_ENGLISH} "${PRODUCT_NAME} requires 64-bit Windows 10 or later (x64), or Windows 11 on ARM64."
LangString MSG_BAD_SWITCHES ${LANG_ENGLISH} "/AllUsers and /CurrentUser cannot be used together."
LangString MSG_OTHER_SCOPE ${LANG_ENGLISH} "${PRODUCT_NAME} $OtherVer is already installed for the other option in:$\r$\n$OtherDir$\r$\n$\r$\nInstalling it both for just you and for all users is not supported. Choose the other option to upgrade that installation, or uninstall it first."
LangString MSG_UPGRADE_OTHER_DIR ${LANG_ENGLISH} "${PRODUCT_NAME} $InfoVer is already installed in:$\r$\n$InfoDir$\r$\n$\r$\nAn installation is upgraded in its own folder and cannot be moved to the folder given with /D=:$\r$\n$CmdInstDir$\r$\n$\r$\nTo install into that folder, uninstall ${PRODUCT_NAME} first.$\r$\n$\r$\nUpgrade the existing installation in its current folder?"
LangString MSG_DOWNGRADE ${LANG_ENGLISH} "A newer version of ${PRODUCT_NAME} ($InfoVer) is installed.$\r$\n$\r$\nDo you want to replace it with the older version ${VERSION}?"
LangString MSG_DIR_USER_PF ${LANG_ENGLISH} "A $\"Just me$\" installation cannot be placed in Program Files or in the Windows folder.$\r$\n$\r$\nChoose a folder in your user profile, or go back and choose $\"All users$\"."
LangString MSG_DIR_ALL_OUTSIDE_PF ${LANG_ENGLISH} "The selected folder is outside Program Files, where users without administrator rights can often modify programs.$\r$\n$\r$\nIf you continue, Setup allows only administrators to change this folder and everything in it.$\r$\n$\r$\nContinue?"
LangString MSG_DIR_ALL_OUTSIDE_PF_SILENT ${LANG_ENGLISH} "Installing for all users outside Program Files ($INSTDIR) requires the /AllowOutsideProgramFiles switch. Setup then allows only administrators to change that folder."
LangString MSG_DIR_LOCK_FAILED ${LANG_ENGLISH} "The permissions of $INSTDIR could not be restricted to administrators (the drive may not support permissions, e.g. FAT32). The installation was stopped. Choose a folder in Program Files."
LangString MSG_APP_RUNNING ${LANG_ENGLISH} "${PRODUCT_NAME} is running (it may be hidden in the notification area).$\r$\n$\r$\nClick OK to close it and continue, or Cancel to stop."
LangString MSG_APP_NOT_CLOSED ${LANG_ENGLISH} "${PRODUCT_NAME} did not close.$\r$\n$\r$\nClose it (including its notification area icon), then click Retry."
LangString MSG_FILE_IN_USE ${LANG_ENGLISH} "The following file is in use:$\r$\n$FileInUse$\r$\n$\r$\nClose ${PRODUCT_NAME} and any running wolm commands (also in other user sessions), then click Retry."
LangString MSG_UAC_DENIED ${LANG_ENGLISH} "Administrator approval is required to install ${PRODUCT_NAME} for all users.$\r$\n$\r$\nClick Retry to ask again, or Cancel to stop."
LangString MSG_UAC_DENIED_SHORT ${LANG_ENGLISH} "Administrator approval was not given."
LangString MSG_CHILD_FAILED ${LANG_ENGLISH} "The installation with administrator rights did not complete. ${PRODUCT_NAME} was not installed for all users."
LangString MSG_CHILD_IN_USE ${LANG_ENGLISH} "The installation with administrator rights could not replace the files in $INSTDIR: ${PRODUCT_NAME} or a wolm command is still running (possibly in another user session).$\r$\n$\r$\nClose them, then click Retry."
LangString MSG_FILES_FAILED ${LANG_ENGLISH} "Some files could not be written to $INSTDIR. The installation was stopped."
LangString MSG_UN_UAC_DENIED ${LANG_ENGLISH} "Administrator approval is required to uninstall ${PRODUCT_NAME} for all users.$\r$\n$\r$\nClick Retry to ask again, or Cancel to stop."

; ---------------------------------------------------------------- progress details
LangString DETAIL_CLOSING_APP ${LANG_ENGLISH} "Closing ${PRODUCT_NAME}..."
LangString DETAIL_ELEVATING ${LANG_ENGLISH} "Waiting for the installation with administrator rights..."
LangString DETAIL_ELEVATED_OK ${LANG_ENGLISH} "The installation with administrator rights completed."
LangString DETAIL_CHILD_START_FAILED ${LANG_ENGLISH} "Could not start the installation with administrator rights (error $ChildRc)."
LangString DETAIL_CHILD_EXIT ${LANG_ENGLISH} "The installation with administrator rights ended with exit code $ChildRc."
LangString DETAIL_DIR_LOCKING ${LANG_ENGLISH} "Allowing only administrators to change $INSTDIR..."
LangString DETAIL_PATH_ADDED ${LANG_ENGLISH} "Added $INSTDIR\${CLI_SUBDIR} to PATH. Open a new terminal window to use wolm."
LangString DETAIL_PATH_PRESENT ${LANG_ENGLISH} "$INSTDIR\${CLI_SUBDIR} is already on PATH."
LangString DETAIL_PATH_ADD_FAILED ${LANG_ENGLISH} "Warning: could not add $INSTDIR\${CLI_SUBDIR} to your PATH (wolm exit code: $PathRc). To add it later, run: $\"$INSTDIR\${CLI_SUBDIR}\${CLI_EXE}$\" path add --scope user"
LangString DETAIL_PATH_ADD_FAILED_MACHINE ${LANG_ENGLISH} "Warning: could not add $INSTDIR\${CLI_SUBDIR} to the system PATH (wolm exit code: $PathRc). To add it later, run this in a terminal started as administrator: $\"$INSTDIR\${CLI_SUBDIR}\${CLI_EXE}$\" path add --scope machine"
LangString DETAIL_PATH_REMOVED ${LANG_ENGLISH} "Removed $INSTDIR\${CLI_SUBDIR} from PATH."
LangString DETAIL_PATH_ABSENT ${LANG_ENGLISH} "$INSTDIR\${CLI_SUBDIR} was not on PATH."
LangString DETAIL_PATH_REMOVE_FAILED ${LANG_ENGLISH} "Warning: could not remove $INSTDIR\${CLI_SUBDIR} from PATH (wolm exit code: $PathRc). Remove it manually if it is still listed."
LangString DETAIL_WOLM_MISSING ${LANG_ENGLISH} "${CLI_EXE} was not found; PATH was not changed."
LangString DETAIL_SETTINGS_KEPT ${LANG_ENGLISH} "Your settings were kept in $APPDATA\${APPDATA_DIRNAME}."
LangString DETAIL_SETTINGS_KEPT_ALL ${LANG_ENGLISH} "The settings of each user (%APPDATA%\${APPDATA_DIRNAME}) were kept."
LangString DETAIL_SETTINGS_REMOVED ${LANG_ENGLISH} "Removed your settings ($APPDATA\${APPDATA_DIRNAME} and $LOCALAPPDATA\${APPDATA_DIRNAME})."

; ---------------------------------------------------------------- finish page
LangString FINISH_TEXT ${LANG_ENGLISH} "${PRODUCT_NAME} has been installed on your computer.$\r$\n$\r$\nTo use the wolm command, open a new terminal window.$\r$\n$\r$\nClick Finish to close Setup."

; ---------------------------------------------------------------- uninstaller
LangString UN_SEC_PROGRAM ${LANG_ENGLISH} "${PRODUCT_NAME}"
LangString UN_SEC_PURGE ${LANG_ENGLISH} "Remove my settings and host list"
LangString UN_DESC_PROGRAM ${LANG_ENGLISH} "Removes the program files, the shortcuts and the PATH entry."
LangString UN_DESC_PURGE ${LANG_ENGLISH} "Also deletes $APPDATA\${APPDATA_DIRNAME} and $LOCALAPPDATA\${APPDATA_DIRNAME}. Leave this unchecked to keep them for a later installation."
