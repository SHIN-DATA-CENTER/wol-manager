; installer\wol-manager.nsi の日本語文字列（UTF-8 BOM 付き・CRLF で保存すること）。
; English.nsh と同じ LangString をすべて定義する（1 つでも欠けると makensis /WX が失敗する）。

; ---------------------------------------------------------------- コンポーネント
LangString SEC_PROGRAM ${LANG_JAPANESE} "${PRODUCT_NAME}（必須）"
LangString SEC_PATH ${LANG_JAPANESE} "wolm コマンドを PATH に追加"
LangString SEC_DESKTOP ${LANG_JAPANESE} "デスクトップのショートカット"
LangString DESC_PROGRAM ${LANG_JAPANESE} "${PRODUCT_NAME} 本体、コマンドラインツール wolm（${CLI_SUBDIR}\${CLI_EXE}）、スタートメニューのショートカット。"
LangString DESC_PATH ${LANG_JAPANESE} "${CLI_SUBDIR} フォルダーを PATH（すべてのユーザー向けの場合はシステムの PATH）に追加し、新しく開いたターミナルから wolm を実行できるようにします。"
LangString DESC_DESKTOP ${LANG_JAPANESE} "デスクトップに ${PRODUCT_NAME} のショートカットを作成します。"

; ---------------------------------------------------------------- インストール範囲のページ
LangString SCOPE_TITLE ${LANG_JAPANESE} "インストールの範囲"
LangString SCOPE_SUBTITLE ${LANG_JAPANESE} "このコンピューターで ${PRODUCT_NAME} を使うユーザーを選んでください。"
LangString SCOPE_PROMPT ${LANG_JAPANESE} "${PRODUCT_NAME} ${VERSION} をインストールする範囲:"
LangString SCOPE_USER ${LANG_JAPANESE} "自分のみ（管理者権限は不要）"
LangString SCOPE_USER_DESC ${LANG_JAPANESE} "ユーザーのプロファイル（%LOCALAPPDATA%\Programs）にインストールし、wolm をユーザーの PATH に追加します。"
LangString SCOPE_ALL ${LANG_JAPANESE} "このコンピューターのすべてのユーザー（管理者の承認が必要）"
LangString SCOPE_ALL_DESC ${LANG_JAPANESE} "Program Files にインストールし、wolm をシステムの PATH に追加します。インストールの開始時に一度だけ承認を求められます。"
LangString SCOPE_INFO_NEW ${LANG_JAPANESE} "この範囲にはまだインストールされていません。"
LangString SCOPE_INFO_UPGRADE ${LANG_JAPANESE} "バージョン $InfoVer が $InfoDir にインストールされています。$\r$\n${VERSION} にアップグレードします。"
LangString SCOPE_INFO_SAME ${LANG_JAPANESE} "バージョン $InfoVer が $InfoDir にインストール済みです。$\r$\n同じバージョンを再インストールします。"
LangString SCOPE_INFO_DOWNGRADE ${LANG_JAPANESE} "バージョン $InfoVer が $InfoDir にインストールされています。$\r$\n${VERSION} をインストールするとダウングレードになります。"
LangString SCOPE_INFO_OTHER ${LANG_JAPANESE} "${PRODUCT_NAME} $OtherVer がもう一方の範囲（$OtherDir）にインストール済みです。アップグレードするにはそちらを選ぶか、先にアンインストールしてください。"
LangString SCOPE_ELEVATED_WARN ${LANG_JAPANESE} "このインストーラーは管理者権限で実行されています。「自分のみ」を選ぶと、インストーラーを実行しているアカウント向けにインストールされます。これは普段お使いのアカウントとは異なる場合があります（管理者保護が有効な場合や、別の管理者が承認した場合など）。"

; ---------------------------------------------------------------- メッセージボックス
LangString MSG_REQ_OS ${LANG_JAPANESE} "${PRODUCT_NAME} には 64 ビット版の Windows 10 以降（x64）、または ARM64 版の Windows 11 が必要です。"
LangString MSG_BAD_SWITCHES ${LANG_JAPANESE} "/AllUsers と /CurrentUser は同時に指定できません。"
LangString MSG_OTHER_SCOPE ${LANG_JAPANESE} "${PRODUCT_NAME} $OtherVer がもう一方の範囲に既にインストールされています:$\r$\n$OtherDir$\r$\n$\r$\n「自分のみ」と「すべてのユーザー」の両方へのインストールには対応していません。そのインストールをアップグレードするにはもう一方を選ぶか、先にアンインストールしてください。"
LangString MSG_UPGRADE_OTHER_DIR ${LANG_JAPANESE} "${PRODUCT_NAME} $InfoVer は次の場所に既にインストールされています:$\r$\n$InfoDir$\r$\n$\r$\nインストール済みの ${PRODUCT_NAME} はそのフォルダーでアップグレードされ、/D= で指定したフォルダーには移動できません:$\r$\n$CmdInstDir$\r$\n$\r$\nそのフォルダーにインストールするには、先に ${PRODUCT_NAME} をアンインストールしてください。$\r$\n$\r$\n現在のフォルダーのままアップグレードしますか？"
LangString MSG_DOWNGRADE ${LANG_JAPANESE} "新しいバージョンの ${PRODUCT_NAME}（$InfoVer）がインストールされています。$\r$\n$\r$\n古いバージョン ${VERSION} で置き換えますか？"
LangString MSG_DIR_USER_PF ${LANG_JAPANESE} "「自分のみ」のインストール先には Program Files や Windows フォルダーを指定できません。$\r$\n$\r$\nユーザーのプロファイル内のフォルダーを選ぶか、前の画面に戻って「すべてのユーザー」を選んでください。"
LangString MSG_DIR_ALL_OUTSIDE_PF ${LANG_JAPANESE} "選んだフォルダーは Program Files の外にあります。このような場所では、管理者権限のないユーザーでもプログラムを書き換えられることがよくあります。$\r$\n$\r$\n続けると、このフォルダーとその中のすべてのファイルを変更できるのは管理者だけになります。$\r$\n$\r$\n続けますか？"
LangString MSG_DIR_ALL_OUTSIDE_PF_SILENT ${LANG_JAPANESE} "Program Files の外（$INSTDIR）にすべてのユーザー向けにインストールするには、/AllowOutsideProgramFiles スイッチが必要です。その場合、このフォルダーを変更できるのは管理者だけになります。"
LangString MSG_DIR_LOCK_FAILED ${LANG_JAPANESE} "$INSTDIR を管理者だけが変更できるように設定できませんでした（FAT32 など、アクセス許可に対応していないドライブの可能性があります）。インストールを中止しました。Program Files 内のフォルダーを選んでください。"
LangString MSG_APP_RUNNING ${LANG_JAPANESE} "${PRODUCT_NAME} が実行中です（通知領域に格納されている場合があります）。$\r$\n$\r$\n[OK] で終了して続行します。[キャンセル] で中止します。"
LangString MSG_APP_NOT_CLOSED ${LANG_JAPANESE} "${PRODUCT_NAME} が終了しませんでした。$\r$\n$\r$\n通知領域のアイコンも含めて終了してから、[再試行] をクリックしてください。"
LangString MSG_FILE_IN_USE ${LANG_JAPANESE} "次のファイルが使用中です:$\r$\n$FileInUse$\r$\n$\r$\n${PRODUCT_NAME} と実行中の wolm コマンド（他のユーザーのセッションも含む）を終了してから、[再試行] をクリックしてください。"
LangString MSG_UAC_DENIED ${LANG_JAPANESE} "すべてのユーザー向けに ${PRODUCT_NAME} をインストールするには、管理者の承認が必要です。$\r$\n$\r$\n[再試行] でもう一度確認します。[キャンセル] で中止します。"
LangString MSG_UAC_DENIED_SHORT ${LANG_JAPANESE} "管理者の承認が得られませんでした。"
LangString MSG_CHILD_FAILED ${LANG_JAPANESE} "管理者権限でのインストールが完了しませんでした。すべてのユーザー向けの ${PRODUCT_NAME} はインストールされていません。"
LangString MSG_CHILD_IN_USE ${LANG_JAPANESE} "管理者権限でのインストールで $INSTDIR のファイルを置き換えられませんでした。${PRODUCT_NAME} または wolm コマンドが実行中です（他のユーザーのセッションの場合もあります）。$\r$\n$\r$\nそれらを終了してから、[再試行] をクリックしてください。"
LangString MSG_FILES_FAILED ${LANG_JAPANESE} "$INSTDIR に書き込めないファイルがありました。インストールを中止しました。"
LangString MSG_UN_UAC_DENIED ${LANG_JAPANESE} "すべてのユーザー向けの ${PRODUCT_NAME} をアンインストールするには、管理者の承認が必要です。$\r$\n$\r$\n[再試行] でもう一度確認します。[キャンセル] で中止します。"

; ---------------------------------------------------------------- 進行状況の詳細
LangString DETAIL_CLOSING_APP ${LANG_JAPANESE} "${PRODUCT_NAME} を終了しています..."
LangString DETAIL_ELEVATING ${LANG_JAPANESE} "管理者権限でのインストールが終わるのを待っています..."
LangString DETAIL_ELEVATED_OK ${LANG_JAPANESE} "管理者権限でのインストールが完了しました。"
LangString DETAIL_CHILD_START_FAILED ${LANG_JAPANESE} "管理者権限でのインストールを開始できませんでした（エラー $ChildRc）。"
LangString DETAIL_CHILD_EXIT ${LANG_JAPANESE} "管理者権限でのインストールが終了コード $ChildRc で終了しました。"
LangString DETAIL_DIR_LOCKING ${LANG_JAPANESE} "$INSTDIR を管理者だけが変更できるように設定しています..."
LangString DETAIL_PATH_ADDED ${LANG_JAPANESE} "$INSTDIR\${CLI_SUBDIR} を PATH に追加しました。wolm を使うには新しいターミナルを開いてください。"
LangString DETAIL_PATH_PRESENT ${LANG_JAPANESE} "$INSTDIR\${CLI_SUBDIR} は既に PATH に含まれています。"
LangString DETAIL_PATH_ADD_FAILED ${LANG_JAPANESE} "警告: $INSTDIR\${CLI_SUBDIR} をユーザーの PATH に追加できませんでした（wolm の終了コード: $PathRc）。後で追加するには次を実行してください: $\"$INSTDIR\${CLI_SUBDIR}\${CLI_EXE}$\" path add --scope user"
LangString DETAIL_PATH_ADD_FAILED_MACHINE ${LANG_JAPANESE} "警告: $INSTDIR\${CLI_SUBDIR} をシステムの PATH に追加できませんでした（wolm の終了コード: $PathRc）。後で追加するには、管理者として開いたターミナルで次を実行してください: $\"$INSTDIR\${CLI_SUBDIR}\${CLI_EXE}$\" path add --scope machine"
LangString DETAIL_PATH_REMOVED ${LANG_JAPANESE} "$INSTDIR\${CLI_SUBDIR} を PATH から削除しました。"
LangString DETAIL_PATH_ABSENT ${LANG_JAPANESE} "$INSTDIR\${CLI_SUBDIR} は PATH に含まれていませんでした。"
LangString DETAIL_PATH_REMOVE_FAILED ${LANG_JAPANESE} "警告: $INSTDIR\${CLI_SUBDIR} を PATH から削除できませんでした（wolm の終了コード: $PathRc）。残っている場合は手動で削除してください。"
LangString DETAIL_WOLM_MISSING ${LANG_JAPANESE} "${CLI_EXE} が見つからないため、PATH は変更しませんでした。"
LangString DETAIL_SETTINGS_KEPT ${LANG_JAPANESE} "設定は $APPDATA\${APPDATA_DIRNAME} に残しました。"
LangString DETAIL_SETTINGS_KEPT_ALL ${LANG_JAPANESE} "各ユーザーの設定（%APPDATA%\${APPDATA_DIRNAME}）は残しました。"
LangString DETAIL_SETTINGS_REMOVED ${LANG_JAPANESE} "設定を削除しました（$APPDATA\${APPDATA_DIRNAME} と $LOCALAPPDATA\${APPDATA_DIRNAME}）。"

; ---------------------------------------------------------------- 完了ページ
LangString FINISH_TEXT ${LANG_JAPANESE} "${PRODUCT_NAME} のインストールが完了しました。$\r$\n$\r$\nwolm コマンドを使うには、新しいターミナルを開いてください。$\r$\n$\r$\n[完了] をクリックするとセットアップを閉じます。"

; ---------------------------------------------------------------- アンインストーラー
LangString UN_SEC_PROGRAM ${LANG_JAPANESE} "${PRODUCT_NAME}"
LangString UN_SEC_PURGE ${LANG_JAPANESE} "設定とホストの一覧も削除する"
LangString UN_DESC_PROGRAM ${LANG_JAPANESE} "プログラムのファイル、ショートカット、PATH のエントリを削除します。"
LangString UN_DESC_PURGE ${LANG_JAPANESE} "$APPDATA\${APPDATA_DIRNAME} と $LOCALAPPDATA\${APPDATA_DIRNAME} も削除します。後で再インストールするときのために残す場合は、チェックを外したままにしてください。"
