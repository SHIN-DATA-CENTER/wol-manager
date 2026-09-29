//! Keeps `wol_core::consts` in sync with `[workspace.metadata.wol]` in the root Cargo.toml,
//! which scripts/build.ps1 passes to the NSIS installer.

use wol_core::consts;

fn metadata() -> toml::Table {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.toml");
    let text = std::fs::read_to_string(path).expect("read workspace Cargo.toml");
    let doc: toml::Table = toml::from_str(&text).expect("parse workspace Cargo.toml");
    doc["workspace"]["metadata"]["wol"]
        .as_table()
        .expect("[workspace.metadata.wol]")
        .clone()
}

#[test]
fn workspace_metadata_matches_consts() {
    let m = metadata();
    let get = |k: &str| {
        m.get(k)
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("missing metadata key {k}"))
            .to_owned()
    };
    assert_eq!(get("product-name"), consts::PRODUCT_NAME);
    assert_eq!(get("publisher"), consts::PUBLISHER);
    assert_eq!(get("app-dir-name"), consts::APP_DIR_NAME);
    assert_eq!(get("install-dir-name"), consts::INSTALL_DIR_NAME);
    assert_eq!(get("uninstall-key"), consts::UNINSTALL_KEY_NAME);
    assert_eq!(get("gui-exe"), consts::GUI_EXE);
    assert_eq!(get("cli-exe"), consts::CLI_EXE);
    assert_eq!(get("cli-subdir"), consts::CLI_SUBDIR);
    assert_eq!(get("portable-marker"), consts::PORTABLE_MARKER);
    assert_eq!(get("portable-data-dir"), consts::PORTABLE_DATA_DIR);
    assert_eq!(get("installed-sentinel"), consts::INSTALLED_SENTINEL);
    assert_eq!(get("gui-mutex"), consts::GUI_MUTEX);
    assert_eq!(get("gui-show-event"), consts::GUI_SHOW_EVENT);
    assert_eq!(get("gui-quit-event"), consts::GUI_QUIT_EVENT);
}

#[test]
fn event_names_derive_from_mutex() {
    assert_eq!(
        consts::GUI_SHOW_EVENT,
        format!("{}.show", consts::GUI_MUTEX)
    );
    assert_eq!(
        consts::GUI_QUIT_EVENT,
        format!("{}.quit", consts::GUI_MUTEX)
    );
    assert_eq!(
        consts::GUI_SETTINGS_MAP,
        format!("{}.settings", consts::GUI_MUTEX)
    );
}

/// The installer writes the uninstaller under the name that marks an installed copy.
#[test]
fn installer_uses_the_shared_names() {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../");
    let build = std::fs::read_to_string(format!("{root}scripts/build.ps1")).unwrap();
    assert!(build.contains("installed-sentinel"), "build.ps1");
    assert!(build.contains("/DUNINSTALLER_EXE="), "build.ps1");
    for f in [
        "installer/wol-manager.nsi",
        "installer/include/elevate.nsh",
        "installer/lang/English.nsh",
        "installer/lang/Japanese.nsh",
    ] {
        let text = std::fs::read_to_string(format!("{root}{f}")).unwrap();
        // The literal names appear only where the defines are declared.
        let subdir = format!("\\{}", consts::CLI_SUBDIR);
        let has_subdir = |l: &str| {
            l.match_indices(&subdir).any(|(i, _)| {
                l[i + subdir.len()..]
                    .chars()
                    .next()
                    .is_none_or(|c| !c.is_alphanumeric() && c != '_')
            })
        };
        let literal = text
            .lines()
            .filter(|l| !l.trim_start().starts_with(';') && !l.contains("!define /ifndef"))
            .filter(|l| {
                l.contains(consts::INSTALLED_SENTINEL)
                    || l.contains(consts::CLI_EXE)
                    || has_subdir(l)
            })
            .collect::<Vec<_>>();
        assert!(
            literal.is_empty(),
            "{f} hard-codes shared names: {literal:#?}"
        );
    }
}
