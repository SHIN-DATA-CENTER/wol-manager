//! Embedding the icon, VERSIONINFO and application manifest into an executable.

use std::path::Path;

/// Which executable is being built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExeKind {
    Gui,
    Console,
}

const GUI_MANIFEST: &str = include_str!("manifests/gui.manifest.xml");
const CONSOLE_MANIFEST: &str = include_str!("manifests/console.manifest.xml");

/// Embeds `icon` plus version information and the manifest for `kind`.
///
/// Does nothing when not targeting Windows. Panics with the underlying error otherwise,
/// because a silently missing manifest or icon would be hard to notice.
pub fn embed(kind: ExeKind, icon: &Path, file_description: &str, original_filename: &str) {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let mut res = winresource::WindowsResource::new();
    res.set_icon(
        icon.to_str()
            .expect("icon path must be valid UTF-8 for the resource compiler"),
    )
    .set("ProductName", "WoL Manager")
    .set("CompanyName", "SHIN DATA CENTER")
    .set("FileDescription", file_description)
    .set("OriginalFilename", original_filename)
    .set("InternalName", original_filename.trim_end_matches(".exe"))
    .set(
        "LegalCopyright",
        "Copyright (c) SHIN DATA CENTER. Apache-2.0. Icons: coolicons (CC BY 4.0).",
    )
    .set_manifest(match kind {
        ExeKind::Gui => GUI_MANIFEST,
        ExeKind::Console => CONSOLE_MANIFEST,
    });
    if let Err(e) = res.compile() {
        panic!("failed to compile Windows resources: {e}");
    }
}
