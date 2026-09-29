//! Build-script helpers shared by the `wol-manager` (GUI) and `wolm` (CLI) packages.
//!
//! Everything derived from coolicons is produced inside `OUT_DIR` at build time and
//! embedded into the executables. Nothing generated here may ever be committed: the
//! coolicons package is CC BY 4.0 third-party material that is kept out of the repository.

pub mod coolicons;
pub mod icon;
pub mod slint_gen;
pub mod winres;

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub use coolicons::{Coolicons, IconRef};

/// Writes `contents` to `path` only if the file does not already hold exactly these bytes.
///
/// Files that slint-build lists in `rerun-if-changed` must keep their mtime when nothing
/// changed, otherwise every `cargo build` would re-run the build script.
/// Returns `true` when the file was (re)written.
pub fn write_if_changed(path: &Path, contents: &[u8]) -> io::Result<bool> {
    if let Ok(existing) = fs::read(path)
        && existing == contents
    {
        return Ok(false);
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, contents)?;
    Ok(true)
}

/// `OUT_DIR` of the running build script.
pub fn out_dir() -> PathBuf {
    PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR is only set for build scripts"))
}

/// `CARGO_MANIFEST_DIR` of the running build script.
pub fn manifest_dir() -> PathBuf {
    PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is only set by cargo"),
    )
}

/// Workspace root, assuming the `crates/<name>` layout.
pub fn workspace_root() -> PathBuf {
    let manifest = manifest_dir();
    manifest
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_if_changed_skips_identical_content() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a").join("b.txt");
        assert!(write_if_changed(&p, b"hello").unwrap());
        assert!(!write_if_changed(&p, b"hello").unwrap());
        assert!(write_if_changed(&p, b"world").unwrap());
        assert_eq!(fs::read(&p).unwrap(), b"world");
    }
}
