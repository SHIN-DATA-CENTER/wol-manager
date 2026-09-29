//! Locating and validating the coolicons v4.1 package at build time.

use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

/// Environment variable naming the extracted coolicons package directory.
/// `.cargo/config.toml` provides a default of `<workspace>/coolicons.v4.1`.
pub const ENV_COOLICONS_DIR: &str = "COOLICONS_DIR";

/// SVG folder names inside the package. The official release zip misspells the folder
/// ("cooliocns SVG"); the git tag archive uses the correct spelling.
const SVG_DIR_CANDIDATES: &[&str] = &["cooliocns SVG", "coolicons SVG"];

const FETCH_HINT: &str = "Run `powershell -ExecutionPolicy Bypass -File scripts\\fetch-coolicons.ps1` \
from the repository root, or set COOLICONS_DIR to an extracted coolicons v4.1 package.";

/// A single coolicons glyph, addressed like the upstream package: `<Category>/<Name>.svg`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IconRef {
    pub category: &'static str,
    pub name: &'static str,
}

impl IconRef {
    pub const fn new(category: &'static str, name: &'static str) -> Self {
        Self { category, name }
    }

    /// File name used for the copy inside `OUT_DIR` (flat, no spaces).
    pub fn flat_file_name(&self) -> String {
        format!("{}_{}.svg", self.category, self.name)
    }
}

/// A validated coolicons package.
#[derive(Debug, Clone)]
pub struct Coolicons {
    root: PathBuf,
    svg_dir: PathBuf,
}

impl Coolicons {
    /// Finds the package via `COOLICONS_DIR` (falling back to `<workspace>/coolicons.v4.1`)
    /// and emits the matching `rerun-if-env-changed` line.
    pub fn locate() -> Result<Self, String> {
        println!("cargo:rerun-if-env-changed={ENV_COOLICONS_DIR}");
        let root = match env::var_os(ENV_COOLICONS_DIR) {
            Some(v) if !v.is_empty() => PathBuf::from(v),
            _ => crate::workspace_root().join("coolicons.v4.1"),
        };
        Self::at(&root)
    }

    /// Validates a package rooted at `root`.
    pub fn at(root: &Path) -> Result<Self, String> {
        if !root.is_dir() {
            return Err(format!(
                "coolicons package not found at '{}'.\n{FETCH_HINT}",
                root.display()
            ));
        }
        let svg_dir = SVG_DIR_CANDIDATES
            .iter()
            .map(|d| root.join(d))
            .find(|p| p.is_dir())
            // Allow pointing COOLICONS_DIR directly at the SVG folder.
            .or_else(|| root.join("System").is_dir().then(|| root.to_path_buf()))
            .ok_or_else(|| {
                format!(
                    "'{}' does not look like a coolicons v4.1 package (no 'cooliocns SVG' or \
                     'coolicons SVG' folder).\n{FETCH_HINT}",
                    root.display()
                )
            })?;
        Ok(Self {
            root: root.to_path_buf(),
            svg_dir,
        })
    }

    /// Like [`Coolicons::locate`], but panics with an actionable message on failure.
    pub fn locate_or_panic() -> Self {
        Self::locate().unwrap_or_else(|e| panic!("\n\n{e}\n\n"))
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn svg_path(&self, icon: IconRef) -> PathBuf {
        self.svg_dir
            .join(icon.category)
            .join(format!("{}.svg", icon.name))
    }

    /// Checks that every icon exists, emits `rerun-if-changed` for each one and panics with
    /// a list of the missing files otherwise.
    pub fn require(&self, icons: &[IconRef]) {
        let mut missing = String::new();
        for icon in icons {
            let p = self.svg_path(*icon);
            println!("cargo:rerun-if-changed={}", p.display());
            if !p.is_file() {
                let _ = writeln!(missing, "  - {}/{}.svg", icon.category, icon.name);
            }
        }
        if !missing.is_empty() {
            panic!(
                "\n\nMissing coolicons files in '{}':\n{missing}{FETCH_HINT}\n\n",
                self.svg_dir.display()
            );
        }
    }

    /// Reads an icon's SVG source.
    pub fn read_svg(&self, icon: IconRef) -> String {
        let p = self.svg_path(icon);
        fs::read_to_string(&p).unwrap_or_else(|e| panic!("cannot read '{}': {e}", p.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_package(spelling: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let sys = dir.path().join(spelling).join("System");
        fs::create_dir_all(&sys).unwrap();
        // Hand-written test shape; not coolicons data.
        fs::write(
            sys.join("Test.svg"),
            r#"<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24"><rect x="4" y="4" width="16" height="16" stroke="currentColor" fill="none"/></svg>"#,
        )
        .unwrap();
        dir
    }

    #[test]
    fn finds_misspelled_release_folder() {
        let pkg = fake_package("cooliocns SVG");
        let c = Coolicons::at(pkg.path()).unwrap();
        assert!(c.svg_path(IconRef::new("System", "Test")).is_file());
    }

    #[test]
    fn finds_correctly_spelled_tag_folder() {
        let pkg = fake_package("coolicons SVG");
        let c = Coolicons::at(pkg.path()).unwrap();
        assert!(c.svg_path(IconRef::new("System", "Test")).is_file());
    }

    #[test]
    fn missing_package_mentions_fetch_script() {
        let err = Coolicons::at(Path::new("Z:\\definitely\\not\\here")).unwrap_err();
        assert!(err.contains("fetch-coolicons.ps1"));
    }

    #[test]
    fn flat_file_name_has_no_spaces_or_separators() {
        assert_eq!(
            IconRef::new("Communication", "Paper_Plane").flat_file_name(),
            "Communication_Paper_Plane.svg"
        );
    }
}
