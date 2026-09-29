//! The real registry backend (winreg 0.56 raw values, type preserved) and the
//! `WM_SETTINGCHANGE` broadcast.

use std::io;

use windows_sys::Win32::UI::WindowsAndMessaging::{
    HWND_BROADCAST, SMTO_ABORTIFHUNG, SendMessageTimeoutW, WM_SETTINGCHANGE,
};
use winreg::enums::{
    HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_SET_VALUE, REG_EXPAND_SZ, REG_SZ,
};
use winreg::{RegKey, RegValue};

use super::{EnvBackend, PathValue, Scope, ValueKind};
use crate::error::{Error, Result};
use crate::sys::to_wide;

const USER_KEY: &str = "Environment";
const MACHINE_KEY: &str = r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment";
const VALUE_NAME: &str = "Path";

/// `HKCU\Environment` / `HKLM\...\Session Manager\Environment`, value `Path`.
#[derive(Debug, Clone, Copy, Default)]
pub struct RegistryBackend;

fn location(scope: Scope) -> (RegKey, &'static str) {
    match scope {
        Scope::User => (RegKey::predef(HKEY_CURRENT_USER), USER_KEY),
        Scope::Machine => (RegKey::predef(HKEY_LOCAL_MACHINE), MACHINE_KEY),
    }
}

fn access_denied(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::PermissionDenied || e.raw_os_error() == Some(5)
}

/// Decodes REG_SZ / REG_EXPAND_SZ bytes (UTF-16LE; odd trailing byte and NULs dropped).
pub(crate) fn decode_utf16(bytes: &[u8]) -> String {
    let (pairs, _odd) = bytes.as_chunks::<2>();
    let mut units: Vec<u16> = pairs.iter().map(|c| u16::from_le_bytes(*c)).collect();
    while units.last() == Some(&0) {
        units.pop();
    }
    String::from_utf16_lossy(&units)
}

/// Encodes a string as UTF-16LE with one terminating NUL.
pub(crate) fn encode_utf16(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .chain(std::iter::once(0))
        .flat_map(u16::to_le_bytes)
        .collect()
}

impl EnvBackend for RegistryBackend {
    fn read(&self, scope: Scope) -> Result<Option<PathValue>> {
        let (root, path) = location(scope);
        let key = match root.open_subkey_with_flags(path, KEY_READ) {
            Ok(k) => k,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(Error::Registry {
                    op: "open",
                    source: e,
                });
            }
        };
        let v = match key.get_raw_value(VALUE_NAME) {
            Ok(v) => v,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(Error::Registry {
                    op: "read",
                    source: e,
                });
            }
        };
        let kind = match v.vtype {
            REG_EXPAND_SZ => ValueKind::ExpandString,
            REG_SZ => ValueKind::String,
            _ => {
                return Err(Error::Registry {
                    op: "read",
                    source: io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Path is neither REG_SZ nor REG_EXPAND_SZ",
                    ),
                });
            }
        };
        Ok(Some(PathValue {
            value: decode_utf16(&v.bytes),
            kind,
        }))
    }

    fn write(&self, scope: Scope, value: &PathValue) -> Result<()> {
        let (root, path) = location(scope);
        let map = |op, e: io::Error| {
            if access_denied(&e) {
                Error::ElevationRequired
            } else {
                Error::Registry { op, source: e }
            }
        };
        let key = match root.open_subkey_with_flags(path, KEY_READ | KEY_SET_VALUE) {
            Ok(k) => k,
            Err(e) if e.kind() == io::ErrorKind::NotFound && scope == Scope::User => {
                root.create_subkey(path).map_err(|e| map("create", e))?.0
            }
            Err(e) => return Err(map("open", e)),
        };
        let vtype = match value.kind {
            ValueKind::ExpandString => REG_EXPAND_SZ,
            ValueKind::String => REG_SZ,
        };
        let raw = RegValue {
            bytes: encode_utf16(&value.value).into(),
            vtype,
        };
        key.set_raw_value(VALUE_NAME, &raw)
            .map_err(|e| map("write", e))
    }

    fn broadcast(&self) -> bool {
        broadcast_environment_change()
    }
}

/// Sends `WM_SETTINGCHANGE` with `"Environment"` to all top-level windows
/// (`SMTO_ABORTIFHUNG`, 1000 ms per window) so Explorer picks up the new PATH.
/// **Blocking**: usually milliseconds, up to about 1 s per slow window.
pub fn broadcast_environment_change() -> bool {
    let env = to_wide("Environment");
    let mut result: usize = 0;
    // SAFETY: `env` is a NUL-terminated UTF-16 string that outlives the call.
    let r = unsafe {
        SendMessageTimeoutW(
            HWND_BROADCAST,
            WM_SETTINGCHANGE,
            0,
            env.as_ptr() as isize,
            SMTO_ABORTIFHUNG,
            1000,
            &mut result,
        )
    };
    r != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf16_round_trip() {
        let s = r"C:\Users\太郎\bin;%USERPROFILE%\x";
        let b = encode_utf16(s);
        assert_eq!(b.len() % 2, 0);
        assert_eq!(&b[b.len() - 2..], &[0, 0]);
        assert_eq!(decode_utf16(&b), s);
        // Odd length and several NULs are tolerated.
        let mut odd = b.clone();
        odd.extend_from_slice(&[0, 0, 0]);
        assert_eq!(decode_utf16(&odd), s);
    }
    // The real registry is deliberately never accessed by tests.
}
