//! ASCII-only JSON: every non-ASCII character is written as `\uXXXX` (UTF-16, surrogate
//! pairs for characters outside the BMP), so PowerShell 5.1 `ConvertFrom-Json` and NSIS
//! read it correctly whatever the console code page is.

use std::fmt::Write as _;

use serde::Serialize;

/// Replaces non-ASCII characters by `\uXXXX` escapes. Valid on serde_json output because
/// non-ASCII characters can only occur inside JSON strings.
pub fn escape_non_ascii(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii() {
            out.push(c);
        } else {
            let mut buf = [0u16; 2];
            for unit in c.encode_utf16(&mut buf) {
                let _ = write!(out, "\\u{unit:04x}");
            }
        }
    }
    out
}

/// The `--json` error line: `{"error":{"kind":..,"message":..,"exit_code":..}}`.
pub fn error_line(kind: &str, message: &str, exit_code: u8) -> String {
    #[derive(Serialize)]
    struct E<'a> {
        kind: &'a str,
        message: &'a str,
        exit_code: u8,
    }
    #[derive(Serialize)]
    struct Doc<'a> {
        error: E<'a>,
    }
    to_line(&Doc {
        error: E {
            kind,
            message,
            exit_code,
        },
    })
}

/// Pretty-printed, ASCII-only.
pub fn to_pretty(value: &impl Serialize) -> String {
    match serde_json::to_string_pretty(value) {
        Ok(s) => escape_non_ascii(&s),
        Err(e) => {
            escape_non_ascii(&serde_json::json!({ "serialize_error": e.to_string() }).to_string())
        }
    }
}

/// Single line, ASCII-only.
pub fn to_line(value: &impl Serialize) -> String {
    match serde_json::to_string(value) {
        Ok(s) => escape_non_ascii(&s),
        Err(e) => {
            escape_non_ascii(&serde_json::json!({ "serialize_error": e.to_string() }).to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_bmp_and_astral_characters() {
        let v = serde_json::json!({ "name": "書斎の NAS", "emoji": "\u{1F600}", "plain": "a\"b" });
        let s = to_line(&v);
        assert!(s.is_ascii(), "{s}");
        assert!(s.contains("\\u66f8\\u658e"));
        assert!(s.contains("\\ud83d\\ude00"));
        let back: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(back, v);
        let p = to_pretty(&v);
        assert!(p.is_ascii());
        assert_eq!(serde_json::from_str::<serde_json::Value>(&p).unwrap(), v);
    }
}
