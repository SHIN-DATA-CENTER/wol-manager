//! Questions on the console: y/N confirmations, a number, hidden passwords, and passwords read
//! from stdin (`--password-stdin`).
//!
//! wolm asks only when stdin is a console ([`stdin_is_console`]); scripts, pipes, scheduled
//! tasks and installers must pass `--yes` / `--pick` / `--password-stdin` instead. Prompts go
//! to stderr, so stdout stays data only.

use std::io::{BufRead, Read, Write};

use wol_core::normalize::normalize_input;
use zeroize::Zeroizing;

use crate::output;

/// `true` when stdin is an interactive console (`GetConsoleMode` succeeds on the standard
/// input handle). Pipes, files, NUL and a closed stdin are not.
pub fn stdin_is_console() -> bool {
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::System::Console::{GetConsoleMode, GetStdHandle, STD_INPUT_HANDLE};
    // SAFETY: GetStdHandle returns this process's handle (or null / invalid, checked);
    // GetConsoleMode only writes the mode into a local.
    unsafe {
        let h = GetStdHandle(STD_INPUT_HANDLE);
        if h.is_null() || h == INVALID_HANDLE_VALUE {
            return false;
        }
        let mut mode = 0u32;
        GetConsoleMode(h, &mut mode) != 0
    }
}

fn write_prompt(prompt: &str) {
    let mut e = std::io::stderr().lock();
    let _ = write!(e, "{}", output::sanitize(prompt));
    let _ = e.flush();
}

/// Prints `prompt` on stderr and reads one line from stdin (`None` at the end of input).
pub fn ask(prompt: &str) -> Option<String> {
    write_prompt(prompt);
    let mut line = String::new();
    match std::io::stdin().lock().read_line(&mut line) {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(line.trim().to_owned()),
    }
}

/// `y`, `yes`, `はい` (full-width and any case accepted).
pub fn is_yes(answer: &str) -> bool {
    let a = normalize_input(answer).trim().to_lowercase();
    matches!(a.as_str(), "y" | "yes" | "はい")
}

/// Asks a y/N question; anything but yes (also the end of input) is no.
pub fn confirm(prompt: &str) -> bool {
    ask(prompt).is_some_and(|a| is_yes(&a))
}

/// Asks for a number in `1..=max`; `None` for an empty answer, the end of input or an
/// invalid number.
pub fn ask_number(prompt: &str, max: usize) -> Option<usize> {
    let a = ask(prompt)?;
    let n: usize = normalize_input(&a).trim().parse().ok()?;
    (1..=max).contains(&n).then_some(n)
}

/// Prints `prompt` on stderr and reads a password from the console without echo.
pub fn password(prompt: &str) -> std::io::Result<Zeroizing<String>> {
    write_prompt(prompt);
    rpassword::read_password().map(Zeroizing::new)
}

/// Largest `--password-stdin` input.
pub const STDIN_SECRET_MAX: usize = 64 * 1024;

/// Why `--password-stdin` input was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StdinSecretError {
    /// More than [`STDIN_SECRET_MAX`] bytes.
    TooLong,
    /// Not UTF-8 (or UTF-16 with BOM).
    NotText,
    /// Empty after removing the line break.
    Empty,
    /// A line break inside the password.
    LineBreak,
    /// stdin could not be read.
    Io,
}

/// Decodes `--password-stdin` input: UTF-8 (BOM removed) or UTF-16LE with BOM; exactly one
/// trailing line break (`\n` or `\r\n`) is removed; empty input and inner line breaks are
/// refused.
pub fn secret_from_bytes(bytes: &[u8]) -> Result<Zeroizing<String>, StdinSecretError> {
    let text: Zeroizing<String> = if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        if rest.len() % 2 != 0 {
            return Err(StdinSecretError::NotText);
        }
        let units: Zeroizing<Vec<u16>> = Zeroizing::new(
            rest.as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes(*c))
                .collect(),
        );
        Zeroizing::new(String::from_utf16(&units).map_err(|_| StdinSecretError::NotText)?)
    } else {
        let rest = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
        Zeroizing::new(
            std::str::from_utf8(rest)
                .map_err(|_| StdinSecretError::NotText)?
                .to_owned(),
        )
    };
    let s: &str = &text;
    let s = s
        .strip_suffix("\r\n")
        .or_else(|| s.strip_suffix('\n'))
        .unwrap_or(s);
    if s.is_empty() {
        return Err(StdinSecretError::Empty);
    }
    if s.contains(['\r', '\n']) {
        return Err(StdinSecretError::LineBreak);
    }
    Ok(Zeroizing::new(s.to_owned()))
}

/// Reads `--password-stdin` (see [`secret_from_bytes`]).
pub fn read_secret_stdin() -> Result<Zeroizing<String>, StdinSecretError> {
    let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
    std::io::stdin()
        .lock()
        .take(STDIN_SECRET_MAX as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|_| StdinSecretError::Io)?;
    if buf.len() > STDIN_SECRET_MAX {
        return Err(StdinSecretError::TooLong);
    }
    secret_from_bytes(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yes_answers() {
        for a in ["y", "Y", "yes", " YES ", "ｙ", "はい"] {
            assert!(is_yes(a), "{a}");
        }
        for a in ["", "n", "no", "yess", "いいえ"] {
            assert!(!is_yes(a), "{a}");
        }
    }

    #[test]
    fn stdin_secrets() {
        let ok = |b: &[u8]| secret_from_bytes(b).map(|s| s.to_string());
        assert_eq!(ok(b"pw\n").unwrap(), "pw");
        assert_eq!(ok(b"pw\r\n").unwrap(), "pw");
        assert_eq!(ok(b"pw").unwrap(), "pw");
        assert_eq!(ok(b" pw with spaces \n").unwrap(), " pw with spaces ");
        assert_eq!(ok("\u{feff}p\u{e4}ss\n".as_bytes()).unwrap(), "p\u{e4}ss");
        let utf16: Vec<u8> = [0xFF, 0xFE]
            .into_iter()
            .chain("pw\u{65e5}\r\n".encode_utf16().flat_map(u16::to_le_bytes))
            .collect();
        assert_eq!(ok(&utf16).unwrap(), "pw\u{65e5}");
        assert_eq!(ok(b"\n"), Err(StdinSecretError::Empty));
        assert_eq!(ok(b""), Err(StdinSecretError::Empty));
        assert_eq!(ok(b"a\nb\n"), Err(StdinSecretError::LineBreak));
        assert_eq!(ok(b"pw\n\n"), Err(StdinSecretError::LineBreak));
        assert_eq!(ok(&[0xC3, 0x28]), Err(StdinSecretError::NotText));
    }
}
