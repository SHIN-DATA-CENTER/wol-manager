//! Low-level output: stdout / stderr lines (colors via anstream, which strips them for
//! `--no-color`, `NO_COLOR` and non-terminals), ASCII-only JSON, tables.
//!
//! Console output goes through `std::io::Stdout`, which writes UTF-16 with WriteConsoleW;
//! pipes and files get UTF-8. `SetConsoleOutputCP` is never called.

pub mod json;
pub mod table;

use std::borrow::Cow;
use std::io::Write;

use anstyle::{AnsiColor, Style};

pub use table::Table;

/// Bold.
pub const BOLD: Style = Style::new().bold();
/// Good / online.
pub const GREEN: Style = AnsiColor::Green.on_default();
/// Bad / offline.
pub const RED: Style = AnsiColor::Red.on_default();
/// Partial / warning.
pub const YELLOW: Style = AnsiColor::Yellow.on_default();
/// Secondary text.
pub const DIM: Style = Style::new().dimmed();
/// Error prefix.
pub const ERROR: Style = AnsiColor::Red.on_default().bold();
/// Warning prefix.
pub const WARNING: Style = AnsiColor::Yellow.on_default().bold();
/// Note prefix.
pub const NOTE: Style = AnsiColor::Cyan.on_default().bold();

/// `text` wrapped in `style` (the escapes are removed by anstream when colors are off).
pub fn paint(style: Style, text: &str) -> String {
    if style == Style::new() || text.is_empty() {
        return text.to_owned();
    }
    format!("{style}{text}{style:#}")
}

/// Shown instead of a control character that a terminal would act on.
const REPLACEMENT: char = '\u{FFFD}';

/// `true` for SGR parameters that [`paint`] writes with the styles above (reset, bold, dim,
/// red, green, yellow, cyan).
fn is_own_sgr(params: &str) -> bool {
    params
        .split(';')
        .all(|p| matches!(p, "" | "0" | "1" | "2" | "31" | "32" | "33" | "36"))
}

/// Makes a line safe for a terminal: every control character except line feed and tab (a
/// CR only when it ends a CR LF pair), DEL and the C1 controls, and every escape sequence
/// except the colors that [`paint`] writes, become U+FFFD. Host names, notes and error
/// texts come from the settings file or an import and are printed through here, so they
/// cannot set the window title, move the cursor, clear or hide text.
pub fn sanitize(line: &str) -> Cow<'_, str> {
    let unsafe_char = |c: char| c.is_control() && c != '\n' && c != '\t';
    if !line.chars().any(unsafe_char) {
        return Cow::Borrowed(line);
    }
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    while let Some(c) = rest.chars().next() {
        let mut take = c.len_utf8();
        if c == '\u{1b}' {
            if let Some(after) = rest.strip_prefix("\u{1b}[")
                && let Some(end) = after.find(|ch: char| !(ch.is_ascii_digit() || ch == ';'))
                && after[end..].starts_with('m')
                && is_own_sgr(&after[..end])
            {
                take = 2 + end + 1;
                out.push_str(&rest[..take]);
            } else {
                out.push(REPLACEMENT);
            }
        } else if c == '\r' && rest[1..].starts_with('\n') {
            // CR LF: the LF alone ends the line.
        } else if unsafe_char(c) {
            out.push(REPLACEMENT);
        } else {
            out.push(c);
        }
        rest = &rest[take..];
    }
    Cow::Owned(out)
}

/// One line on stdout ([`sanitize`]d). Write errors (closed pipe) are ignored.
pub fn stdout_line(line: &str) {
    let mut o = anstream::stdout().lock();
    let _ = writeln!(o, "{}", sanitize(line));
    let _ = o.flush();
}

/// One line on stderr ([`sanitize`]d).
pub fn stderr_line(line: &str) {
    let mut e = anstream::stderr().lock();
    let _ = writeln!(e, "{}", sanitize(line));
    let _ = e.flush();
}

/// Raw bytes on stdout (exported files).
pub fn stdout_bytes(bytes: &[u8]) {
    let mut o = std::io::stdout().lock();
    let _ = o.write_all(bytes);
    let _ = o.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn own_colors_survive() {
        for style in [BOLD, GREEN, RED, YELLOW, DIM, ERROR, WARNING, NOTE] {
            let p = paint(style, "text");
            assert_eq!(sanitize(&p), p, "{p:?}");
        }
    }

    #[test]
    fn terminal_controls_from_data_are_neutralized() {
        let evil = "evil\u{1b}]0;PWNED\u{7}\u{1b}[31mRED\u{1b}[8mhidden\u{1b}[2J\u{9b}1m\r!";
        let s = sanitize(evil);
        assert!(
            !s.contains('\u{1b}') || s.matches('\u{1b}').count() == 1,
            "{s:?}"
        );
        assert!(
            !s.contains('\u{7}') && !s.contains('\u{9b}') && !s.contains('\r'),
            "{s:?}"
        );
        // Only the plain red SGR (a color paint also writes) is kept.
        assert!(s.contains("\u{1b}[31mRED"), "{s:?}");
        assert!(!s.contains("\u{1b}[8m") && !s.contains("\u{1b}[2J") && !s.contains("\u{1b}]0"));
        assert_eq!(sanitize("a\r\nb\tc"), "a\nb\tc");
        assert!(matches!(sanitize("日本語 ok"), Cow::Borrowed(_)));
    }
}
