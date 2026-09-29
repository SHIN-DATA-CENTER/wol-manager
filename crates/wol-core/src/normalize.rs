//! Input normalization for Japanese IME users.
//!
//! Technical fields (MAC, IP, port, targets) are typed in plain text boxes where a Japanese
//! IME in full-width mode produces `１９２．１６８．０．１`, `ＡＡ：ＢＢ`, `ー` for `-`, or the
//! ideographic space. [`normalize_input`] folds all of that to ASCII. When the IME is in
//! hiragana mode hex letters become kana (`a` → `あ`), which cannot be recovered;
//! [`check_technical`] reports that as [`FieldIssue::ImeKana`].
//!
//! Names are never rewritten; they are only compared through [`name_key`].

use std::borrow::Cow;

use crate::error::FieldIssue;

/// Maps one character of technical input to its ASCII replacement, if any.
fn fold_char(c: char, list: bool) -> Option<char> {
    match c {
        // Full-width ASCII block (！ .. ～).
        '\u{FF01}'..='\u{FF5E}' => char::from_u32(c as u32 - 0xFF01 + 0x21),
        // Ideographic space, no-break space.
        '\u{3000}' | '\u{00A0}' => Some(' '),
        // Dashes and prolonged sound marks an IME may produce for '-'.
        '\u{30FC}' | '\u{FF70}' | '\u{2010}' | '\u{2011}' | '\u{2012}' | '\u{2013}'
        | '\u{2014}' | '\u{2015}' | '\u{2212}' | '\u{FE63}' => Some('-'),
        // Ideographic / half-width full stop.
        '\u{3002}' | '\u{FF61}' => Some('.'),
        // Ideographic / half-width comma, only in list fields.
        '\u{3001}' | '\u{FF64}' if list => Some(','),
        _ => None,
    }
}

fn fold(s: &str, list: bool) -> Cow<'_, str> {
    if !s.chars().any(|c| fold_char(c, list).is_some()) {
        return Cow::Borrowed(s);
    }
    Cow::Owned(s.chars().map(|c| fold_char(c, list).unwrap_or(c)).collect())
}

/// Folds full-width ASCII to half-width, U+3000 / NBSP to a space, the various dashes
/// (`ー ｰ ‐ ‑ ‒ – — ― − ﹣`) to `-` and `。｡` to `.`.
///
/// For single-value technical fields (MAC, IPv4, port, SecureOn). Does not trim.
pub fn normalize_input(s: &str) -> Cow<'_, str> {
    fold(s, false)
}

/// Like [`normalize_input`], and additionally maps `、` / `､` to `,`.
///
/// For list fields (targets, TCP ports, interfaces).
pub fn normalize_list_input(s: &str) -> Cow<'_, str> {
    fold(s, true)
}

/// `true` for hiragana, katakana (full and half width) and CJK ideographs.
pub fn is_kana_or_cjk(c: char) -> bool {
    matches!(c,
        '\u{3040}'..='\u{309F}'   // Hiragana
        | '\u{30A0}'..='\u{30FF}' // Katakana
        | '\u{31F0}'..='\u{31FF}' // Katakana phonetic extensions
        | '\u{FF66}'..='\u{FF9F}' // Half-width katakana
        | '\u{3400}'..='\u{4DBF}' // CJK extension A
        | '\u{4E00}'..='\u{9FFF}' // CJK unified ideographs
    )
}

/// `true` when `s` contains kana or CJK characters (checked after [`normalize_input`], so
/// `ー` used as a dash does not count).
pub fn contains_kana(s: &str) -> bool {
    normalize_input(s).chars().any(is_kana_or_cjk)
}

/// Normalizes and trims a single-value technical field.
///
/// Returns [`FieldIssue::ImeKana`] when kana / CJK remain. An empty result is returned as
/// `Ok("")`; callers decide whether the field is required.
pub fn check_technical(s: &str) -> Result<String, FieldIssue> {
    let n = normalize_input(s);
    let t = n.trim();
    if t.chars().any(is_kana_or_cjk) {
        return Err(FieldIssue::ImeKana);
    }
    Ok(t.to_owned())
}

/// Like [`check_technical`] for list fields (also folds `、` to `,`).
pub fn check_technical_list(s: &str) -> Result<String, FieldIssue> {
    let n = normalize_list_input(s);
    let t = n.trim();
    if t.chars().any(is_kana_or_cjk) {
        return Err(FieldIssue::ImeKana);
    }
    Ok(t.to_owned())
}

/// Folds only width: full-width ASCII → ASCII and U+3000 → space. Kana, `ー` etc. are kept.
pub fn fold_width(s: &str) -> Cow<'_, str> {
    let needs = s
        .chars()
        .any(|c| matches!(c, '\u{FF01}'..='\u{FF5E}' | '\u{3000}'));
    if !needs {
        return Cow::Borrowed(s);
    }
    Cow::Owned(
        s.chars()
            .map(|c| match c {
                '\u{FF01}'..='\u{FF5E}' => char::from_u32(c as u32 - 0xFF01 + 0x21).unwrap_or(c),
                '\u{3000}' => ' ',
                _ => c,
            })
            .collect(),
    )
}

/// Comparison key for host / group names: width-folded, trimmed, lowercased.
///
/// `ＮＡＳ`, `nas` and ` NAS ` all have the same key. Used for uniqueness checks,
/// [`crate::model::Config::find`] and import matching.
pub fn name_key(s: &str) -> String {
    fold_width(s).trim().to_lowercase()
}

/// Search key for GUI filtering: width-folded and lowercased (not trimmed, so the caller can
/// search for a substring that contains spaces).
pub fn search_key(s: &str) -> String {
    fold_width(s).to_lowercase()
}

/// Removes control characters (tabs, newlines...) by replacing them with a space, and trims.
/// Used for single-line text such as host and group names.
pub fn clean_single_line(s: &str) -> String {
    let replaced: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    replaced.trim().to_owned()
}

/// Cleans multi-line text such as host notes: keeps line breaks (CR LF and CR become LF) and
/// tabs, drops every other control character (ESC, BEL, DEL, C1 controls...), so that text
/// from an import or another program cannot carry terminal escape sequences. Trailing
/// whitespace is removed.
pub fn clean_notes(s: &str) -> String {
    let unified = s.replace("\r\n", "\n").replace('\r', "\n");
    let kept: String = unified
        .chars()
        .filter(|&c| c == '\n' || c == '\t' || !c.is_control())
        .collect();
    kept.trim_end().to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_width_digits_and_colons() {
        assert_eq!(normalize_input("１９２．１６８．０．１"), "192.168.0.1");
        assert_eq!(normalize_input("ＡＡ：ＢＢ：ｃｃ"), "AA:BB:cc");
        assert_eq!(normalize_input("ａａ－ｂｂ"), "aa-bb");
    }

    #[test]
    fn dashes_and_spaces() {
        for d in ["ー", "ｰ", "‐", "‑", "‒", "–", "—", "―", "−", "﹣", "－"] {
            assert_eq!(normalize_input(&format!("AA{d}BB")), "AA-BB", "dash {d:?}");
        }
        assert_eq!(normalize_input("AA\u{3000}BB"), "AA BB");
        assert_eq!(normalize_input("1。2｡3"), "1.2.3");
    }

    #[test]
    fn list_commas_only_in_lists() {
        assert_eq!(normalize_input("1、2"), "1、2");
        assert_eq!(normalize_list_input("1、2､3"), "1,2,3");
    }

    #[test]
    fn borrowed_when_ascii() {
        assert!(matches!(normalize_input("192.168.0.1"), Cow::Borrowed(_)));
    }

    #[test]
    fn kana_detection() {
        assert!(contains_kana("あa:bb"));
        assert!(contains_kana("ｱ"));
        assert!(contains_kana("カ"));
        assert!(contains_kana("漢"));
        // Prolonged sound mark is a dash, not kana.
        assert!(!contains_kana("AAーBB"));
        assert_eq!(check_technical(" ａあ "), Err(FieldIssue::ImeKana));
        assert_eq!(check_technical(" １０ ").as_deref(), Ok("10"));
        assert_eq!(check_technical_list("１、２").as_deref(), Ok("1,2"));
    }

    #[test]
    fn name_keys() {
        assert_eq!(name_key("ＮＡＳ"), name_key(" nas "));
        assert_ne!(name_key("サーバー"), name_key("サーバ-"));
        assert_eq!(name_key("サーバー"), "サーバー");
        assert_eq!(search_key("Ｌａｂ　ＰＣ"), "lab pc");
    }

    #[test]
    fn single_line() {
        assert_eq!(clean_single_line(" a\tb\nc "), "a b c");
        assert_eq!(clean_single_line("evil\u{1b}]0;x\u{7}"), "evil ]0;x");
    }

    #[test]
    fn notes_keep_lines_but_no_escapes() {
        assert_eq!(clean_notes("a\r\nb\rc\td  \n"), "a\nb\nc\td");
        assert_eq!(
            clean_notes("n\u{1b}[31mote\u{1b}]0;PWNED\u{7}x\u{7f}\u{9b}2J"),
            "n[31mote]0;PWNEDx2J"
        );
        assert_eq!(clean_notes("書斎の NAS"), "書斎の NAS");
    }
}
