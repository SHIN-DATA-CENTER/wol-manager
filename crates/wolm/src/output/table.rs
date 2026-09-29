//! Column-aligned tables. Widths come from `unicode-width`, so Japanese names (2 columns
//! per character) line up in the console.

use anstyle::Style;
use unicode_width::UnicodeWidthStr;

use super::paint;

/// One cell: text and style.
#[derive(Debug, Clone)]
pub struct Cell {
    text: String,
    style: Style,
}

impl Cell {
    /// Plain cell.
    pub fn plain(text: impl Into<String>) -> Cell {
        Cell {
            text: text.into(),
            style: Style::new(),
        }
    }

    /// Styled cell.
    pub fn styled(text: impl Into<String>, style: Style) -> Cell {
        Cell {
            text: text.into(),
            style,
        }
    }
}

impl From<String> for Cell {
    fn from(s: String) -> Cell {
        Cell::plain(s)
    }
}

impl From<&str> for Cell {
    fn from(s: &str) -> Cell {
        Cell::plain(s)
    }
}

/// A table with a header row.
#[derive(Debug, Clone, Default)]
pub struct Table {
    headers: Vec<String>,
    rows: Vec<Vec<Cell>>,
    indent: usize,
}

/// Display width, with control characters counted as one column (they are replaced).
pub fn width(s: &str) -> usize {
    UnicodeWidthStr::width(s)
}

fn clean(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

impl Table {
    /// New table.
    pub fn new(headers: Vec<String>) -> Table {
        Table {
            headers,
            rows: Vec::new(),
            indent: 0,
        }
    }

    /// Indents every line.
    pub fn indent(mut self, n: usize) -> Table {
        self.indent = n;
        self
    }

    /// Adds a row (missing cells are empty).
    pub fn row(&mut self, cells: Vec<Cell>) {
        self.rows.push(cells);
    }

    /// Rendered lines (header first). The last column is not padded.
    pub fn lines(&self) -> Vec<String> {
        let cols = self
            .headers
            .len()
            .max(self.rows.iter().map(Vec::len).max().unwrap_or(0));
        let mut widths = vec![0usize; cols];
        let header_cells: Vec<Cell> = self
            .headers
            .iter()
            .map(|h| Cell::styled(h.clone(), super::BOLD))
            .collect();
        let all = std::iter::once(&header_cells).chain(self.rows.iter());
        for r in all.clone() {
            for (i, c) in r.iter().enumerate() {
                widths[i] = widths[i].max(width(&clean(&c.text)));
            }
        }
        let pad = " ".repeat(self.indent);
        all.map(|r| {
            let mut line = pad.clone();
            for (i, col_width) in widths.iter().enumerate() {
                let (text, style) = match r.get(i) {
                    Some(c) => (clean(&c.text), c.style),
                    None => (String::new(), Style::new()),
                };
                let w = width(&text);
                line.push_str(&paint(style, &text));
                if i + 1 < cols {
                    line.push_str(&" ".repeat(col_width.saturating_sub(w) + 2));
                }
            }
            line.trim_end().to_owned()
        })
        .collect()
    }
}

/// `label  value` pairs with aligned values (for `show`, `config path`, ...).
pub fn key_values(pairs: &[(String, String)], indent: usize) -> Vec<String> {
    let w = pairs.iter().map(|(k, _)| width(k)).max().unwrap_or(0);
    pairs
        .iter()
        .map(|(k, v)| {
            format!(
                "{}{}{}  {}",
                " ".repeat(indent),
                paint(super::BOLD, k),
                " ".repeat(w - width(k)),
                clean(v)
            )
            .trim_end()
            .to_owned()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strip(s: &str) -> String {
        let mut out = String::new();
        let mut in_esc = false;
        for c in s.chars() {
            if c == '\u{1b}' {
                in_esc = true;
            } else if in_esc {
                if c == 'm' {
                    in_esc = false;
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    #[test]
    fn cjk_columns_line_up() {
        let mut t = Table::new(vec!["NAME".into(), "MAC".into()]);
        t.row(vec!["書斎の NAS".into(), "00:11:22:33:44:55".into()]);
        t.row(vec!["pc".into(), "AA:BB:CC:DD:EE:FF".into()]);
        let lines: Vec<String> = t.lines().iter().map(|l| strip(l)).collect();
        let col = |l: &str, needle: &str| width(&l[..l.find(needle).unwrap()]);
        assert_eq!(col(&lines[0], "MAC"), col(&lines[1], "00:"));
        assert_eq!(col(&lines[1], "00:"), col(&lines[2], "AA:"));
        assert!(!lines[1].ends_with(' '));
    }

    #[test]
    fn key_values_align() {
        let l = key_values(
            &[("名前".into(), "x".into()), ("MAC".into(), "y".into())],
            0,
        );
        let a = strip(&l[0]);
        let b = strip(&l[1]);
        assert_eq!(width(&a), width(&b));
    }
}
