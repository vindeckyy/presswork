//! Configuration file lexer — a faithful port of libcups `cupsFileGetConf`.
//!
//! Line semantics:
//! - `#` starts a comment (unless escaped).
//! - `\\`, `\#`, `\n`, `\r` escape sequences are unescaped in place.
//! - Leading whitespace is stripped; first token is the directive.
//! - Everything after the directive's whitespace is the value.
//! - Directives starting with `<` must end the line with `>`; the `>` is
//!   stripped from the value. `</X>` has no value.

use std::io::{BufRead, Read};

/// One logical configuration line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfLine {
    /// 1-based line number in the source.
    pub linenum: usize,
    /// Directive name (first whitespace-delimited token).
    pub name: String,
    /// Value text, if any (`None` for bare directives).
    pub value: Option<String>,
}

/// Iterator over the logical lines of a configuration file.
pub struct ConfLines<R> {
    reader: R,
    linenum: usize,
    pending: Vec<ConfLine>,
}

impl<R: BufRead> ConfLines<R> {
    /// Create a lexer over `reader`.
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            linenum: 0,
            pending: Vec::new(),
        }
    }

    /// Current 1-based line number.
    pub fn linenum(&self) -> usize {
        self.linenum
    }
}

impl<R: BufRead> Iterator for ConfLines<R> {
    type Item = std::io::Result<ConfLine>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(l) = self.pending.pop() {
            return Some(Ok(l));
        }
        let mut raw = String::new();
        loop {
            raw.clear();
            match self.reader.read_line(&mut raw) {
                Err(e) => return Some(Err(e)),
                Ok(0) => return None,
                Ok(_) => {}
            }
            self.linenum += 1;

            let line = unescape_and_strip(&raw);
            let line = line.trim().to_string();
            if line.is_empty() {
                continue;
            }

            // Split directive / value on first whitespace run.
            let it = line.char_indices();
            let mut end = line.len();
            for (i, c) in it {
                if c.is_whitespace() {
                    end = i;
                    break;
                }
            }
            let name = line[..end].to_string();
            let mut value: Option<String> = None;
            if end < line.len() {
                let rest = line[end..].trim_start();
                if !rest.is_empty() {
                    let mut v = rest.to_string();
                    if name.starts_with('<') {
                        // Must end with '>' — strip it, else syntax error
                        // (value = NULL in the C original).
                        if v.ends_with('>') {
                            v.pop();
                            v = v.trim_end().to_string();
                        } else {
                            return Some(Ok(ConfLine {
                                linenum: self.linenum,
                                name,
                                value: None,
                            }));
                        }
                    }
                    if !v.is_empty() {
                        value = Some(v);
                    }
                }
            } else if name.starts_with('<') && !name.ends_with('>') {
                // `<Foo` with no value: C keeps the name, no value.
            }
            return Some(Ok(ConfLine {
                linenum: self.linenum,
                name,
                value,
            }));
        }
    }
}

/// Create a lexer from any `Read` (wraps in `BufReader` if needed via
/// caller; accepts pre-buffered readers for `read_line` support).
pub fn conf_lines<R: Read>(r: R) -> ConfLines<std::io::BufReader<R>> {
    ConfLines::new(std::io::BufReader::new(r))
}

/// Apply `cupsFileGetConf`'s escape processing and comment stripping.
///
/// `#` terminates the line; `\\` `\#` `\n` `\r` are unescaped.
fn unescape_and_strip(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = String::with_capacity(raw.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'#' => break,
            b'\\' if i + 1 < bytes.len() && matches!(bytes[i + 1], b'\\' | b'#' | b'n' | b'r') => {
                match bytes[i + 1] {
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    c => out.push(c as char),
                }
                i += 2;
            }
            _ => {
                // Preserve UTF-8: copy the whole codepoint.
                let ch_len = utf8_len(bytes[i]);
                out.push_str(&raw[i..(i + ch_len).min(raw.len())]);
                i += ch_len;
            }
        }
    }
    out
}

fn utf8_len(b: u8) -> usize {
    if b < 0x80 {
        1
    } else if b < 0xE0 {
        2
    } else if b < 0xF0 {
        3
    } else {
        4
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(s: &str) -> Vec<ConfLine> {
        conf_lines(s.as_bytes()).map(|r| r.unwrap()).collect()
    }

    #[test]
    fn basic_directive() {
        let ls = lines("LogLevel warn\n");
        assert_eq!(ls.len(), 1);
        assert_eq!(ls[0].name, "LogLevel");
        assert_eq!(ls[0].value.as_deref(), Some("warn"));
        assert_eq!(ls[0].linenum, 1);
    }

    #[test]
    fn comments_and_blanks() {
        let ls = lines("# full comment\n   # indented\nLogLevel warn # trailing\n\n");
        assert_eq!(ls.len(), 1);
        assert_eq!(ls[0].value.as_deref(), Some("warn"));
        assert_eq!(ls[0].linenum, 3);
    }

    #[test]
    fn escapes() {
        let ls = lines("SetEnv A foo\\#bar\nSetEnv B x\\\\y\n");
        assert_eq!(ls[0].value.as_deref(), Some("A foo#bar"));
        assert_eq!(ls[1].value.as_deref(), Some("B x\\y"));
    }

    #[test]
    fn location_block_tag() {
        let ls = lines("<Location /admin>\nOrder allow,deny\n</Location>\n");
        assert_eq!(ls[0].name, "<Location");
        assert_eq!(ls[0].value.as_deref(), Some("/admin"));
        assert_eq!(ls[2].name, "</Location>");
        assert_eq!(ls[2].value, None);
    }

    #[test]
    fn unterminated_block_tag_is_syntax_error() {
        let ls = lines("<Location /admin\n");
        assert_eq!(ls[0].name, "<Location");
        assert_eq!(ls[0].value, None);
    }

    #[test]
    fn no_value() {
        let ls = lines("Browsing\n");
        assert_eq!(ls[0].value, None);
    }
}
