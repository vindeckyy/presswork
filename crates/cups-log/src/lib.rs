//! `cups-log` — the three scheduler log files, ported from
//! `scheduler/log.c`:
//!
//! - `error_log`: `L [dd/Mon/yyyy:HH:MM:SS ±ZZZZ] message`
//! - `access_log`: common log format + op/status names
//!   (`host - user [time] "METHOD uri HTTP/x.y" code bytes op status`)
//! - `page_log`: `PageLogFormat` template expansion
//!   (`%p %u %j %T %P %C %{attr}`)

#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]

use std::fmt::Write as _;
use std::io::Write as _;
use std::sync::Mutex;

use ipp_codec::{Attribute, Value};

/// cupsd log levels — the `levels[]` array order in `cupsdWriteErrorLog`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Level {
    /// Emergency (`X`).
    Emergency = 1,
    /// Alert (`A`).
    Alert = 2,
    /// Critical (`C`).
    Crit = 3,
    /// Error (`E`).
    Error = 4,
    /// Warning (`W`).
    Warn = 5,
    /// Notice (`N`).
    Notice = 6,
    /// Info (`I`).
    Info = 7,
    /// Debug (`D`).
    Debug = 8,
    /// Debug2 (`d`).
    Debug2 = 9,
}

impl Level {
    /// Single-letter tag as written to `error_log`.
    #[must_use]
    pub const fn letter(self) -> char {
        match self {
            Self::Emergency => 'X',
            Self::Alert => 'A',
            Self::Crit => 'C',
            Self::Error => 'E',
            Self::Warn => 'W',
            Self::Notice => 'N',
            Self::Info => 'I',
            Self::Debug => 'D',
            Self::Debug2 => 'd',
        }
    }
}

/// `LogTimeFormat` variants (upstream `CUPSD_TIME_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TimeFormat {
    /// `[dd/Mon/yyyy:HH:MM:SS ±ZZZZ]` (upstream default).
    #[default]
    Standard,
    /// Same with `.usecs` appended — `LogTimeFormat usecs`.
    Usecs,
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// `cupsdGetDateTime()` — `[dd/Mon/yyyy:HH:MM:SS[.uuuuuu] ±ZZZZ]`.
#[must_use]
pub fn datetime(format: TimeFormat) -> String {
    let now = time::OffsetDateTime::now_local().unwrap_or_else(|_| time::OffsetDateTime::now_utc());
    let off = now.offset();
    let (h, m, _s) = off.as_hms();
    let sign = if off.whole_seconds() < 0 { '-' } else { '+' };
    let mon = MONTHS[now.month() as usize - 1];
    let mut s = String::with_capacity(40);
    let _ = write!(
        s,
        "[{:02}/{}/{:04}:{:02}:{:02}:{:02}",
        now.day(),
        mon,
        now.year(),
        now.hour(),
        now.minute(),
        now.second()
    );
    if format == TimeFormat::Usecs {
        let _ = write!(s, ".{:06}", now.microsecond());
    }
    let _ = write!(s, " {}{:02}{:02}]", sign, h.abs(), m.abs());
    s
}

/// One log sink — a lazily-opened file (or stderr). `MaxLogSize`
/// rotation lands with the config plumbing (P1 follow-up).
pub struct Sink {
    inner: Mutex<Option<std::fs::File>>,
    path: std::path::PathBuf,
    /// Fallback when the file can't be opened (upstream logs to
    /// stderr when running with `-f`).
    stderr: bool,
}

impl Sink {
    /// A file-backed sink.
    #[must_use]
    pub fn file(path: impl Into<std::path::PathBuf>) -> Self {
        Self {
            inner: Mutex::new(None),
            path: path.into(),
            stderr: false,
        }
    }

    /// Stderr sink (foreground mode).
    #[must_use]
    pub fn stderr() -> Self {
        Self {
            inner: Mutex::new(None),
            path: std::path::PathBuf::from("/dev/stderr"),
            stderr: true,
        }
    }

    /// Write one formatted line; returns false if the file failed.
    pub fn write(&self, line: &str) -> bool {
        if self.stderr {
            let _ = writeln!(std::io::stderr(), "{line}");
            return true;
        }
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if guard.is_none() {
            match std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)
            {
                Ok(f) => *guard = Some(f),
                Err(_) => return false,
            }
        }
        guard
            .as_mut()
            .is_some_and(|f| f.write_all(line.as_bytes()).is_ok() && f.write_all(b"\n").is_ok())
    }
}

/// `cupsdWriteErrorLog()` — `L [time] message`.
pub fn error_line(level: Level, tf: TimeFormat, message: &str) -> String {
    format!("{} {} {}", level.letter(), datetime(tf), message)
}

/// `cupsdLogRequest()` — common log format +
/// `op-name status-name` tail.
///
/// `version` is `HttpVersion` as `(major*100 + minor*100)`-style
/// numbers upstream uses (`version / 100`, `version % 100` → "1.1").
#[must_use]
pub fn access_line(
    host: &str,
    user: Option<&str>,
    tf: TimeFormat,
    method: &str,
    uri: &str,
    version: (u8, u8),
    code: u16,
    bytes: u64,
    op_name: &str,
    status_name: &str,
    con_start: Option<time::OffsetDateTime>,
) -> String {
    let ts = con_start.map_or_else(
        || datetime(tf),
        |t| {
            let _ = t;
            datetime(tf)
        },
    );
    format!(
        "{} - {} {} \"{} {} HTTP/{}.{}\" {} {} {} {}",
        host,
        user.unwrap_or("-"),
        ts,
        method,
        encode_uri(uri),
        version.0,
        version.1,
        code,
        bytes,
        op_name,
        status_name
    )
}

/// `_httpEncodeURI` — escape `"` and control/unsafe chars for the
/// quoted request field (upstream escapes `%`, `"`, space, controls).
fn encode_uri(uri: &str) -> String {
    let mut out = String::with_capacity(uri.len() + 8);
    for b in uri.bytes() {
        match b {
            b'"' | b'\\' | b'%' => out.push_str(&format!("%{b:02X}")),
            0x20 => out.push('+'),
            0..=0x1f | 0x7f..=0xff => out.push_str(&format!("%{b:02X}")),
            _ => out.push(b as char),
        }
    }
    out
}

/// `cupsdLogPage()` — expand `PageLogFormat` for one printed page.
///
/// `%p` printer, `%u` user, `%j` job-id, `%T` time, `%P` page number,
/// `%C` copies, `%{attr}` job attribute (multi → comma-joined),
/// `%%` literal.
///
/// `page` is the backend's `PAGE:` line tail — "number copies" (the
/// `sscanf("%255s%d")` split upstream does).
#[must_use]
pub fn page_line(
    format: &str,
    printer: &str,
    user: Option<&str>,
    job_id: i32,
    page: &str,
    job_attrs: &[Attribute],
    tf: TimeFormat,
) -> String {
    let mut parts = page.split_whitespace();
    let number = parts.next().unwrap_or("1").to_string();
    let copies: i32 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(1);

    let mut out = String::with_capacity(256);
    let mut it = format.chars().peekable();
    while let Some(c) = it.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match it.next() {
            Some('%') => out.push('%'),
            Some('p') => out.push_str(printer),
            Some('j') => {
                let _ = write!(out, "{job_id}");
            }
            Some('u') => out.push_str(user.unwrap_or("-")),
            Some('T') => out.push_str(&datetime(tf)),
            Some('P') => out.push_str(&number),
            Some('C') => {
                let _ = write!(out, "{copies}");
            }
            Some('{') => {
                let mut name = String::new();
                for c in it.by_ref() {
                    if c == '}' {
                        break;
                    }
                    name.push(c);
                }
                // Aliases upstream honors.
                let lookup = if name == "job-billing" {
                    job_attrs
                        .iter()
                        .find(|a| a.name == "job-billing")
                        .or_else(|| job_attrs.iter().find(|a| a.name == "job-account-id"))
                } else if name == "media" {
                    job_attrs
                        .iter()
                        .find(|a| a.name == "media")
                        .or_else(|| job_attrs.iter().find(|a| a.name == "media-col/media-size"))
                } else {
                    job_attrs.iter().find(|a| a.name == name.as_str())
                };
                if let Some(attr) = lookup {
                    for (i, v) in attr.values.iter().enumerate() {
                        if i > 0 {
                            out.push(',');
                        }
                        match v {
                            Value::Integer(x) | Value::Enum(x) => {
                                let _ = write!(out, "{x}");
                            }
                            Value::Boolean(b) => {
                                let _ = write!(out, "{}", i32::from(*b));
                            }
                            Value::Text(t)
                            | Value::Name(t)
                            | Value::Keyword(t)
                            | Value::Uri(t)
                            | Value::UriScheme(t)
                            | Value::Charset(t)
                            | Value::NaturalLanguage(t)
                            | Value::MimeMediaType(t) => out.push_str(&t.as_str()),
                            Value::TextWithLanguage { text, .. }
                            | Value::NameWithLanguage { text, .. } => {
                                out.push_str(&text.as_str());
                            }
                            _ => {}
                        }
                    }
                }
            }
            Some(other) => {
                out.push('%');
                out.push(other);
            }
            None => out.push('%'),
        }
    }
    out
}
