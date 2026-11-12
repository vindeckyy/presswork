//! Shared CUPS backend framework — the argv/env/exit contract every backend
//! honors (`cups/backend.h`, `backend/*.c`).
//!
//! A backend is run two ways:
//!  * `scheme` (argv.len()==1) — *device discovery*: print one
//!    `class uri make-model info [device-id]` line per found device, exit 0.
//!  * `scheme job-id user title copies options [file]` — print the job from
//!    stdin (or `file`) to `DEVICE_URI`, exit a `CUPS_BACKEND_*` code.

use std::env;
use std::fs::File;
use std::io::{self, Read, Write};

/// `CUPS_BACKEND_*` exit codes (`cups/backend.h`).
pub mod code {
    /// Job completed successfully.
    pub const OK: i32 = 0;
    /// Job failed; apply error-policy.
    pub const FAILED: i32 = 1;
    /// Authentication required.
    pub const AUTH_REQUIRED: i32 = 2;
    /// Hold the job.
    pub const HOLD: i32 = 3;
    /// Stop the queue.
    pub const STOP: i32 = 4;
    /// Cancel the job.
    pub const CANCEL: i32 = 5;
    /// Retry later.
    pub const RETRY: i32 = 6;
    /// Retry immediately.
    pub const RETRY_CURRENT: i32 = 7;
}

/// Parsed backend invocation.
pub struct Invocation {
    /// `argv[1]` job id (0 in discovery).
    pub job_id: i32,
    /// `argv[2]` user.
    pub user: String,
    /// `argv[3]` job title.
    pub title: String,
    /// `argv[4]` copies.
    pub copies: i32,
    /// `argv[5]` options string.
    pub options: String,
    /// `argv[6]` document path, if supplied (else read stdin).
    pub file: Option<String>,
    /// `DEVICE_URI` env var.
    pub device_uri: String,
}

/// Parse argv+env for a print invocation; `None` if run in discovery mode
/// (no args) or malformed.
pub fn parse<I: Iterator<Item = String>>(argv: I) -> Option<Invocation> {
    let a: Vec<String> = argv.collect();
    if a.len() < 6 {
        return None;
    }
    Some(Invocation {
        job_id: a[1].parse().unwrap_or(0),
        user: a.get(2).cloned().unwrap_or_default(),
        title: a.get(3).cloned().unwrap_or_default(),
        copies: a[4].parse().unwrap_or(1),
        options: a.get(5).cloned().unwrap_or_default(),
        file: a.get(6).cloned(),
        device_uri: env::var("DEVICE_URI").unwrap_or_default(),
    })
}

/// Open the job document as a reader — `argv[6]` file or stdin.
pub fn document(inv: &Invocation) -> io::Result<Box<dyn Read + Send>> {
    match &inv.file {
        Some(f) => Ok(Box::new(File::open(f)?)),
        None => Ok(Box::new(io::stdin())),
    }
}

/// Emit one discovery line (`class uri "make-model" "info" ["device-id"]`).
pub fn report(class_: &str, uri: &str, make_model: &str, info: &str, device_id: Option<&str>) {
    let mut out = io::stdout().lock();
    let _ = write!(out, "{class_} {uri} \"{make_model}\" \"{info}\"");
    if let Some(id) = device_id {
        let _ = write!(out, " \"{id}\"");
    }
    let _ = writeln!(out);
}

/// `DEBUG:` line on stderr (consumed by the scheduler's filter log).
pub fn debug(args: std::fmt::Arguments<'_>) {
    eprintln!("DEBUG: {args}");
}
/// `INFO:` line on stderr → `error_log`.
pub fn info(args: std::fmt::Arguments<'_>) {
    eprintln!("INFO: {args}");
}
/// `ERROR:` line on stderr → `error_log`.
pub fn error(args: std::fmt::Arguments<'_>) {
    eprintln!("ERROR: {args}");
}

/// Run a backend main: `discover()` when `argv.len()`<6, else `print(inv)`.
/// `print` returns a `CUPS_BACKEND_*` code.
pub fn run<D, P>(discover: D, print: P) -> !
where
    D: FnOnce() -> i32,
    P: FnOnce(Invocation) -> i32,
{
    let code = match parse(env::args()) {
        Some(inv) => print(inv),
        None => discover(),
    };
    std::process::exit(code)
}
