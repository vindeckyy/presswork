//! cups-config — parsers for the CUPS configuration files
//! (`cupsd.conf`, `cups-files.conf`) with semantics ported from
//! `scheduler/conf.c` upstream.
//!
//! ```
//! let text = b"LogLevel warn\nPort 631\n";
//! let (cfg, diags) = cups_config::parse_cupsd_conf(&text[..], "cupsd.conf");
//! assert_eq!(cfg.max_clients, 100);
//! assert!(!diags.has_errors());
//! ```

mod acl;
mod config;
mod lexer;
mod types;
mod vars;

pub use acl::{parse_aaa, Diag, Location, Severity};
pub use config::{
    default_listeners, default_policy, read_cups_files_conf, read_cupsd_conf, CupsFilesConfig,
    CupsdConfig, DiagSink, Diagnostic, Diagnostics, Policy, PolicyOp,
};
pub use lexer::{conf_lines, ConfLine, ConfLines};
pub use types::{
    limit, AccessLogLevel, AuthLevel, AuthType, BrowseProtocols, Encryption, ErrorPolicy,
    FatalErrors, HostMask, IpNet, ListenAddr, Listener, LogLevel, LogTimeFormat, OrderType,
    PeerCred, PrintcapFormat, Sandboxing, Satisfy, TlsOptions, TlsVersion,
};

use std::path::{Path, PathBuf};

/// Combined runtime configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// `cupsd.conf` contents.
    pub cupsd: CupsdConfig,
    /// `cups-files.conf` contents.
    pub files: CupsFilesConfig,
}

/// Path set resolved from env + cups-files.conf.
#[derive(Debug, Clone)]
pub struct Paths {
    /// `CUPS_SERVERROOT` or default `/etc/cups`.
    pub server_root: PathBuf,
    /// `cupsd.conf` location.
    pub cupsd_conf: PathBuf,
    /// `cups-files.conf` location.
    pub cups_files_conf: PathBuf,
}

impl Paths {
    /// Resolve like cupsd: `CUPS_SERVERROOT` env, `-c` override handled
    /// by the caller (pass `Some` for it).
    pub fn resolve(server_root_arg: Option<&Path>) -> Self {
        let root = server_root_arg
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("CUPS_SERVERROOT").map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from("/etc/cups"));
        Self {
            cupsd_conf: root.join("cupsd.conf"),
            cups_files_conf: root.join("cups-files.conf"),
            server_root: root,
        }
    }
}

/// Parse `cupsd.conf` from a reader (convenience wrapper).
pub fn parse_cupsd_conf<R: std::io::BufRead>(r: R, filename: &str) -> (CupsdConfig, Diagnostics) {
    let mut cfg = CupsdConfig::defaults();
    let mut diags = Diagnostics {
        fatal: cfg.fatal_errors,
        ..Diagnostics::default()
    };
    read_cupsd_conf(r, filename, &mut cfg, &mut diags);
    (cfg, diags)
}

/// Parse `cups-files.conf` from a reader (convenience wrapper).
pub fn parse_cups_files_conf<R: std::io::BufRead>(
    r: R,
    filename: &str,
    server_root: &str,
) -> (CupsFilesConfig, FatalErrors, Diagnostics) {
    let mut cfg = CupsFilesConfig::defaults();
    let mut fatal = FatalErrors::default();
    let mut diags = Diagnostics {
        fatal,
        ..Diagnostics::default()
    };
    read_cups_files_conf(
        r,
        filename,
        &mut cfg,
        server_root,
        &mut fatal,
        &mut diags,
        &|_| None,
        &|_| None,
    );
    (cfg, fatal, diags)
}

/// Result of a full `cupsd -t`-style validation pass.
pub struct LoadOutcome {
    /// The merged config (valid even when `ok == false` if non-fatal).
    pub config: Config,
    /// All diagnostics from both files.
    pub diagnostics: Vec<Diagnostic>,
    /// Whether the parse succeeded (mirrors `cupsdReadConfiguration`).
    pub ok: bool,
}

/// Load + validate `cups-files.conf` then `cupsd.conf` from `paths`,
/// with system user/group resolution.
///
/// Mirrors `cupsdReadConfiguration`'s order and failure behavior:
/// missing cups-files.conf → INFO + defaults; missing cupsd.conf →
/// fatal. Applies the default-policy synthesis and listener defaults.
#[must_use]
pub fn load(paths: &Paths) -> LoadOutcome {
    let mut files = CupsFilesConfig::defaults();
    let mut cupsd = CupsdConfig::defaults();
    let mut diags = Diagnostics::default();
    let mut ok = true;

    let server_root = paths.server_root.to_string_lossy().to_string();

    // cups-files.conf — optional; absent means defaults.
    match std::fs::File::open(&paths.cups_files_conf) {
        Ok(f) => {
            let mut fatal = cupsd.fatal_errors;
            let r = std::io::BufReader::new(f);
            if !read_cups_files_conf(
                r,
                &paths.cups_files_conf.to_string_lossy(),
                &mut files,
                &server_root,
                &mut fatal,
                &mut diags,
                &resolve_group,
                &resolve_user,
            ) {
                ok = false;
            }
            cupsd.fatal_errors = fatal;
            diags.fatal = fatal;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            diags.entries.push(Diagnostic {
                severity: Severity::Info,
                file: paths.cups_files_conf.to_string_lossy().to_string(),
                line: 0,
                message: format!("No {}, using defaults.", paths.cups_files_conf.display()),
            });
        }
        Err(e) => {
            diags.entries.push(Diagnostic {
                severity: Severity::Error,
                file: paths.cups_files_conf.to_string_lossy().to_string(),
                line: 0,
                message: format!(
                    "Unable to read \"{}\" - {e}",
                    paths.cups_files_conf.display()
                ),
            });
            return LoadOutcome {
                config: Config { cupsd, files },
                diagnostics: diags.entries,
                ok: false,
            };
        }
    }

    // cupsd.conf — required.
    match std::fs::File::open(&paths.cupsd_conf) {
        Ok(f) => {
            let r = std::io::BufReader::new(f);
            if !read_cupsd_conf(
                r,
                &paths.cupsd_conf.to_string_lossy(),
                &mut cupsd,
                &mut diags,
            ) {
                ok = false;
            }
        }
        Err(e) => {
            diags.entries.push(Diagnostic {
                severity: Severity::Error,
                file: paths.cupsd_conf.to_string_lossy().to_string(),
                line: 0,
                message: format!("Unable to open \"{}\" - {e}", paths.cupsd_conf.display()),
            });
            return LoadOutcome {
                config: Config { cupsd, files },
                diagnostics: diags.entries,
                ok: false,
            };
        }
    }

    // Default policy synthesis (conf.c ~1441).
    let dp_ok = cupsd
        .default_policy
        .as_deref()
        .is_some_and(|name| cupsd.policies.iter().any(|p| p.name == name));
    if !dp_ok {
        if let Some(name) = &cupsd.default_policy {
            diags.entries.push(Diagnostic {
                severity: Severity::Error,
                file: paths.cupsd_conf.to_string_lossy().to_string(),
                line: 0,
                message: format!("Default policy \"{name}\" not found."),
            });
        }
        if !cupsd.policies.iter().any(|p| p.name == "default") {
            cupsd.policies.push(default_policy());
        }
        cupsd.default_policy = Some("default".to_string());
    }

    default_listeners(&mut cupsd);

    LoadOutcome {
        config: Config { cupsd, files },
        diagnostics: diags.entries,
        ok,
    }
}

#[cfg(unix)]
fn resolve_group(name: &str) -> Option<u32> {
    sys::gid_of(name)
}

#[cfg(not(unix))]
fn resolve_group(_name: &str) -> Option<u32> {
    None
}

#[cfg(unix)]
fn resolve_user(name: &str) -> Option<u32> {
    sys::uid_of(name)
}

#[cfg(not(unix))]
fn resolve_user(_name: &str) -> Option<u32> {
    None
}
