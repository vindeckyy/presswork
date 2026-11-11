//! `CupsdConfig`/`CupsFilesConfig` — the parsed configuration model with
//! defaults matching `cupsdReadConfiguration`, plus the top-level file
//! parsers ported from `read_cupsd_conf`/`read_cups_files_conf`/
//! `read_location`/`read_policy`.

use std::io::BufRead;
use std::net::ToSocketAddrs;

use crate::acl::{parse_aaa, AaaResult, Diag, Location, Severity};
use crate::lexer::{ConfLines, ConfLine};
use crate::types::{
    limit, AccessLogLevel, AuthLevel, AuthType, BrowseProtocols, Encryption,
    FatalErrors, ListenAddr, Listener, LogLevel, LogTimeFormat, OrderType,
    PeerCred, PrintcapFormat, Sandboxing, TlsOptions, TlsVersion,
};
use crate::vars::{parse_variable_cupsd, parse_variable_files};

/// One configuration diagnostic (what cupsd logs during parse).
#[derive(Debug, Clone)]
pub struct Diagnostic {
    /// Severity.
    pub severity: Severity,
    /// Source file.
    pub file: String,
    /// 1-based line number (0 for non-file issues).
    pub line: usize,
    /// Message text (matches upstream wording where practical).
    pub message: String,
}

/// Collects diagnostics during a parse.
#[derive(Default)]
pub struct Diagnostics {
    /// All diagnostics emitted.
    pub entries: Vec<Diagnostic>,
    /// `FatalErrors` bitmask in force (updated when the directive is read).
    pub fatal: FatalErrors,
    /// True once a fatal-class error aborted the parse.
    pub aborted: bool,
}

impl Diagnostics {
    /// Emit through the `Diag` interface for one file.
    pub fn sink<'a>(&'a mut self, file: &'a str) -> DiagSink<'a> {
        DiagSink { diags: self, file }
    }

    /// Did any Error-severity diagnostic occur?
    pub fn has_errors(&self) -> bool {
        self.entries.iter().any(|e| e.severity == Severity::Error)
    }
}

/// Per-file adapter implementing `Diag`.
pub struct DiagSink<'a> {
    diags: &'a mut Diagnostics,
    file: &'a str,
}

impl Diag for DiagSink<'_> {
    fn log(&mut self, severity: Severity, linenum: usize, msg: String) {
        self.diags.entries.push(Diagnostic {
            severity,
            file: self.file.to_string(),
            line: linenum,
            message: msg,
        });
    }
}

/// Everything parsed from `cupsd.conf` (upstream globals in conf.c).
#[derive(Debug, Clone)]
pub struct CupsdConfig {
    // Listeners
    /// `Listen`/`Port`/`SSLListen`/`SSLPort` accumulated addresses.
    pub listeners: Vec<Listener>,
    /// First non-localhost listen port (used for remote URI generation).
    pub remote_port: u16,

    // Browsing / DNS-SD
    /// `Browsing`.
    pub browsing: bool,
    /// `BrowseLocalProtocols`/`BrowseProtocols`.
    pub browse_local_protocols: BrowseProtocols,
    /// `BrowseWebIF`.
    pub browse_web_if: bool,
    /// `BrowseIPPSOnly`.
    pub browse_ipps_only: bool,
    /// `BrowseDNSSDSubTypes`.
    pub dnssd_subtypes: Option<String>,
    /// `DNSSDComputerName`.
    pub dnssd_computer_name: Option<String>,
    /// `DNSSDHostName`.
    pub dnssd_host_name: Option<String>,

    // Sharing
    /// `DefaultShared`.
    pub default_shared: bool,
    /// `DefaultPolicy` name.
    pub default_policy: Option<String>,
    /// `DefaultLanguage`.
    pub default_language: Option<String>,
    /// `DefaultPaperSize`.
    pub default_paper_size: Option<String>,
    /// `ReadyPaperSizes` list.
    pub ready_paper_sizes: Vec<String>,

    // Classification banners
    /// `Classification`.
    pub classification: Option<String>,
    /// `ClassifyOverride`.
    pub classify_override: bool,

    // Server identity
    /// `ServerName`.
    pub server_name: Option<String>,
    /// `ServerAdmin`.
    pub server_admin: Option<String>,
    /// `Server:` header built from `ServerTokens`.
    pub server_header: String,
    /// `ServerAlias` names.
    pub server_aliases: Vec<String>,
    /// `HostNameLookups`: 0=off, 1=on, 2=double.
    pub host_name_lookups: u8,

    // Logging
    /// `LogLevel`.
    pub log_level: LogLevel,
    /// `LogTimeFormat`.
    pub log_time_format: LogTimeFormat,
    /// `AccessLogLevel`.
    pub access_log_level: AccessLogLevel,
    /// `LogDebugHistory`.
    pub log_debug_history: i32,
    /// `MaxLogSize`.
    pub max_log_size: u64,
    /// `PageLogFormat`.
    pub page_log_format: Option<String>,

    // Error policy
    /// `FatalErrors` bitmask.
    pub fatal_errors: FatalErrors,
    /// `ErrorPolicy` default.
    pub error_policy: Option<String>,

    // Client limits
    /// `MaxClients`.
    pub max_clients: i32,
    /// `MaxClientsPerHost`.
    pub max_clients_per_host: i32,
    /// `MaxRequestSize`/`LimitRequestBody`.
    pub max_request_size: u64,
    /// `Timeout`.
    pub timeout: i32,
    /// `KeepAlive`.
    pub keep_alive: bool,
    /// `KeepAliveTimeout` — not a directive; cupsd derives from Timeout.
    pub keep_alive_timeout: i32,
    /// `MultipleOperationTimeout`.
    pub multiple_operation_timeout: i32,
    /// `ReloadTimeout`.
    pub reload_timeout: i32,
    /// `DirtyCleanInterval`.
    pub dirty_clean_interval: i32,

    // Jobs
    /// `AutoPurgeJobs`.
    pub job_auto_purge: bool,
    /// `MaxHoldTime`.
    pub max_hold_time: i32,
    /// `MaxJobs`.
    pub max_jobs: i32,
    /// `MaxActiveJobs`.
    pub max_active_jobs: i32,
    /// `MaxJobsPerUser`.
    pub max_jobs_per_user: i32,
    /// `MaxJobsPerPrinter`.
    pub max_jobs_per_printer: i32,
    /// `MaxCopies`.
    pub max_copies: i32,
    /// `MaxJobTime`.
    pub max_job_time: i32,
    /// `PreserveJobHistory` (seconds; `i32::MAX` = forever).
    pub preserve_job_history: i32,
    /// `PreserveJobFiles` (seconds).
    pub preserve_job_files: i32,
    /// `JobKillDelay`.
    pub job_kill_delay: i32,
    /// `JobRetryLimit` (also deprecated `FaxRetryLimit`).
    pub job_retry_limit: i32,
    /// `JobRetryInterval` (also deprecated `FaxRetryInterval`).
    pub job_retry_interval: i32,

    // Subscriptions / events
    /// `MaxSubscriptions`.
    pub max_subscriptions: i32,
    /// `MaxSubscriptionsPerJob`.
    pub max_subscriptions_per_job: i32,
    /// `MaxSubscriptionsPerPrinter`.
    pub max_subscriptions_per_printer: i32,
    /// `MaxSubscriptionsPerUser`.
    pub max_subscriptions_per_user: i32,
    /// `DefaultLeaseDuration`.
    pub default_lease_duration: i32,
    /// `MaxLeaseDuration`.
    pub max_lease_duration: i32,
    /// `MaxEvents`.
    pub max_events: i32,

    // Filters
    /// `FilterLimit`.
    pub filter_limit: i32,
    /// `FilterNice` 0-19.
    pub filter_nice: i32,

    // Misc behavior
    /// `WebInterface`.
    pub web_interface: bool,
    /// `StrictConformance`.
    pub strict_conformance: bool,
    /// `IdleExitTimeout` (on-demand mode).
    pub idle_exit_timeout: i32,
    /// `RootCertDuration`.
    pub root_cert_duration: i32,

    // Auth defaults
    /// `DefaultAuthType`.
    pub default_auth_type: AuthType,
    /// `DefaultEncryption`.
    pub default_encryption: Encryption,
    /// `GSSServiceName`.
    pub gss_service_name: Option<String>,

    // TLS
    /// `SSLOptions`.
    pub tls_options: TlsOptions,

    // Blocks
    /// `<Location>` objects incl. `<Limit>` expansions, in file order.
    pub locations: Vec<Location>,
    /// `<Policy>` objects.
    pub policies: Vec<Policy>,
}

/// A `<Policy name>` block: per-op ACLs + private attribute lists.
#[derive(Debug, Clone)]
pub struct Policy {
    /// Policy name.
    pub name: String,
    /// Per-operation limits (op code → Location acl). `0xffffffff` =
    /// `IPP_ANY_OPERATION` (the `<Limit All>` fallback).
    pub ops: Vec<PolicyOp>,
    /// `JobPrivateAccess` list.
    pub job_access: Vec<String>,
    /// `JobPrivateValues` list.
    pub job_values: Vec<String>,
    /// `SubscriptionPrivateAccess` list.
    pub sub_access: Vec<String>,
    /// `SubscriptionPrivateValues` list.
    pub sub_values: Vec<String>,
}

/// One `<Limit op…>` inside a `<Policy>`.
#[derive(Debug, Clone)]
pub struct PolicyOp {
    /// IPP operation code (`IPP_OP_*`), or `u32::MAX` for `All`.
    pub op: u32,
    /// The ACL built by the directives inside this `<Limit>`.
    pub loc: Location,
}

/// Everything parsed from `cups-files.conf`.
#[derive(Debug, Clone)]
pub struct CupsFilesConfig {
    /// `AccessLog` path.
    pub access_log: Option<String>,
    /// `ErrorLog` path (None → syslog/default).
    pub error_log: Option<String>,
    /// `PageLog` path.
    pub page_log: Option<String>,
    /// `ConfigFilePerm`.
    pub config_file_perm: u32,
    /// `LogFilePerm`.
    pub log_file_perm: u32,
    /// `LogFileGroup` (resolved gid).
    pub log_file_group: Option<u32>,
    /// `ServerRoot`.
    pub server_root: Option<String>,
    /// `ServerBin`.
    pub server_bin: Option<String>,
    /// `ServerKeychain`.
    pub server_keychain: Option<String>,
    /// `RequestRoot` (spool dir).
    pub request_root: Option<String>,
    /// `CacheDir`.
    pub cache_dir: Option<String>,
    /// `DataDir`.
    pub data_dir: Option<String>,
    /// `DocumentRoot`.
    pub document_root: Option<String>,
    /// `StateDir`.
    pub state_dir: Option<String>,
    /// `TempDir`.
    pub temp_dir: Option<String>,
    /// `Printcap` path.
    pub printcap: Option<String>,
    /// `PrintcapFormat`.
    pub printcap_format: PrintcapFormat,
    /// `RemoteRoot` username for remote auth.
    pub remote_root: Option<String>,
    /// `User` uid (resolved).
    pub user: u32,
    /// `Group` gid (resolved).
    pub group: u32,
    /// `SystemGroup` gids (resolved).
    pub system_groups: Vec<u32>,
    /// `SystemGroup` names as written (kept for diagnostics).
    pub system_group_names: Vec<String>,
    /// `SystemGroupAuthKey` (macOS).
    pub system_group_auth_key: Option<String>,
    /// `FileDevice` — `None` = off; Some(regex string) = compiled pattern.
    pub file_device: Option<String>,
    /// `PassEnv` variable names.
    pub pass_env: Vec<String>,
    /// `SetEnv` pairs.
    pub set_env: Vec<(String, String)>,
    /// `PeerCred`.
    pub peer_cred: PeerCred,
    /// `Sandboxing`.
    pub sandboxing: Sandboxing,
    /// `StripUserDomain`.
    pub strip_user_domain: bool,
    /// `SyncOnClose`.
    pub sync_on_close: bool,
    /// `CreateSelfSignedCerts`.
    pub create_self_signed_certs: bool,
    /// `OAuthServer`.
    pub oauth_server: Option<String>,
    /// `OAuthScopes`.
    pub oauth_scopes: Option<String>,
    /// `OAuthGroup` name→file map.
    pub oauth_groups: Vec<(String, String)>,
}

impl CupsdConfig {
    /// Defaults exactly as `cupsdReadConfiguration` sets them pre-parse.
    pub fn defaults() -> Self {
        Self {
            listeners: Vec::new(),
            remote_port: 0,

            browsing: true, // CUPS_DEFAULT_BROWSING=1
            browse_local_protocols: BrowseProtocols::default(),
            browse_web_if: false,
            browse_ipps_only: false,
            dnssd_subtypes: Some("_cups,_print,_universal".to_string()),
            dnssd_computer_name: None,
            dnssd_host_name: None,

            default_shared: true, // CUPS_DEFAULT_DEFAULT_SHARED=1
            default_policy: None,
            default_language: Some("en".to_string()),
            default_paper_size: None,
            ready_paper_sizes: Vec::new(),

            classification: None,
            classify_override: false,

            server_name: None,
            server_admin: None,
            server_header: format!(
                "CUPS/{}.{} IPP/2.1",
                cups_version_major(),
                cups_version_minor()
            ),
            server_aliases: Vec::new(),
            host_name_lookups: 0,

            log_level: LogLevel::Warn,
            log_time_format: LogTimeFormat::Standard,
            access_log_level: AccessLogLevel::Actions,
            log_debug_history: 200,
            max_log_size: 1024 * 1024,
            page_log_format: Some(concat!(
                "%p %u %j %T %P %C %{job-billing} ",
                "%{job-originating-host-name} %{job-name} %{media} %{sides}"
            ).to_string()),

            fatal_errors: FatalErrors::default(),
            error_policy: Some("stop-printer".to_string()),

            max_clients: 100,
            max_clients_per_host: 0,
            max_request_size: 0,
            timeout: 900,
            keep_alive: true,
            keep_alive_timeout: 30, // DEFAULT_KEEPALIVE
            multiple_operation_timeout: 900,
            reload_timeout: 30,
            dirty_clean_interval: 30,

            job_auto_purge: false,
            max_hold_time: 0,
            max_jobs: 500,
            max_active_jobs: 0,
            max_jobs_per_user: 0,
            max_jobs_per_printer: 0,
            max_copies: 9999,
            max_job_time: 10800, // 3 hours default
            preserve_job_history: i32::MAX, // DEFAULT_HISTORY
            preserve_job_files: 86400,      // DEFAULT_FILES
            job_kill_delay: 300,            // DEFAULT_TIMEOUT
            job_retry_limit: 5,
            job_retry_interval: 300,

            max_subscriptions: 100,
            max_subscriptions_per_job: 0,
            max_subscriptions_per_printer: 0,
            max_subscriptions_per_user: 0,
            default_lease_duration: 86400,
            max_lease_duration: 0,
            max_events: 100,

            filter_limit: 0,
            filter_nice: 0,

            web_interface: true, // CUPS_DEFAULT_WEBIF=1 typical
            strict_conformance: false,
            idle_exit_timeout: 60,
            root_cert_duration: 300,

            default_auth_type: AuthType::Auto,
            default_encryption: Encryption::IfRequested,
            gss_service_name: Some(String::new()),

            tls_options: TlsOptions::default(),

            locations: Vec::new(),
            policies: Vec::new(),
        }
    }
}

impl CupsFilesConfig {
    /// Defaults exactly as `cupsdReadConfiguration` sets them pre-parse.
    pub fn defaults() -> Self {
        Self {
            access_log: Some("/var/log/cups/access_log".to_string()),
            error_log: Some("/var/log/cups/error_log".to_string()),
            page_log: Some("/var/log/cups/page_log".to_string()),
            config_file_perm: 0o640,
            log_file_perm: 0o644,
            log_file_group: None,
            server_root: Some("/etc/cups".to_string()),
            server_bin: Some("/usr/lib/cups".to_string()),
            server_keychain: Some("/etc/cups/ssl".to_string()),
            request_root: Some("/var/spool/cups".to_string()),
            cache_dir: Some("/var/cache/cups".to_string()),
            data_dir: Some("/usr/share/cups".to_string()),
            document_root: Some("/usr/share/doc/cups".to_string()),
            state_dir: Some("/run/cups".to_string()),
            temp_dir: None,
            printcap: Some("/etc/printcap".to_string()),
            printcap_format: PrintcapFormat::Bsd,
            remote_root: Some("remroot".to_string()),
            user: 65534,
            group: 65534,
            system_groups: Vec::new(),
            system_group_names: Vec::new(),
            system_group_auth_key: Some("system.print.admin".to_string()),
            file_device: None,
            pass_env: Vec::new(),
            set_env: Vec::new(),
            peer_cred: PeerCred::On,
            sandboxing: Sandboxing::Strict,
            strip_user_domain: false,
            sync_on_close: false,
            create_self_signed_certs: true,
            oauth_server: None,
            oauth_scopes: None,
            oauth_groups: Vec::new(),
        }
    }
}

fn cups_version_major() -> u32 {
    2
}
fn cups_version_minor() -> u32 {
    5
}

/// Environment variables that may not be passed/set (`prohibited_env[]`).
static PROHIBITED_ENV: &[&str] = &[
    "APPLE_LANGUAGE",
    "AUTH_DOMAIN",
    "AUTH_INFO_REQUIRED",
    "AUTH_NEGOTIATE",
    "AUTH_PASSWORD",
    "AUTH_UID",
    "AUTH_USERNAME",
    "CHARSET",
    "CLASS",
    "CLASSIFICATION",
    "CONTENT_TYPE",
    "CUPS_CACHEDIR",
    "CUPS_DATADIR",
    "CUPS_DOCROOT",
    "CUPS_FILETYPE",
    "CUPS_FONTPATH",
    "CUPS_MAX_MESSAGE",
    "CUPS_REQUESTROOT",
    "CUPS_SERVERBIN",
    "CUPS_SERVERROOT",
    "CUPS_STATEDIR",
    "DEVICE_URI",
    "FINAL_CONTENT_TYPE",
    "HOME",
    "LANG",
    "PPD",
    "PRINTER",
    "PRINTER_INFO",
    "PRINTER_LOCATION",
    "PRINTER_STATE_REASONS",
    "RIP_CACHE",
    "SERVER_ADMIN",
    "SOFTWARE",
    "TMPDIR",
    "USER",
];

/// Parse `cups-files.conf` — port of `read_cups_files_conf`.
///
/// `resolve_user`/`resolve_group` resolve names→ids; tests inject fakes.
#[allow(clippy::too_many_lines)]
pub fn read_cups_files_conf<R: BufRead>(
    r: R,
    filename: &str,
    cfg: &mut CupsFilesConfig,
    server_root: &str,
    fatal: &mut FatalErrors,
    diags: &mut Diagnostics,
    resolve_group: &dyn Fn(&str) -> Option<u32>,
    resolve_user: &dyn Fn(&str) -> Option<u32>,
) -> bool {
    let sink_file = filename.to_string();
    let mut lines = ConfLines::new(r);
    let mut ok = true;

    macro_rules! err {
        ($line:expr, $($f:tt)*) => {{
            diags.entries.push(Diagnostic {
                severity: Severity::Error,
                file: sink_file.clone(),
                line: $line,
                message: format!($($f)*),
            });
        }};
    }
    macro_rules! info {
        ($line:expr, $($f:tt)*) => {{
            diags.entries.push(Diagnostic {
                severity: Severity::Info,
                file: sink_file.clone(),
                line: $line,
                message: format!($($f)*),
            });
        }};
    }
    macro_rules! fatal_if {
        ($mask:expr) => {
            if fatal.has($mask) {
                return false;
            }
        };
    }
    let _ = &sink_file;

    for line in lines.by_ref() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                err!(0, "I/O error reading {}: {}", filename, e);
                return false;
            }
        };
        let name = line.name.as_str();
        let value = line.value.as_deref();
        let ln = line.linenum;

        if name.eq_ignore_ascii_case("FatalErrors") {
            let (f, bad) = FatalErrors::parse(value);
            for b in bad {
                err!(ln, "Unknown FatalErrors kind \"{}\" ignored.", b);
            }
            *fatal = f;
        } else if name.eq_ignore_ascii_case("FileDevice") && value.is_some() {
            let v = value.unwrap();
            if matches!(v.to_ascii_lowercase().as_str(), "false" | "no" | "off") {
                cfg.file_device = None;
            } else {
                let pat = if matches!(v.to_ascii_lowercase().as_str(), "on" | "true" | "yes") {
                    "^/dev/tty[A-Za-z0-9._]+$".to_string()
                } else if v.starts_with('^') {
                    v.to_string()
                } else {
                    err!(ln, "Unsupported FileDevice \"{}\" on line {} of {}.", v, ln, filename);
                    fatal_if!(FatalErrors::CONFIG);
                    cfg.file_device = None;
                    continue;
                };
                cfg.file_device = Some(pat);
            }
        } else if name.eq_ignore_ascii_case("Group") && value.is_some() {
            let v = value.unwrap();
            if v.as_bytes().first().is_some_and(u8::is_ascii_digit) {
                cfg.group = v.parse().unwrap_or(cfg.group);
            } else if let Some(gid) = resolve_group(v) {
                cfg.group = gid;
            } else {
                err!(ln, "Unknown Group \"{}\" on line {} of {}.", v, ln, filename);
                fatal_if!(FatalErrors::CONFIG);
            }
        } else if name.eq_ignore_ascii_case("LogFileGroup") && value.is_some() {
            let v = value.unwrap();
            if v.as_bytes().first().is_some_and(u8::is_ascii_digit) {
                cfg.log_file_group = v.parse().ok();
            } else if let Some(gid) = resolve_group(v) {
                cfg.log_file_group = Some(gid);
            } else {
                err!(ln, "Unknown LogFileGroup \"{}\" on line {} of {}.", v, ln, filename);
                fatal_if!(FatalErrors::CONFIG);
            }
        } else if name.eq_ignore_ascii_case("OAuthGroup") && value.is_some() {
            let v = value.unwrap();
            let mut parts = v.splitn(2, char::is_whitespace);
            let gname = parts.next().unwrap_or("");
            let file = parts.next().unwrap_or("").trim_start();
            let joined = if file.starts_with('/') {
                file.to_string()
            } else {
                format!("{server_root}/{file}")
            };
            if !file.is_empty() && std::path::Path::new(&joined).exists() {
                cfg.oauth_groups.push((gname.to_string(), joined));
            } else {
                err!(ln, "Unable to read OAuthGroup file \"{}\" on line {} of {}.", joined, ln, filename);
                fatal_if!(FatalErrors::CONFIG);
            }
        } else if name.eq_ignore_ascii_case("PassEnv") && value.is_some() {
            for var in value.unwrap().split(|c: char| c.is_whitespace() || c == ',') {
                if var.is_empty() {
                    continue;
                }
                if PROHIBITED_ENV.contains(&var) {
                    err!(ln, "Environment variable \"{}\" cannot be passed through on line {} of {}.", var, ln, filename);
                    fatal_if!(FatalErrors::CONFIG);
                } else {
                    cfg.pass_env.push(var.to_string());
                }
            }
        } else if name.eq_ignore_ascii_case("PeerCred") && value.is_some() {
            match value.unwrap().to_ascii_lowercase().as_str() {
                "off" => cfg.peer_cred = PeerCred::Off,
                "on" => cfg.peer_cred = PeerCred::On,
                "root-only" => cfg.peer_cred = PeerCred::RootOnly,
                v => {
                    err!(ln, "Unknown PeerCred \"{}\" on line {} of {}.", v, ln, filename);
                    fatal_if!(FatalErrors::CONFIG);
                }
            }
        } else if name.eq_ignore_ascii_case("PrintcapFormat") && value.is_some() {
            match value.unwrap().to_ascii_lowercase().as_str() {
                "bsd" => cfg.printcap_format = PrintcapFormat::Bsd,
                "plist" => cfg.printcap_format = PrintcapFormat::Plist,
                "solaris" => cfg.printcap_format = PrintcapFormat::Solaris,
                v => {
                    err!(ln, "Unknown PrintcapFormat \"{}\" on line {} of {}.", v, ln, filename);
                    fatal_if!(FatalErrors::CONFIG);
                }
            }
        } else if name.eq_ignore_ascii_case("Sandboxing") && value.is_some() {
            match value.unwrap().to_ascii_lowercase().as_str() {
                "off" => cfg.sandboxing = Sandboxing::Off,
                "relaxed" => cfg.sandboxing = Sandboxing::Relaxed,
                "strict" => cfg.sandboxing = Sandboxing::Strict,
                v => {
                    err!(ln, "Unknown Sandboxing \"{}\" on line {} of {}.", v, ln, filename);
                    fatal_if!(FatalErrors::CONFIG);
                }
            }
        } else if name.eq_ignore_ascii_case("SetEnv") && value.is_some() {
            let v = value.unwrap();
            let mut parts = v.splitn(2, char::is_whitespace);
            let var = parts.next().unwrap_or("");
            let val = parts.next().map(str::trim_start).unwrap_or("");
            if val.is_empty() {
                err!(ln, "Missing value for SetEnv directive on line {} of {}.", ln, filename);
            } else if PROHIBITED_ENV.contains(&var) {
                err!(ln, "Environment variable \"{}\" cannot be set  on line {} of {}.", var, ln, filename);
                fatal_if!(FatalErrors::CONFIG);
            } else {
                cfg.set_env.push((var.to_string(), val.to_string()));
            }
        } else if name.eq_ignore_ascii_case("SystemGroup") && value.is_some() {
            for gname in split_groups(value.unwrap()) {
                if let Some(gid) = resolve_group(&gname) {
                    cfg.system_groups.push(gid);
                    cfg.system_group_names.push(gname);
                } else {
                    err!(ln, "Unknown SystemGroup \"{}\" on line {} of {}.", gname, ln, filename);
                    fatal_if!(FatalErrors::CONFIG);
                }
            }
        } else if name.eq_ignore_ascii_case("User") && value.is_some() {
            let v = value.unwrap();
            if v.as_bytes().first().is_some_and(u8::is_ascii_digit) {
                let uid: u32 = v.parse().unwrap_or(u32::MAX);
                if uid == 0 {
                    err!(ln, "Will not use User 0 as specified on line {} of {} for security reasons.  You must use a non-privileged account instead.", ln, filename);
                    fatal_if!(FatalErrors::CONFIG);
                } else {
                    cfg.user = uid;
                }
            } else if let Some(uid) = resolve_user(v) {
                if uid == 0 {
                    err!(ln, "Will not use User {} (UID=0) as specified on line {} of {} for security reasons.  You must use a non-privileged account instead.", v, ln, filename);
                    fatal_if!(FatalErrors::CONFIG);
                } else {
                    cfg.user = uid;
                }
            } else {
                err!(ln, "Unknown User \"{}\" on line {} of {}.", v, ln, filename);
                fatal_if!(FatalErrors::CONFIG);
            }
        } else if name.eq_ignore_ascii_case("ServerCertificate")
            || name.eq_ignore_ascii_case("ServerKey")
        {
            info!(ln, "The \"{}\" directive on line {} of {} is no longer supported; this will become an error in a future release.", name, ln, filename);
        } else {
            let mut sink = diags.sink(filename);
            match parse_variable_files(
                cfg,
                server_root,
                name,
                value,
                ln,
                filename,
                &mut sink,
            ) {
                Ok(_) => {}
                Err(()) => {
                    if fatal.has(FatalErrors::CONFIG) || fatal.has(FatalErrors::UNKNOWN) {
                        return false;
                    }
                }
            }
        }
    }
    let _ = ok;
    ok = true;
    ok
}

/// Split `SystemGroup` list honoring quotes (port of `parse_groups`).
fn split_groups(value: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        if bytes[i] == b'"' || bytes[i] == b'\'' {
            let q = bytes[i];
            let start = i + 1;
            let mut j = start;
            while j < bytes.len() && bytes[j] != q {
                j += 1;
            }
            out.push(value[start..j].to_string());
            i = j + usize::from(j < bytes.len());
        } else {
            let start = i;
            while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            out.push(value[start..i].to_string());
        }
    }
    out
}

/// Parse `cupsd.conf` — port of `read_cupsd_conf`.
#[allow(clippy::too_many_lines)]
pub fn read_cupsd_conf<R: BufRead>(
    r: R,
    filename: &str,
    cfg: &mut CupsdConfig,
    diags: &mut Diagnostics,
) -> bool {
    let mut lines = ConfLines::new(r);
    let fatal = cfg.fatal_errors;

    macro_rules! err {
        ($ln:expr, $($f:tt)*) => {{
            diags.entries.push(Diagnostic {
                severity: Severity::Error,
                file: filename.to_string(),
                line: $ln,
                message: format!($($f)*),
            });
        }};
    }
    macro_rules! warn {
        ($ln:expr, $($f:tt)*) => {{
            diags.entries.push(Diagnostic {
                severity: Severity::Warn,
                file: filename.to_string(),
                line: $ln,
                message: format!($($f)*),
            });
        }};
    }
    macro_rules! info {
        ($ln:expr, $($f:tt)*) => {{
            diags.entries.push(Diagnostic {
                severity: Severity::Info,
                file: filename.to_string(),
                line: $ln,
                message: format!($($f)*),
            });
        }};
    }
    macro_rules! fatal_cfg {
        () => {
            if fatal.has(FatalErrors::CONFIG) {
                return false;
            }
        };
    }

    /// Directives that belong in cups-files.conf — warn when found here.
    const MOVED: &[&str] = &[
        "AccessLog",
        "CacheDir",
        "ConfigFilePerm",
        "DataDir",
        "DocumentRoot",
        "ErrorLog",
        "FatalErrors",
        "FileDevice",
        "Group",
        "LogFilePerm",
        "PageLog",
        "PassEnv",
        "Printcap",
        "PrintcapFormat",
        "RemoteRoot",
        "RequestRoot",
        "ServerBin",
        "ServerCertificate",
        "ServerKey",
        "ServerKeychain",
        "ServerRoot",
        "SetEnv",
        "StateDir",
        "SystemGroup",
        "SystemGroupAuthKey",
        "TempDir",
        "User",
    ];

    while let Some(line) = lines.next() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                err!(0, "I/O error reading {}: {}", filename, e);
                return false;
            }
        };
        let name = line.name.as_str();
        let ln = line.linenum;

        if name.eq_ignore_ascii_case("<Location") && line.value.is_some() {
            let path = line.value.clone().unwrap();
            if !read_location(&mut lines, cfg, &path, ln, filename, diags) {
                return false;
            }
        } else if name.eq_ignore_ascii_case("<Policy") && line.value.is_some() {
            let pname = line.value.clone().unwrap();
            if !read_policy(&mut lines, cfg, &pname, ln, filename, diags) {
                return false;
            }
        } else if name.eq_ignore_ascii_case("FaxRetryInterval")
            && line.value.is_some()
        {
            cfg.job_retry_interval = line.value.as_deref().unwrap().parse().unwrap_or(0);
            warn!(ln, "FaxRetryInterval is deprecated; use JobRetryInterval on line {} of {}.", ln, filename);
        } else if name.eq_ignore_ascii_case("FaxRetryLimit") && line.value.is_some() {
            cfg.job_retry_limit = line.value.as_deref().unwrap().parse().unwrap_or(0);
            warn!(ln, "FaxRetryLimit is deprecated; use JobRetryLimit on line {} of {}.", ln, filename);
        } else if name.eq_ignore_ascii_case("SSLOptions") {
            parse_ssl_options(&line, &mut cfg.tls_options, filename, diags);
        } else if (name.eq_ignore_ascii_case("Port")
            || name.eq_ignore_ascii_case("Listen")
            || name.eq_ignore_ascii_case("SSLPort")
            || name.eq_ignore_ascii_case("SSLListen"))
            && line.value.is_some()
        {
            let ssl = name.eq_ignore_ascii_case("SSLPort")
                || name.eq_ignore_ascii_case("SSLListen");
            let v = line.value.as_deref().unwrap();
            add_listeners(cfg, v, ssl, ln, filename, diags);
        } else if name.eq_ignore_ascii_case("BrowseProtocols")
            || name.eq_ignore_ascii_case("BrowseLocalProtocols")
        {
            match line.value.as_deref() {
                Some(v) => match BrowseProtocols::parse(v) {
                    Ok(p) => cfg.browse_local_protocols = p,
                    Err(bad) => {
                        err!(ln, "Unknown browse protocol \"{}\" on line {} of {}.", bad, ln, filename);
                        break;
                    }
                },
                None => {
                    cfg.browse_local_protocols = BrowseProtocols(0);
                }
            }
        } else if name.eq_ignore_ascii_case("DefaultAuthType") && line.value.is_some() {
            let v = line.value.as_deref().unwrap();
            let t = if v.eq_ignore_ascii_case("none") {
                Some(AuthType::None)
            } else if v.eq_ignore_ascii_case("basic") {
                Some(AuthType::Basic)
            } else if v.eq_ignore_ascii_case("bearer") {
                Some(AuthType::Bearer)
            } else if v.eq_ignore_ascii_case("negotiate") {
                Some(AuthType::Negotiate)
            } else if v.eq_ignore_ascii_case("auto") {
                Some(AuthType::Auto)
            } else {
                None
            };
            match t {
                Some(t) => cfg.default_auth_type = t,
                None => {
                    warn!(ln, "Unknown default authorization type {} on line {} of {}.", v, ln, filename);
                    fatal_cfg!();
                }
            }
        } else if name.eq_ignore_ascii_case("DefaultEncryption") {
            let v = line.value.as_deref();
            match v {
                None => cfg.default_encryption = Encryption::Never,
                Some(v) if v.eq_ignore_ascii_case("never") => {
                    cfg.default_encryption = Encryption::Never;
                }
                Some(v) if v.eq_ignore_ascii_case("required") => {
                    cfg.default_encryption = Encryption::Required;
                }
                Some(v) if v.eq_ignore_ascii_case("ifrequested") => {
                    cfg.default_encryption = Encryption::IfRequested;
                }
                Some(v) => {
                    warn!(ln, "Unknown default encryption {} on line {} of {}.", v, ln, filename);
                    fatal_cfg!();
                }
            }
        } else if name.eq_ignore_ascii_case("HostNameLookups") && line.value.is_some() {
            let v = line.value.as_deref().unwrap();
            if matches!(v.to_ascii_lowercase().as_str(), "off" | "no" | "false") {
                cfg.host_name_lookups = 0;
            } else if matches!(v.to_ascii_lowercase().as_str(), "on" | "yes" | "true") {
                cfg.host_name_lookups = 1;
            } else if v.eq_ignore_ascii_case("double") {
                cfg.host_name_lookups = 2;
            } else {
                warn!(ln, "Unknown HostNameLookups {} on line {} of {}.", v, ln, filename);
            }
        } else if name.eq_ignore_ascii_case("AccessLogLevel") && line.value.is_some() {
            match line.value.as_deref().unwrap().to_ascii_lowercase().as_str() {
                "all" => cfg.access_log_level = AccessLogLevel::All,
                "actions" => cfg.access_log_level = AccessLogLevel::Actions,
                "config" => cfg.access_log_level = AccessLogLevel::Config,
                "none" => cfg.access_log_level = AccessLogLevel::None,
                v => warn!(ln, "Unknown AccessLogLevel {} on line {} of {}.", v, ln, filename),
            }
        } else if name.eq_ignore_ascii_case("LogLevel") && line.value.is_some() {
            match LogLevel::parse(line.value.as_deref().unwrap()) {
                Some(l) => cfg.log_level = l,
                None => warn!(ln, "Unknown LogLevel {} on line {} of {}.", line.value.as_deref().unwrap(), ln, filename),
            }
        } else if name.eq_ignore_ascii_case("LogTimeFormat") && line.value.is_some() {
            match line.value.as_deref().unwrap().to_ascii_lowercase().as_str() {
                "standard" => cfg.log_time_format = LogTimeFormat::Standard,
                "usecs" => cfg.log_time_format = LogTimeFormat::Usecs,
                v => warn!(ln, "Unknown LogTimeFormat {} on line {} of {}.", v, ln, filename),
            }
        } else if name.eq_ignore_ascii_case("ReadyPaperSizes") && line.value.is_some() {
            cfg.ready_paper_sizes.extend(
                line.value
                    .as_deref()
                    .unwrap()
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty()),
            );
        } else if name.eq_ignore_ascii_case("ServerTokens") && line.value.is_some() {
            let v = line.value.as_deref().unwrap();
            if v.eq_ignore_ascii_case("ProductOnly") {
                cfg.server_header = "CUPS IPP".to_string();
            } else if v.eq_ignore_ascii_case("Major") {
                cfg.server_header = format!("CUPS/{} IPP/2", cups_version_major());
            } else if v.eq_ignore_ascii_case("Minor") {
                cfg.server_header = format!(
                    "CUPS/{}.{} IPP/2.1",
                    cups_version_major(),
                    cups_version_minor()
                );
            } else if v.eq_ignore_ascii_case("Minimal") {
                cfg.server_header = format!(
                    "CUPS/{}.{}-rust IPP/2.1",
                    cups_version_major(),
                    cups_version_minor()
                );
            } else if v.eq_ignore_ascii_case("OS") {
                cfg.server_header = format!(
                    "CUPS/{}.{}-rust ({} {}) IPP/2.1",
                    cups_version_major(),
                    cups_version_minor(),
                    std::env::consts::OS,
                    "kernel"
                );
            } else if v.eq_ignore_ascii_case("Full") {
                cfg.server_header = format!(
                    "CUPS/{}.{}-rust ({} {}; {}) IPP/2.1",
                    cups_version_major(),
                    cups_version_minor(),
                    std::env::consts::OS,
                    "kernel",
                    std::env::consts::ARCH
                );
            } else if v.eq_ignore_ascii_case("None") {
                cfg.server_header = String::new();
            } else {
                warn!(ln, "Unknown ServerTokens {} on line {} of {}.", v, ln, filename);
            }
        } else if name.eq_ignore_ascii_case("ServerAlias") && line.value.is_some() {
            for a in line
                .value
                .as_deref()
                .unwrap()
                .split(|c: char| c.is_whitespace() || c == ',')
            {
                if !a.is_empty() {
                    add_alias(&mut cfg.server_aliases, a);
                }
            }
        } else if name.eq_ignore_ascii_case("FilterNice") && line.value.is_some() {
            match line.value.as_deref().unwrap().parse::<i64>() {
                Ok(n) if (0..=19).contains(&n) => cfg.filter_nice = n as i32,
                _ => {
                    warn!(ln, "The directive FilterNice accepts values 0 to 19.");
                    fatal_cfg!();
                }
            }
        } else if MOVED.iter().any(|d| d.eq_ignore_ascii_case(name)) {
            info!(ln, "Please move \"{}{}\" on line {} of {} to the {} file; this will become an error in a future release.",
                  name,
                  line.value.as_deref().map(|v| format!(" {v}")).unwrap_or_default(),
                  ln, filename, "cups-files.conf");
        } else {
            let value = line.value.as_deref();
            let mut sink = diags.sink(filename);
            match parse_variable_cupsd(cfg, name, value, ln, filename, &mut sink) {
                Ok(false) => {
                    // Unknown directive — fatal only if UNKNOWN bit set.
                    if fatal.has(FatalErrors::UNKNOWN) {
                        return false;
                    }
                }
                Ok(true) => {}
                Err(()) => {
                    fatal_cfg!();
                }
            }
        }
    }
    true
}

/// Add a `ServerAlias` honoring `*`/case folding like `cupsdAddAlias`.
fn add_alias(aliases: &mut Vec<String>, name: &str) {
    // cupsd stores aliases lowercase, "*" allowed.
    let n = name.to_ascii_lowercase();
    if !aliases.contains(&n) {
        aliases.push(n);
    }
}

/// Parse `SSLOptions` values (port of the inline block in conf.c).
fn parse_ssl_options(
    line: &ConfLine,
    opts: &mut TlsOptions,
    filename: &str,
    diags: &mut Diagnostics,
) {
    let Some(v) = line.value.as_deref() else {
        return;
    };
    for w in v.split_whitespace() {
        match w.to_ascii_lowercase().as_str() {
            "allowrc4" => opts.allow_rc4 = true,
            "allowssl3" => opts.min_version = TlsVersion::Ssl3,
            "allowdh" => opts.allow_dh = true,
            "denycbc" => opts.deny_cbc = true,
            "denytls1.0" => opts.min_version = TlsVersion::V1_1,
            "maxtls1.0" => opts.max_version = TlsVersion::V1_0,
            "maxtls1.1" => opts.max_version = TlsVersion::V1_1,
            "maxtls1.2" => opts.max_version = TlsVersion::V1_2,
            "maxtls1.3" => opts.max_version = TlsVersion::V1_3,
            "mintls1.0" => opts.min_version = TlsVersion::V1_0,
            "mintls1.1" => opts.min_version = TlsVersion::V1_1,
            "mintls1.2" => opts.min_version = TlsVersion::V1_2,
            "mintls1.3" => opts.min_version = TlsVersion::V1_3,
            "none" => *opts = TlsOptions::default(),
            "nosystem" => opts.no_system = true,
            "noemptyfragments" => {}
            _ => diags.entries.push(Diagnostic {
                severity: Severity::Warn,
                file: filename.to_string(),
                line: line.linenum,
                message: format!("Unknown SSL option {w} at line {}.", line.linenum),
            }),
        }
    }
}

/// `get_address()` + listener dedup/append — port of the Listen/Port block.
fn add_listeners(
    cfg: &mut CupsdConfig,
    value: &str,
    ssl: bool,
    ln: usize,
    filename: &str,
    diags: &mut Diagnostics,
) {
    // Domain socket.
    if value.starts_with('/') {
        let path = value;
        if path.len() > 100 {
            diags.entries.push(Diagnostic {
                severity: Severity::Info,
                file: filename.to_string(),
                line: ln,
                message: format!("Ignoring Listen address {value} at line {ln} - too long."),
            });
            return;
        }
        let addr = ListenAddr::Unix(std::path::PathBuf::from(path));
        if cfg.listeners.iter().any(|l| l.addr == addr) {
            diags.entries.push(Diagnostic {
                severity: Severity::Warn,
                file: filename.to_string(),
                line: ln,
                message: format!("Duplicate listen address \"{value}\" ignored."),
            });
            return;
        }
        cfg.listeners.push(Listener { addr, ssl });
        return;
    }

    // host:port / [v6]:port / host / port / *
    let (host, port) = split_host_port(value, 631);
    let host = host.as_deref();
    let addrs: Vec<std::net::SocketAddr> = match host {
        None | Some("*") => vec![
            std::net::SocketAddr::from(([0, 0, 0, 0], port)),
            std::net::SocketAddr::from(([0u16; 8], port)),
        ],
        Some(h) => match (h, port).to_socket_addrs() {
            Ok(it) => it.collect(),
            Err(_) => {
                diags.entries.push(Diagnostic {
                    severity: Severity::Error,
                    file: filename.to_string(),
                    line: ln,
                    message: format!("Hostname lookup for \"{h}\" failed."),
                });
                return;
            }
        },
    };

    for a in addrs {
        let addr = ListenAddr::Tcp(a);
        if cfg.listeners.iter().any(|l| l.addr == addr) {
            diags.entries.push(Diagnostic {
                severity: Severity::Warn,
                file: filename.to_string(),
                line: ln,
                message: format!("Duplicate listen address \"{value}\" ignored."),
            });
            continue;
        }
        cfg.listeners.push(Listener { addr: addr.clone(), ssl });
        if let ListenAddr::Tcp(sa) = &addr {
            if !sa.ip().is_loopback() {
                cfg.remote_port = sa.port();
            }
        }
    }
}

/// Split `host:port`/`[v6]:port`/bare forms (port of get_address).
fn split_host_port(value: &str, defport: u16) -> (Option<String>, u16) {
    if let Some(rb) = value.rfind(']') {
        // [v6] or [v6]:port
        if value.starts_with('[') {
            let inner = &value[1..rb];
            let port = value[rb + 1..]
                .strip_prefix(':')
                .and_then(|p| p.parse().ok())
                .unwrap_or(defport);
            return (Some(inner.to_string()), port);
        }
    }
    if let Some(i) = value.rfind(':') {
        // host:port (single colon) or multi-colon v6 without port
        let after = &value[i + 1..];
        if value[..i].contains(':') {
            // bare v6 address
            return (Some(value.to_string()), defport);
        }
        if let Ok(p) = after.parse() {
            return (Some(value[..i].to_string()), p);
        }
        // port as service name — unsupported; treat as host only
        return (Some(value.to_string()), defport);
    }
    if value.bytes().all(|b| b.is_ascii_digit()) && !value.is_empty() {
        return (None, value.parse().unwrap_or(defport));
    }
    (Some(value.to_string()), defport)
}

/// `read_location()` — parse `<Location path>…</Location>` incl.
/// `<Limit>`/`<LimitExcept>` child copies. Returns false on fatal error.
fn read_location<R: BufRead>(
    lines: &mut ConfLines<R>,
    cfg: &mut CupsdConfig,
    path: &str,
    start_ln: usize,
    filename: &str,
    diags: &mut Diagnostics,
) -> bool {
    let fatal = cfg.fatal_errors;

    if cfg.locations.iter().any(|l| l.path == path && l.limit == limit::ALL) {
        diags.entries.push(Diagnostic {
            severity: Severity::Warn,
            file: filename.to_string(),
            line: start_ln,
            message: format!("Duplicate <Location {path}> on line {start_ln} of {filename}."),
        });
    }

    let parent_idx = cfg.locations.len();
    let mut parent = Location::new(path);
    parent.encryption = cfg.default_encryption;
    cfg.locations.push(parent.clone());

    // `loc` = index of the currently-edited location.
    let mut cur_idx = parent_idx;

    while let Some(line) = lines.next() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                diags.entries.push(Diagnostic {
                    severity: Severity::Error,
                    file: filename.to_string(),
                    line: 0,
                    message: format!("I/O error: {e}"),
                });
                return false;
            }
        };
        let name = line.name.as_str();
        let ln = line.linenum;

        if name.eq_ignore_ascii_case("</Location>") {
            return true;
        } else if name.eq_ignore_ascii_case("<Limit")
            || name.eq_ignore_ascii_case("<LimitExcept")
        {
            let Some(v) = line.value.as_deref() else {
                diags.entries.push(Diagnostic {
                    severity: Severity::Error,
                    file: filename.to_string(),
                    line: ln,
                    message: format!("Syntax error on line {ln} of {filename}."),
                });
                if fatal.has(FatalErrors::CONFIG) {
                    return false;
                }
                continue;
            };

            // Child copy of parent with a method bitmask.
            let mut child = cfg.locations[parent_idx].clone();
            child.limit = 0;
            for m in v.split_whitespace() {
                let bits = if m.eq_ignore_ascii_case("ALL") {
                    limit::ALL
                } else if m.eq_ignore_ascii_case("GET") {
                    limit::GET
                } else if m.eq_ignore_ascii_case("HEAD") {
                    limit::HEAD
                } else if m.eq_ignore_ascii_case("OPTIONS") {
                    limit::OPTIONS
                } else if m.eq_ignore_ascii_case("POST") {
                    limit::POST
                } else if m.eq_ignore_ascii_case("PUT") {
                    limit::PUT
                } else if m.eq_ignore_ascii_case("TRACE") {
                    limit::TRACE
                } else if m.eq_ignore_ascii_case("DELETE") {
                    limit::DELETE
                } else {
                    diags.entries.push(Diagnostic {
                        severity: Severity::Warn,
                        file: filename.to_string(),
                        line: ln,
                        message: format!(
                            "Unknown request type {m} on line {ln} of {filename}."
                        ),
                    });
                    0
                };
                child.limit |= bits;
            }
            if name.eq_ignore_ascii_case("<LimitExcept") {
                child.limit = limit::ALL ^ child.limit;
            }
            cfg.locations[parent_idx].limit &= !child.limit;
            cfg.locations.push(child);
            cur_idx = cfg.locations.len() - 1;
        } else if name.eq_ignore_ascii_case("</Limit>")
            || name.eq_ignore_ascii_case("</LimitExcept>")
        {
            cur_idx = parent_idx;
        } else if line.value.is_none() {
            diags.entries.push(Diagnostic {
                severity: Severity::Error,
                file: filename.to_string(),
                line: ln,
                message: format!("Missing value on line {ln} of {filename}."),
            });
            if fatal.has(FatalErrors::CONFIG) {
                return false;
            }
        } else {
            let mut sink = diags.sink(filename);
            match parse_aaa(&mut cfg.locations[cur_idx], &line, &mut sink, filename) {
                AaaResult::Ok => {}
                AaaResult::Unknown => {
                    sink.log(
                        Severity::Error,
                        ln,
                        format!("Unknown Location directive {name} on line {ln} of {filename}."),
                    );
                    if fatal.has(FatalErrors::CONFIG) {
                        return false;
                    }
                }
                AaaResult::Error => {
                    if fatal.has(FatalErrors::CONFIG) {
                        return false;
                    }
                }
            }
        }
    }

    diags.entries.push(Diagnostic {
        severity: Severity::Error,
        file: filename.to_string(),
        line: lines.linenum(),
        message: format!(
            "Unexpected end-of-file at line {} while reading location.",
            lines.linenum()
        ),
    });
    !fatal.has(FatalErrors::CONFIG)
}

/// `read_policy()` — parse `<Policy name>…</Policy>`.
fn read_policy<R: BufRead>(
    lines: &mut ConfLines<R>,
    cfg: &mut CupsdConfig,
    name: &str,
    start_ln: usize,
    filename: &str,
    diags: &mut Diagnostics,
) -> bool {
    let fatal = cfg.fatal_errors;

    if cfg.policies.iter().any(|p| p.name == name) {
        diags.entries.push(Diagnostic {
            severity: Severity::Warn,
            file: filename.to_string(),
            line: start_ln,
            message: format!("Duplicate <Policy {name}> on line {start_ln} of {filename}."),
        });
    }

    let pidx = cfg.policies.len();
    cfg.policies.push(Policy {
        name: name.to_string(),
        ops: Vec::new(),
        job_access: Vec::new(),
        job_values: Vec::new(),
        sub_access: Vec::new(),
        sub_values: Vec::new(),
    });

    // Current `<Limit>` op codes + accumulated ACL (built on a Location).
    let mut cur_ops: Vec<u32> = Vec::new();
    let mut cur_loc: Option<Location> = None;

    while let Some(line) = lines.next() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                diags.entries.push(Diagnostic {
                    severity: Severity::Error,
                    file: filename.to_string(),
                    line: 0,
                    message: format!("I/O error: {e}"),
                });
                return false;
            }
        };
        let lname = line.name.as_str();
        let ln = line.linenum;

        if lname.eq_ignore_ascii_case("</Policy>") {
            if cur_loc.is_some() {
                diags.entries.push(Diagnostic {
                    severity: Severity::Warn,
                    file: filename.to_string(),
                    line: ln,
                    message: format!(
                        "Missing </Limit> before </Policy> on line {ln} of {filename}."
                    ),
                });
            }
            return true;
        } else if lname.eq_ignore_ascii_case("<Limit") && cur_loc.is_none() {
            let Some(v) = line.value.as_deref() else {
                diags.entries.push(Diagnostic {
                    severity: Severity::Error,
                    file: filename.to_string(),
                    line: ln,
                    message: format!("Syntax error on line {ln} of {filename}."),
                });
                if fatal.has(FatalErrors::CONFIG) {
                    return false;
                }
                continue;
            };

            cur_ops.clear();
            for opname in v.split_whitespace() {
                if cur_ops.len() >= 100 {
                    diags.entries.push(Diagnostic {
                        severity: Severity::Error,
                        file: filename.to_string(),
                        line: ln,
                        message: format!(
                            "Too many operations listed on line {ln} of {filename}."
                        ),
                    });
                    break;
                }
                if opname.eq_ignore_ascii_case("All") {
                    cur_ops.push(ipp_codec::ops::op::ANY_OPERATION);
                } else {
                    match ipp_codec::ops::op::value(opname) {
                        Some(op) => cur_ops.push(u32::from(op)),
                        None => diags.entries.push(Diagnostic {
                            severity: Severity::Error,
                            file: filename.to_string(),
                            line: ln,
                            message: format!(
                                "Bad IPP operation name \"{opname}\" on line {ln} of {filename}."
                            ),
                        }),
                    }
                }
            }
            if cur_ops.is_empty() {
                cur_ops.push(ipp_codec::ops::op::ANY_OPERATION);
            }
            cur_loc = Some(Location::new(name));
        } else if lname.eq_ignore_ascii_case("</Limit>") && cur_loc.is_some() {
            let loc = cur_loc.take().unwrap();
            for &op in &cur_ops {
                cfg.policies[pidx].ops.push(PolicyOp {
                    op,
                    loc: loc.clone(),
                });
            }
            cur_ops.clear();
        } else if line.value.is_none() {
            diags.entries.push(Diagnostic {
                severity: Severity::Error,
                file: filename.to_string(),
                line: ln,
                message: format!("Missing value on line {ln} of {filename}."),
            });
            if fatal.has(FatalErrors::CONFIG) {
                return false;
            }
        } else if lname.eq_ignore_ascii_case("JobPrivateAccess")
            || lname.eq_ignore_ascii_case("JobPrivateValues")
            || lname.eq_ignore_ascii_case("SubscriptionPrivateAccess")
            || lname.eq_ignore_ascii_case("SubscriptionPrivateValues")
        {
            if cur_loc.is_some() {
                diags.entries.push(Diagnostic {
                    severity: Severity::Error,
                    file: filename.to_string(),
                    line: ln,
                    message: format!(
                        "{lname} directive must appear outside <Limit>...</Limit> on line {ln} of {filename}."
                    ),
                });
                if fatal.has(FatalErrors::CONFIG) {
                    return false;
                }
            } else {
                let v = line.value.as_deref().unwrap();
                for tok in v.split_whitespace() {
                    if lname.eq_ignore_ascii_case("JobPrivateAccess") {
                        if tok.eq_ignore_ascii_case("default") {
                            cfg.policies[pidx].job_access.push("@OWNER".into());
                            cfg.policies[pidx].job_access.push("@SYSTEM".into());
                        } else {
                            cfg.policies[pidx].job_access.push(tok.to_string());
                        }
                    } else if lname.eq_ignore_ascii_case("JobPrivateValues") {
                        if tok.eq_ignore_ascii_case("default") {
                            for a in [
                                "job-name",
                                "job-originating-host-name",
                                "job-originating-user-name",
                                "phone",
                            ] {
                                cfg.policies[pidx].job_values.push(a.to_string());
                            }
                        } else {
                            cfg.policies[pidx].job_values.push(tok.to_string());
                        }
                    } else if lname.eq_ignore_ascii_case("SubscriptionPrivateAccess") {
                        if tok.eq_ignore_ascii_case("default") {
                            cfg.policies[pidx].sub_access.push("@OWNER".into());
                            cfg.policies[pidx].sub_access.push("@SYSTEM".into());
                        } else {
                            cfg.policies[pidx].sub_access.push(tok.to_string());
                        }
                    } else if tok.eq_ignore_ascii_case("default") {
                        for a in [
                            "notify-events",
                            "notify-pull-method",
                            "notify-recipient-uri",
                            "notify-subscriber-user-name",
                            "notify-user-data",
                        ] {
                            cfg.policies[pidx].sub_values.push(a.to_string());
                        }
                    } else {
                        cfg.policies[pidx].sub_values.push(tok.to_string());
                    }
                }
            }
        } else if let Some(loc) = cur_loc.as_mut() {
            let mut sink = diags.sink(filename);
            match parse_aaa(loc, &line, &mut sink, filename) {
                AaaResult::Ok => {}
                AaaResult::Unknown => {
                    sink.log(
                        Severity::Error,
                        ln,
                        format!("Unknown Policy directive {lname} on line {ln} of {filename}."),
                    );
                    if fatal.has(FatalErrors::CONFIG) {
                        return false;
                    }
                }
                AaaResult::Error => {
                    if fatal.has(FatalErrors::CONFIG) {
                        return false;
                    }
                }
            }
        } else {
            diags.entries.push(Diagnostic {
                severity: Severity::Error,
                file: filename.to_string(),
                line: ln,
                message: format!(
                    "Policy directive {lname} outside <Limit> on line {ln} of {filename}."
                ),
            });
            if fatal.has(FatalErrors::CONFIG) {
                return false;
            }
        }
    }

    diags.entries.push(Diagnostic {
        severity: Severity::Error,
        file: filename.to_string(),
        line: lines.linenum(),
        message: format!(
            "Unexpected end-of-file at line {} while reading policy.",
            lines.linenum()
        ),
    });
    !fatal.has(FatalErrors::CONFIG)
}

/// Build the synthesized "default" policy cupsd creates when the config
/// defines none (port of the block at conf.c ~1441-1615).
pub fn default_policy() -> Policy {
    use ipp_codec::ops::op as ops;

    let mut p = Policy {
        name: "default".to_string(),
        ops: Vec::new(),
        job_access: vec!["@OWNER".into(), "@SYSTEM".into()],
        job_values: vec![
            "job-name".into(),
            "job-originating-host-name".into(),
            "job-originating-user-name".into(),
            "phone".into(),
        ],
        sub_access: vec!["@OWNER".into(), "@SYSTEM".into()],
        sub_values: Vec::new(),
    };
    // Upstream quirk (conf.c): the "SubscriptionPrivateValues default"
    // block adds the notify-* names to `p->job_attrs` — replicate.
    for a in [
        "notify-events",
        "notify-pull-method",
        "notify-recipient-uri",
        "notify-subscriber-user-name",
        "notify-user-data",
    ] {
        p.job_values.push(a.to_string());
    }

    let anon_loc = |order| {
        let mut l = Location::new("<policy>");
        l.order = order;
        l
    };
    let user_loc = |names: &[&str]| {
        let mut l = Location::new("<policy>");
        l.order = OrderType::Allow;
        l.auth_level = AuthLevel::User;
        l.names = names.iter().map(|s| s.to_string()).collect();
        l
    };
    let auth_loc = |names: &[&str]| {
        let mut l = user_loc(names);
        l.auth_type = AuthType::Default;
        l
    };
    let mut add = |ops_list: &[u16], loc: Location| {
        for &op in ops_list {
            p.ops.push(PolicyOp {
                op: u32::from(op),
                loc: loc.clone(),
            });
        }
    };

    // Create-Job Print-Job Print-URI Validate-Job — anonymous.
    add(
        &[
            ops::CREATE_JOB,
            ops::PRINT_JOB,
            ops::PRINT_URI,
            ops::VALIDATE_JOB,
        ],
        anon_loc(OrderType::Allow),
    );

    // Job-owner ops — Require user @OWNER @SYSTEM.
    add(
        &[
            ops::SEND_DOCUMENT,
            ops::SEND_URI,
            ops::HOLD_JOB,
            ops::RELEASE_JOB,
            ops::RESTART_JOB,
            ops::PURGE_JOBS,
            ops::SET_JOB_ATTRIBUTES,
            ops::CREATE_JOB_SUBSCRIPTIONS,
            ops::RENEW_SUBSCRIPTION,
            ops::CANCEL_SUBSCRIPTION,
            ops::GET_NOTIFICATIONS,
            ops::REPROCESS_JOB,
            ops::CANCEL_CURRENT_JOB,
            ops::SUSPEND_CURRENT_JOB,
            ops::RESUME_JOB,
            ops::CANCEL_MY_JOBS,
            ops::CLOSE_JOB,
            ops::CUPS_MOVE_JOB,
        ],
        user_loc(&["@OWNER", "@SYSTEM"]),
    );

    // CUPS-Get-Document — AuthType Default + @OWNER @SYSTEM.
    add(&[ops::CUPS_GET_DOCUMENT], auth_loc(&["@OWNER", "@SYSTEM"]));

    // Admin ops — AuthType Default + @SYSTEM.
    add(
        &[
            ops::PAUSE_PRINTER,
            ops::RESUME_PRINTER,
            ops::SET_PRINTER_ATTRIBUTES,
            ops::ENABLE_PRINTER,
            ops::DISABLE_PRINTER,
            ops::PAUSE_PRINTER_AFTER_CURRENT_JOB,
            ops::HOLD_NEW_JOBS,
            ops::RELEASE_HELD_NEW_JOBS,
            ops::DEACTIVATE_PRINTER,
            ops::ACTIVATE_PRINTER,
            ops::RESTART_PRINTER,
            ops::SHUTDOWN_PRINTER,
            ops::STARTUP_PRINTER,
            ops::PROMOTE_JOB,
            ops::SCHEDULE_JOB_AFTER,
            ops::CANCEL_JOBS,
            ops::CUPS_ADD_MODIFY_PRINTER,
            ops::CUPS_DELETE_PRINTER,
            ops::CUPS_ADD_MODIFY_CLASS,
            ops::CUPS_DELETE_CLASS,
            ops::CUPS_ACCEPT_JOBS,
            ops::CUPS_REJECT_JOBS,
            ops::CUPS_SET_DEFAULT,
        ],
        auth_loc(&["@SYSTEM"]),
    );

    // Cancel-Job — @OWNER + print-operator auth (@SYSTEM on Linux).
    add(&[ops::CANCEL_JOB], user_loc(&["@OWNER", "@SYSTEM"]));

    // CUPS-Authenticate-Job — AuthType Default + @OWNER @SYSTEM.
    add(
        &[ops::CUPS_AUTHENTICATE_JOB],
        auth_loc(&["@OWNER", "@SYSTEM"]),
    );

    // <Limit All> fallback — anonymous.
    p.ops.push(PolicyOp {
        op: ops::ANY_OPERATION,
        loc: anon_loc(OrderType::Allow),
    });
    p
}

/// Apply a listener config default when no Listen lines were given:
/// cupsd binds the default domain socket + localhost:631.
pub fn default_listeners(cfg: &mut CupsdConfig) {
    if cfg.listeners.is_empty() {
        cfg.listeners.push(Listener {
            addr: ListenAddr::Tcp("127.0.0.1:631".parse().unwrap()),
            ssl: false,
        });
        cfg.listeners.push(Listener {
            addr: ListenAddr::Tcp("[::1]:631".parse().unwrap()),
            ssl: false,
        });
    }
}
