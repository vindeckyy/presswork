//! Shared configuration types — constants mirror `scheduler/conf.h`,
//! `scheduler/auth.h`, and `config.h` from upstream cupsd.

use std::fmt;
use std::net::IpAddr;

/// `HTTP_ENCRYPTION_*` — required TLS level for a location or default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Encryption {
    /// Never offer/require TLS on this path.
    Never,
    /// Offer TLS; use it only if the client requests (RFC 2817 upgrade).
    #[default]
    IfRequested,
    /// Require TLS for all requests on this path.
    Required,
    /// Listener-level TLS (`SSLListen`) — always encrypted, no upgrade.
    Always,
}

/// `CUPSD_AUTH_*` authentication type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthType {
    /// Use `DefaultAuthType`.
    #[default]
    Default,
    /// No authentication.
    None,
    /// HTTP Basic (PAM/local).
    Basic,
    /// OAuth Bearer.
    Bearer,
    /// Kerberos Negotiate (feature `gssapi`).
    Negotiate,
    /// Auto: Negotiate/Bearer/Basic depending on server config.
    Auto,
}

/// `CUPSD_AUTH_ANON/USER/GROUP` — required authentication level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, PartialOrd, Ord)]
pub enum AuthLevel {
    /// Anonymous access.
    #[default]
    Anon = 0,
    /// Must have a valid username/password.
    User = 1,
    /// Must also be in a named group.
    Group = 2,
}

/// `CUPSD_AUTH_ALLOW/DENY` — which rule list wins when both match.
///
/// `Order allow,deny` → `Deny` wins (deny is evaluated last).
/// `Order deny,allow` → `Allow` wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OrderType {
    /// `Order deny,allow` — allow rules override denies.
    #[default]
    Allow,
    /// `Order allow,deny` — deny rules override allows.
    Deny,
}

/// `CUPSD_AUTH_SATISFY_*` — whether host rules AND auth rules must hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Satisfy {
    /// Both address and authentication must succeed.
    #[default]
    All,
    /// Either suffices.
    Any,
}

/// HTTP method limit bitmask (`CUPSD_AUTH_LIMIT_*`).
pub mod limit {
    /// DELETE requests.
    pub const DELETE: u32 = 1;
    /// GET requests.
    pub const GET: u32 = 2;
    /// HEAD requests.
    pub const HEAD: u32 = 4;
    /// OPTIONS requests.
    pub const OPTIONS: u32 = 8;
    /// POST requests.
    pub const POST: u32 = 16;
    /// PUT requests.
    pub const PUT: u32 = 32;
    /// TRACE requests.
    pub const TRACE: u32 = 64;
    /// All request types.
    pub const ALL: u32 = 127;
    /// IPP requests (policy op mapping marker).
    pub const IPP: u32 = 128;
}

/// `cupsdLogLevel` — `error_log` verbosity (`CUPSD_LOG_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, PartialOrd, Ord)]
pub enum LogLevel {
    /// No logging.
    None = -1,
    /// Emergency conditions.
    Emerg = 0,
    /// Alert conditions.
    Alert = 1,
    /// Critical errors.
    Crit = 2,
    /// Normal errors.
    Error = 3,
    /// Warnings — the default.
    #[default]
    Warn = 4,
    /// Normal informational messages.
    Notice = 5,
    /// Informational messages.
    Info = 6,
    /// Debug messages.
    Debug = 7,
    /// Verbose debug.
    Debug2 = 8,
}

impl LogLevel {
    /// Parse a `LogLevel` directive value.
    #[must_use]
    pub fn parse(v: &str) -> Option<Self> {
        Some(match v.to_ascii_lowercase().as_str() {
            "debug2" => Self::Debug2,
            "debug" => Self::Debug,
            "info" => Self::Info,
            "notice" => Self::Notice,
            "warn" => Self::Warn,
            "error" => Self::Error,
            "crit" => Self::Crit,
            "alert" => Self::Alert,
            "emerg" => Self::Emerg,
            "none" => Self::None,
            _ => return None,
        })
    }

    /// cupsd.conf string form.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Debug2 => "debug2",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Notice => "notice",
            Self::Warn => "warn",
            Self::Error => "error",
            Self::Crit => "crit",
            Self::Alert => "alert",
            Self::Emerg => "emerg",
            Self::None => "none",
        }
    }
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// `CUPSD_ACCESSLOG_*` — what goes to `access_log`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AccessLogLevel {
    /// Log nothing.
    None,
    /// Config requests only.
    Config,
    /// Config + print + job management requests (default).
    #[default]
    Actions,
    /// Everything.
    All,
}

/// `CUPSD_TIME_*` — `error_log` timestamp format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogTimeFormat {
    /// Standard Apache/CLF format.
    #[default]
    Standard,
    /// Standard with microseconds.
    Usecs,
}

/// `CUPSD_SANDBOXING_*` — filter sandbox policy level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Sandboxing {
    /// No sandboxing (non-root only upstream).
    Off,
    /// Relaxed sandboxing.
    Relaxed,
    /// Strict sandboxing (default).
    #[default]
    Strict,
}

/// `PRINTCAP_*` — /etc/printcap generation format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PrintcapFormat {
    /// Berkeley LPD format.
    #[default]
    Bsd,
    /// Solaris lpsched format.
    Solaris,
    /// macOS plist format.
    Plist,
}

/// `CUPSD_PEERCRED_*` — domain-socket peer credential auth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PeerCred {
    /// Disabled.
    Off,
    /// Enabled for all users (default).
    #[default]
    On,
    /// Root only.
    RootOnly,
}

/// `CUPSD_FATAL_*` — which error classes abort startup/config-test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FatalErrors(pub u32);

impl FatalErrors {
    /// No errors fatal.
    pub const NONE: Self = Self(0);
    /// Browse bind errors fatal.
    pub const BROWSE: Self = Self(1);
    /// Config syntax errors fatal.
    pub const CONFIG: Self = Self(2);
    /// Listen bind errors fatal.
    pub const LISTEN: Self = Self(4);
    /// Log file errors fatal.
    pub const LOG: Self = Self(8);
    /// File permission errors fatal.
    pub const PERMISSIONS: Self = Self(16);
    /// Unknown directive errors fatal.
    pub const UNKNOWN: Self = Self(32);

    /// Parse the `FatalErrors` directive value
    /// (`none all browse config listen log permissions unknown`, `-x` removes).
    #[must_use]
    pub fn parse(s: Option<&str>) -> (Self, Vec<String>) {
        let mut fatal = 0u32;
        let mut bad = Vec::new();
        let Some(s) = s else {
            return (Self::NONE, bad);
        };
        for word in s.split(|c: char| c.is_whitespace() || c == ',') {
            if word.is_empty() {
                continue;
            }
            let w = word.to_ascii_lowercase();
            match w.as_str() {
                "all" => fatal = u32::MAX,
                "browse" => fatal |= Self::BROWSE.0,
                "-browse" => fatal &= !Self::BROWSE.0,
                "config" => fatal |= Self::CONFIG.0,
                "-config" => fatal &= !Self::CONFIG.0,
                "listen" => fatal |= Self::LISTEN.0,
                "-listen" => fatal &= !Self::LISTEN.0,
                "log" => fatal |= Self::LOG.0,
                "-log" => fatal &= !Self::LOG.0,
                "permissions" => fatal |= Self::PERMISSIONS.0,
                "-permissions" => fatal &= !Self::PERMISSIONS.0,
                "unknown" => fatal |= Self::UNKNOWN.0,
                "-unknown" => fatal &= !Self::UNKNOWN.0,
                "none" => {}
                _ => bad.push(word.to_string()),
            }
        }
        (Self(fatal), bad)
    }

    /// True if `mask` bits are set fatal.
    #[must_use]
    pub fn has(self, mask: Self) -> bool {
        self.0 & mask.0 != 0
    }
}

impl Default for FatalErrors {
    /// `CUPS_DEFAULT_FATAL_ERRORS` = "config".
    fn default() -> Self {
        Self::CONFIG
    }
}

/// Browse protocol bitmask (`BROWSE_*` — 2.5 keeps only DNS-SD).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrowseProtocols(pub u32);

impl BrowseProtocols {
    /// DNS Service Discovery.
    pub const DNSSD: Self = Self(1);
    /// All protocols (alias — upstream collapsed to DNSSD-only).
    pub const ALL: Self = Self(1);

    /// Parse `Browse*Protocols` value; `Err` on unknown token.
    pub fn parse(s: &str) -> Result<Self, String> {
        let mut bits = 0;
        for w in s.split(|c: char| c.is_whitespace() || c == ',') {
            if w.is_empty() {
                continue;
            }
            match w.to_ascii_lowercase().as_str() {
                "all" => bits |= Self::ALL.0,
                "dnssd" => bits |= Self::DNSSD.0,
                "none" => {}
                other => return Err(other.to_string()),
            }
        }
        Ok(Self(bits))
    }
}

impl Default for BrowseProtocols {
    /// `CUPS_DEFAULT_BROWSE_LOCAL_PROTOCOLS` = "dnssd".
    fn default() -> Self {
        Self::DNSSD
    }
}

/// TLS option flags + min/max protocol version (`SSLOptions`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // TLS option bits mirror upstream _HTTP_TLS_* flags
pub struct TlsOptions {
    /// Option bits (`_HTTP_TLS_*`): `allow_rc4`, `allow_dh`, `deny_cbc`,
    /// `no_system`, `no_empty_fragments`.
    pub allow_rc4: bool,
    /// DH cipher suites allowed.
    pub allow_dh: bool,
    /// CBC suites denied.
    pub deny_cbc: bool,
    /// Skip system trust store.
    pub no_system: bool,
    /// Minimum TLS version.
    pub min_version: TlsVersion,
    /// Maximum TLS version.
    pub max_version: TlsVersion,
}

impl Default for TlsOptions {
    fn default() -> Self {
        Self {
            allow_rc4: false,
            allow_dh: false,
            deny_cbc: false,
            no_system: false,
            min_version: TlsVersion::V1_0,
            max_version: TlsVersion::Max,
        }
    }
}

/// TLS protocol version selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TlsVersion {
    /// `SSLv3` (only via `AllowSSL3` — rustls cannot honor this).
    Ssl3,
    /// TLS 1.0.
    V1_0,
    /// TLS 1.1.
    V1_1,
    /// TLS 1.2.
    V1_2,
    /// TLS 1.3.
    V1_3,
    /// Whatever the TLS stack supports maximum.
    Max,
}

/// A host allow/deny mask — `cupsd` stores these as `http_addrlist_t`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostMask {
    /// IPv4/IPv6 network: address + netmask (up to 16 bytes each).
    Ip {
        /// Address bytes (4 for v4, 16 for v6).
        addr: IpNet,
        /// Mask bytes, same width as `addr`.
        mask: IpNet,
    },
    /// Host/domain name pattern (`.example.com`, `host.name`, `@LOCAL`,
    /// interface name `@IFname`).
    Name(String),
}

/// Raw address bytes — 4 or 16.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpNet {
    /// IPv4.
    V4([u8; 4]),
    /// IPv6.
    V6([u8; 16]),
}

impl IpNet {
    /// Number of address bits.
    #[must_use]
    pub fn bits(&self) -> u32 {
        match self {
            Self::V4(_) => 32,
            Self::V6(_) => 128,
        }
    }
}

impl From<IpAddr> for IpNet {
    fn from(a: IpAddr) -> Self {
        match a {
            IpAddr::V4(v4) => Self::V4(v4.octets()),
            IpAddr::V6(v6) => Self::V6(v6.octets()),
        }
    }
}

/// A listener address from `Listen`/`Port`/`SSLListen`/`SSLPort`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listener {
    /// Bind address (or unix socket path).
    pub addr: ListenAddr,
    /// `true` when added via `SSLListen`/`SSLPort` (always-TLS).
    pub ssl: bool,
}

/// Listener bind target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListenAddr {
    /// TCP socket.
    Tcp(std::net::SocketAddr),
    /// Unix domain socket path.
    Unix(std::path::PathBuf),
}

/// Error policy values (`ErrorPolicy` directive / per-printer).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ErrorPolicy {
    /// Abort the job on backend/filter error.
    AbortJob,
    /// Retry the job (JobRetryLimit/Interval).
    RetryJob,
    /// Retry this job at next boot.
    RetryCurrentJob,
    /// Stop the printer (default).
    #[default]
    StopPrinter,
}
