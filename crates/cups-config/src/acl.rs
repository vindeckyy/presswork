//! `<Location>`/`<Limit>`/`<LimitExcept>` model + `parse_aaa` — the
//! authentication/authorization/access-control directive parser ported
//! from `scheduler/conf.c`.

use crate::lexer::ConfLine;
use crate::types::{
    limit, AuthLevel, AuthType, Encryption, HostMask, IpNet, OrderType, Satisfy,
};

/// One `<Location>` (or one `<Limit>` variant of it, or one `<Policy>`
/// operation limit — same structure upstream).
#[derive(Debug, Clone)]
pub struct Location {
    /// Path this location applies to (`/`, `/admin`, `/printers/x`…),
    /// or the policy op name inside `<Policy>` blocks.
    pub path: String,
    /// HTTP-method bitmask this location limits (`CUPSD_AUTH_LIMIT_*`).
    pub limit: u32,
    /// `Order` — which of allow/deny wins.
    pub order: OrderType,
    /// `Allow` host masks.
    pub allow: Vec<HostMask>,
    /// `Deny` host masks.
    pub deny: Vec<HostMask>,
    /// `AuthType`.
    pub auth_type: AuthType,
    /// Auth level required (anon/user/group).
    pub auth_level: AuthLevel,
    /// Required user/group names (`Require user a b`, `Require group g`,
    /// `@SYSTEM`, `@OWNER`, `valid-user` marker, etc.).
    pub names: Vec<String>,
    /// `Encryption` level required.
    pub encryption: Encryption,
    /// `Satisfy` mode.
    pub satisfy: Satisfy,
}

impl Location {
    /// New location with cupsd's implicit defaults
    /// (`limit ALL`, `Order deny,allow`, `Encryption` from `DefaultEncryption`).
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            limit: limit::ALL,
            order: OrderType::default(),
            allow: Vec::new(),
            deny: Vec::new(),
            auth_type: AuthType::Default,
            auth_level: AuthLevel::Anon,
            names: Vec::new(),
            encryption: Encryption::default(),
            satisfy: Satisfy::default(),
        }
    }

    /// Add a name to the `Require` list (dedup not performed upstream).
    pub fn add_name(&mut self, name: impl Into<String>) {
        self.names.push(name.into());
    }
}

/// Diagnostic sink shared by all parsers.
pub trait Diag {
    /// Emit a message at `severity` for `linenum`.
    fn log(&mut self, severity: Severity, linenum: usize, msg: String);
}

/// Log severity, mapped from `CUPSD_LOG_*`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Fatal error — parse aborts if the matching `FatalErrors` bit is set.
    Error,
    /// Warning — parse continues.
    Warn,
    /// Informational.
    Info,
}

/// Result of parsing one aaa directive.
pub enum AaaResult {
    /// Directive handled.
    Ok,
    /// Unknown directive.
    Unknown,
    /// Error; `fatal` = whether `FatalErrors & CONFIG` should abort.
    Error,
}

/// `parse_aaa()` — handle one directive inside a `<Location>`/`<Limit>`/
/// `<Policy><Limit>` block. Returns `Unknown` for anything it doesn't own.
pub fn parse_aaa<D: Diag>(
    loc: &mut Location,
    line: &ConfLine,
    diags: &mut D,
    filename: &str,
) -> AaaResult {
    let name = line.name.as_str();
    let value = match &line.value {
        Some(v) => v.as_str(),
        None => {
            diags.log(
                Severity::Error,
                line.linenum,
                format!("Missing value on line {} of {}.", line.linenum, filename),
            );
            return AaaResult::Error;
        }
    };
    let l = line.linenum;

    if eq(name, "Encryption") {
        if eq(value, "never") {
            loc.encryption = Encryption::Never;
        } else if eq(value, "always") {
            diags.log(Severity::Error, l, format!(
                "Encryption value \"{value}\" on line {l} of {filename} is invalid in this context. Using \"required\" instead."));
            loc.encryption = Encryption::Required;
        } else if eq(value, "required") {
            loc.encryption = Encryption::Required;
        } else if eq(value, "ifrequested") {
            loc.encryption = Encryption::IfRequested;
        } else {
            diags.log(
                Severity::Error,
                l,
                format!("Unknown Encryption value {value} on line {l} of {filename}."),
            );
            return AaaResult::Error;
        }
    } else if eq(name, "Order") {
        if value.len() >= 4 && value[..4].eq_ignore_ascii_case("deny") {
            loc.order = OrderType::Allow; // deny evaluated first → allow wins
        } else if value.len() >= 5 && value[..5].eq_ignore_ascii_case("allow") {
            loc.order = OrderType::Deny; // allow evaluated first → deny wins
        } else {
            diags.log(
                Severity::Error,
                l,
                format!("Unknown Order value {value} on line {l} of {filename}."),
            );
            return AaaResult::Error;
        }
    } else if eq(name, "Allow") || eq(name, "Deny") {
        let is_allow = eq(name, "Allow");
        for token in HostMask::parse_list(value) {
            match token {
                Ok(m) => {
                    if is_allow {
                        loc.allow.push(m);
                    } else {
                        loc.deny.push(m);
                    }
                }
                Err(e) => {
                    diags.log(
                        Severity::Error,
                        l,
                        format!("{e} on line {l} of {filename}."),
                    );
                    return AaaResult::Error;
                }
            }
        }
    } else if eq(name, "AuthType") {
        if eq(value, "none") {
            loc.auth_type = AuthType::None;
            loc.auth_level = AuthLevel::Anon;
        } else {
            let t = if eq(value, "basic") {
                Some(AuthType::Basic)
            } else if eq(value, "bearer") {
                Some(AuthType::Bearer)
            } else if eq(value, "default") {
                Some(AuthType::Default)
            } else if eq(value, "negotiate") {
                Some(AuthType::Negotiate)
            } else {
                None
            };
            match t {
                Some(t) => {
                    loc.auth_type = t;
                    if loc.auth_level == AuthLevel::Anon {
                        loc.auth_level = AuthLevel::User;
                    }
                }
                None => {
                    diags.log(Severity::Warn, l, format!(
                        "Unknown authorization type {value} on line {l} of {filename}."));
                    return AaaResult::Error;
                }
            }
        }
    } else if eq(name, "AuthClass") {
        if eq(value, "anonymous") {
            loc.auth_type = AuthType::None;
            loc.auth_level = AuthLevel::Anon;
            diags.log(Severity::Warn, l, format!(
                "\"AuthClass {value}\" is deprecated; consider removing it from line {l}."));
        } else if eq(value, "user") {
            loc.auth_level = AuthLevel::User;
            diags.log(Severity::Warn, l, format!(
                "\"AuthClass {value}\" is deprecated; consider using \"Require valid-user\" on line {l} of {filename}."));
        } else if eq(value, "group") {
            loc.auth_level = AuthLevel::Group;
            diags.log(Severity::Warn, l, format!(
                "\"AuthClass {value}\" is deprecated; consider using \"Require user @groupname\" on line {l} of {filename}."));
        } else if eq(value, "system") {
            loc.auth_level = AuthLevel::Group;
            loc.add_name("@SYSTEM");
            diags.log(Severity::Warn, l, format!(
                "\"AuthClass {value}\" is deprecated; consider using \"Require user @SYSTEM\" on line {l} of {filename}."));
        } else {
            diags.log(Severity::Warn, l, format!(
                "Unknown authorization class {value} on line {l} of {filename}."));
            return AaaResult::Error;
        }
    } else if eq(name, "AuthGroupName") {
        loc.add_name(value);
        diags.log(Severity::Warn, l, format!(
            "\"AuthGroupName {value}\" directive is deprecated; consider using \"Require user @{value}\" on line {l} of {filename}."));
    } else if eq(name, "Require") {
        let mut words = split_require(value);
        let kind = if words.is_empty() {
            ""
        } else {
            words.remove(0)
        };
        if eq(kind, "valid-user") || eq(kind, "user") {
            if loc.auth_level == AuthLevel::Anon {
                loc.auth_level = AuthLevel::User;
            }
        } else if eq(kind, "group") {
            if loc.auth_level == AuthLevel::Anon {
                loc.auth_level = AuthLevel::Group;
            }
        } else {
            diags.log(Severity::Warn, l, format!(
                "Unknown Require type {kind} on line {l} of {filename}."));
            return AaaResult::Error;
        }
        for w in words {
            loc.add_name(w);
        }
    } else if eq(name, "Satisfy") {
        if eq(value, "all") {
            loc.satisfy = Satisfy::All;
        } else if eq(value, "any") {
            loc.satisfy = Satisfy::Any;
        } else {
            diags.log(Severity::Warn, l, format!(
                "Unknown Satisfy value {value} on line {l} of {filename}."));
            return AaaResult::Error;
        }
    } else {
        return AaaResult::Unknown;
    }
    AaaResult::Ok
}

/// Case-insensitive compare (matches `_cups_strcasecmp`).
fn eq(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// Split a `Require` value into words honoring `'…'`/`"…"` quoting.
///
/// Upstream also supports `@AUTHKEY(name)` on macOS; we keep the token
/// verbatim so authz can decide.
fn split_require(value: &str) -> Vec<&str> {
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
            out.push(&value[start..j]);
            i = j + usize::from(j < bytes.len());
        } else {
            let start = i;
            while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            out.push(&value[start..i]);
        }
    }
    out
}

impl HostMask {
    /// Parse an `Allow`/`Deny` value list (`[from] host …`).
    ///
    /// Port of the `parse_aaa` allow/deny branch + `get_addr_and_mask`.
    pub fn parse_list(value: &str) -> impl Iterator<Item = Result<Self, String>> + '_ {
        let mut tokens: Vec<String> = value
            .split_whitespace()
            .map(ToString::to_string)
            .collect();
        // Strip leading "from".
        if tokens.first().is_some_and(|t| t.eq_ignore_ascii_case("from")) {
            tokens.remove(0);
        }
        tokens.into_iter().map(|tok| Self::parse_one(&tok))
    }

    /// Parse one allow/deny address token.
    ///
    /// Forms (upstream `parse_aaa`):
    /// `all`, `none`, `*.domain.com`, `.domain.com`, `host.domain.com`,
    /// `nnn.*`, `nnn.nnn.*`, `nnn.nnn.nnn.*`, `a.b.c.d`, `a.b.c.d/mm`,
    /// `a.b.c.d/m.m.m.m`, `[v6]`, `v6/mask`, `@LOCAL`, `@IFname`.
    pub fn parse_one(tok: &str) -> Result<Self, String> {
        if tok.eq_ignore_ascii_case("all") {
            return Ok(Self::Ip {
                addr: IpNet::V4([0; 4]),
                mask: IpNet::V4([0; 4]),
            });
        }
        if tok.eq_ignore_ascii_case("none") {
            // "none" = match nothing: addr ones masked to zero.
            return Ok(Self::Ip {
                addr: IpNet::V4([0xff; 4]),
                mask: IpNet::V4([0; 4]),
            });
        }
        let first = tok.as_bytes()[0];
        if first == b'*'
            || first == b'.'
            || (!first.is_ascii_digit() && first != b'[')
        {
            let name = tok.strip_prefix('*').unwrap_or(tok);
            return Ok(Self::Name(name.to_string()));
        }
        parse_ip_mask(tok)
    }

    /// Does `addr` satisfy this mask? (Host side of `cupsdCheckAuth`.)
    ///
    /// `@LOCAL` matches only loopback; name masks match suffixes; IP
    /// masks do masked compare.
    pub fn matches(&self, addr: &std::net::IpAddr) -> bool {
        match self {
            Self::Ip { addr: net, mask } => ip_match(addr, net, mask),
            Self::Name(name) => {
                if name.eq_ignore_ascii_case("@LOCAL") {
                    addr.is_loopback()
                } else {
                    false // name masks only match resolved hostnames
                }
            }
        }
    }

    /// Does `hostname` satisfy this name mask (suffix match like cupsd)?
    pub fn matches_name(&self, hostname: &str) -> bool {
        match self {
            Self::Name(pattern) => {
                if pattern.starts_with('.') {
                    hostname
                        .to_ascii_lowercase()
                        .ends_with(&pattern.to_ascii_lowercase())
                } else {
                    hostname.eq_ignore_ascii_case(pattern)
                }
            }
            Self::Ip { .. } => false,
        }
    }
}

/// Masked-compare an address against `net`/`mask` bytes.
///
/// Upstream stores the raw address and evaluates `(a & mask) == addr`
/// — this is what makes `Deny none` (addr=0xffffffff, mask=0) vacuous
/// and `Allow all` (0/0) universal.
fn ip_match(addr: &std::net::IpAddr, net: &IpNet, mask: &IpNet) -> bool {
    match (addr, net, mask) {
        (std::net::IpAddr::V4(a), IpNet::V4(n), IpNet::V4(m)) => {
            let a = u32::from_be_bytes(a.octets());
            let n = u32::from_be_bytes(*n);
            let m = u32::from_be_bytes(*m);
            (a & m) == n
        }
        (std::net::IpAddr::V6(a), IpNet::V6(n), IpNet::V6(m)) => {
            let a = a.octets();
            for i in 0..16 {
                if (a[i] & m[i]) != n[i] {
                    return false;
                }
            }
            true
        }
        (std::net::IpAddr::V4(a4), IpNet::V6(n6), IpNet::V6(m6)) => {
            // v4-in-v6: cupsd maps to ::ffff:a.b.c.d
            let a = a4.to_ipv6_mapped().octets();
            for i in 0..16 {
                if (a[i] & m6[i]) != n6[i] {
                    return false;
                }
            }
            true
        }
        _ => false,
    }
}

/// `get_addr_and_mask()` — parse `nnn.*`, `a.b.c.d`, `a.b.c.d/nn`,
/// `a.b.c.d/m.m.m.m`, `[v6]`, `v6:…/nn` forms.
fn parse_ip_mask(value: &str) -> Result<HostMask, String> {
    let (addr_part, mask_part) = match value.split_once('/') {
        Some((a, m)) => (a, Some(m)),
        None => (value, None),
    };

    // IPv6 literal in brackets or with colons.
    if addr_part.starts_with('[') || addr_part.contains(':') {
        let cleaned = addr_part.trim_start_matches('[').trim_end_matches(']');
        let v6: std::net::Ipv6Addr = cleaned
            .parse()
            .map_err(|_| format!("Bad netmask value {value}"))?;
        let mask = match mask_part {
            None => IpNet::V6([0xff; 16]),
            Some(m) => {
                if let Ok(bits) = m.parse::<u32>() {
                    if bits > 128 {
                        return Err(format!("Bad netmask value {value}"));
                    }
                    IpNet::V6(prefix_mask_v6(bits))
                } else {
                    let mv: std::net::Ipv6Addr =
                        m.parse().map_err(|_| format!("Bad netmask value {value}"))?;
                    IpNet::V6(mv.octets())
                }
            }
        };
        return Ok(HostMask::Ip {
            addr: IpNet::V6(v6.octets()),
            mask,
        });
    }

    // IPv4 forms incl. `nnn.*` wildcards.
    let mut addr = [0u8; 4];
    let mut mask = [0xffu8; 4];
    let mut i = 0;
    for (idx, piece) in addr_part.split('.').enumerate() {
        if idx >= 4 {
            return Err(format!("Bad netmask value {value}"));
        }
        if piece == "*" {
            mask[idx] = 0;
        } else {
            addr[idx] = piece
                .parse::<u8>()
                .map_err(|_| format!("Bad netmask value {value}"))?;
        }
        i = idx + 1;
    }
    if i == 0 {
        return Err(format!("Bad netmask value {value}"));
    }

    // cupsd treats `nnn.*` as nnn.0.0.0/255.0.0.0 — i.e. wildcard pieces
    // zero the mask at that position (already done) and everything
    // after. Trailing omitted octets (e.g. `10.*`) stay 0/masked too.
    for m in mask.iter_mut().skip(i) {
        *m = 0;
    }

    if let Some(m) = mask_part {
        let m = m.trim();
        if let Ok(bits) = m.parse::<u32>() {
            if bits > 32 {
                return Err(format!("Bad netmask value {value}"));
            }
            mask = prefix_mask_v4(bits);
        } else if m.starts_with("0x") || m.starts_with("0X") {
            let raw = u32::from_str_radix(&m[2..], 16)
                .map_err(|_| format!("Bad netmask value {value}"))?;
            mask = raw.to_be_bytes();
        } else {
            let parts: Vec<&str> = m.split('.').collect();
            if parts.len() != 4 {
                return Err(format!("Bad netmask value {value}"));
            }
            for (i, p) in parts.iter().enumerate() {
                mask[i] = p
                    .parse::<u8>()
                    .map_err(|_| format!("Bad netmask value {value}"))?;
            }
        }
    }

    Ok(HostMask::Ip {
        addr: IpNet::V4(addr),
        mask: IpNet::V4(mask),
    })
}

fn prefix_mask_v4(bits: u32) -> [u8; 4] {
    if bits == 0 {
        return [0; 4];
    }
    (u32::MAX << (32 - bits)).to_be_bytes()
}

fn prefix_mask_v6(bits: u32) -> [u8; 16] {
    let mut m = [0u8; 16];
    let mut remaining = bits;
    for byte in &mut m {
        if remaining >= 8 {
            *byte = 0xff;
            remaining -= 8;
        } else {
            *byte = 0xffu8 << (8 - remaining);
            break;
        }
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_all_none() {
        let m = HostMask::parse_one("all").unwrap();
        assert!(m.matches(&"1.2.3.4".parse().unwrap()));
        let m = HostMask::parse_one("none").unwrap();
        assert!(!m.matches(&"1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn wildcard_v4() {
        let m = HostMask::parse_one("192.168.*").unwrap();
        assert!(m.matches(&"192.168.7.9".parse().unwrap()));
        assert!(!m.matches(&"192.169.7.9".parse().unwrap()));
    }

    #[test]
    fn cidr() {
        let m = HostMask::parse_one("10.0.0.0/8").unwrap();
        assert!(m.matches(&"10.44.1.2".parse().unwrap()));
        assert!(!m.matches(&"11.0.0.1".parse().unwrap()));
    }

    #[test]
    fn name_masks() {
        let m = HostMask::parse_one("*.example.com").unwrap();
        assert!(m.matches_name("a.example.com"));
        assert!(!m.matches_name("example.com"));
        let m = HostMask::parse_one("@LOCAL").unwrap();
        assert!(m.matches(&"127.0.0.1".parse().unwrap()));
        assert!(m.matches(&"::1".parse().unwrap()));
        assert!(!m.matches(&"192.168.1.5".parse().unwrap()));
    }

    #[test]
    fn require_split_quoting() {
        let v = split_require("user alice 'bob smith' @lpadmin");
        assert_eq!(v, vec!["user", "alice", "bob smith", "@lpadmin"]);
    }
}
