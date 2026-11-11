//! Typed variable tables (`cupsd_vars[]`, `cupsfiles_vars[]`) and the
//! `parse_variable()` coercion port.

use crate::acl::{Diag, Severity};
use crate::config::{CupsFilesConfig, CupsdConfig};

/// `CUPSD_VARTYPE_*` — how the value is coerced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VarType {
    /// Decimal/hex/octal int, `0..=INT_MAX`.
    Integer,
    /// Bytes with `k`/`m`/`g` suffix (1024-based).
    Size,
    /// Octal file permission.
    Perm,
    /// Seconds with `m`/`h`/`d`/`w` suffix; PreserveJob* also take booleans.
    Time,
    /// yes/no/on/off/true/false/enabled/disabled/1/0.
    Boolean,
    /// Absolute path or ServerRoot-relative; existence-checked.
    Pathname,
    /// String that may be cleared by missing value.
    NullString,
    /// Required string.
    String,
}

/// The `cupsd.conf` typed variables (upstream `cupsd_vars[]`).
static CUPSD_VARS: &[(&str, VarType)] = &[
    ("AutoPurgeJobs", VarType::Boolean),
    ("BrowseDNSSDSubTypes", VarType::NullString),
    ("BrowseIPPSOnly", VarType::Boolean),
    ("BrowseWebIF", VarType::Boolean),
    ("Browsing", VarType::Boolean),
    ("Classification", VarType::String),
    ("ClassifyOverride", VarType::Boolean),
    ("DefaultLanguage", VarType::String),
    ("DefaultLeaseDuration", VarType::Time),
    ("DefaultPaperSize", VarType::String),
    ("DefaultPolicy", VarType::String),
    ("DefaultShared", VarType::Boolean),
    ("DirtyCleanInterval", VarType::Time),
    ("DNSSDComputerName", VarType::String),
    ("DNSSDHostName", VarType::String),
    ("ErrorPolicy", VarType::String),
    ("FilterLimit", VarType::Integer),
    ("GSSServiceName", VarType::String),
    ("IdleExitTimeout", VarType::Time),
    ("JobKillDelay", VarType::Time),
    ("JobRetryLimit", VarType::Integer),
    ("JobRetryInterval", VarType::Time),
    ("KeepAlive", VarType::Boolean),
    ("LaunchdTimeout", VarType::Time),
    ("LimitRequestBody", VarType::Size),
    ("LogDebugHistory", VarType::Integer),
    ("MaxActiveJobs", VarType::Integer),
    ("MaxClients", VarType::Integer),
    ("MaxClientsPerHost", VarType::Integer),
    ("MaxCopies", VarType::Integer),
    ("MaxEvents", VarType::Integer),
    ("MaxHoldTime", VarType::Time),
    ("MaxJobs", VarType::Integer),
    ("MaxJobsPerPrinter", VarType::Integer),
    ("MaxJobsPerUser", VarType::Integer),
    ("MaxJobTime", VarType::Time),
    ("MaxLeaseDuration", VarType::Time),
    ("MaxLogSize", VarType::Size),
    ("MaxRequestSize", VarType::Size),
    ("MaxSubscriptions", VarType::Integer),
    ("MaxSubscriptionsPerJob", VarType::Integer),
    ("MaxSubscriptionsPerPrinter", VarType::Integer),
    ("MaxSubscriptionsPerUser", VarType::Integer),
    ("MultipleOperationTimeout", VarType::Time),
    ("PageLogFormat", VarType::NullString),
    ("PreserveJobFiles", VarType::Time),
    ("PreserveJobHistory", VarType::Time),
    ("ReloadTimeout", VarType::Time),
    ("RootCertDuration", VarType::Time),
    ("ServerAdmin", VarType::String),
    ("ServerName", VarType::String),
    ("StrictConformance", VarType::Boolean),
    ("Timeout", VarType::Time),
    ("WebInterface", VarType::Boolean),
];

/// The `cups-files.conf` typed variables (upstream `cupsfiles_vars[]`).
static CUPSFILES_VARS: &[(&str, VarType)] = &[
    ("AccessLog", VarType::String),
    ("CacheDir", VarType::String),
    ("ConfigFilePerm", VarType::Perm),
    ("CreateSelfSignedCerts", VarType::Boolean),
    ("DataDir", VarType::String),
    ("DocumentRoot", VarType::String),
    ("ErrorLog", VarType::String),
    ("LogFilePerm", VarType::Perm),
    ("OAuthScopes", VarType::String),
    ("OAuthServer", VarType::String),
    ("PageLog", VarType::String),
    ("Printcap", VarType::String),
    ("RemoteRoot", VarType::String),
    ("RequestRoot", VarType::String),
    ("ServerBin", VarType::Pathname),
    ("ServerKeychain", VarType::Pathname),
    ("ServerRoot", VarType::Pathname),
    ("StateDir", VarType::String),
    ("StripUserDomain", VarType::Boolean),
    ("SyncOnClose", VarType::Boolean),
    ("SystemGroupAuthKey", VarType::String),
    ("TempDir", VarType::Pathname),
];

/// Coerced value handed to the config object.
#[derive(Debug, Clone)]
pub enum Typed {
    /// Integer result.
    Int(i64),
    /// Size in bytes.
    Size(u64),
    /// Permission bits.
    Perm(u32),
    /// Seconds.
    Time(i64),
    /// Boolean.
    Bool(bool),
    /// String contents.
    Str(String),
    /// Cleared / set to NULL.
    Null,
}

/// Parse + coerce one `name value` per `parse_variable`.
///
/// Returns `Ok(Some(typed))` for known directives, `Ok(None)` for
/// unknown (caller decides fatality), `Err(())` on coercion failure
/// (already logged).
pub fn parse_variable_cupsd<D: Diag>(
    cfg: &mut CupsdConfig,
    name: &str,
    value: Option<&str>,
    linenum: usize,
    filename: &str,
    diags: &mut D,
) -> Result<bool, ()> {
    let Some(ty) = lookup(CUPSD_VARS, name) else {
        diags.log(
            Severity::Error,
            linenum,
            format!("Unknown directive {name} on line {linenum} of {filename}."),
        );
        return Ok(false);
    };
    coerce(name, ty, value, linenum, filename, diags).map(|v| {
        apply_cupsd(cfg, name, v);
        true
    })
}

/// Same for `cups-files.conf`.
pub fn parse_variable_files<D: Diag>(
    cfg: &mut CupsFilesConfig,
    server_root: &str,
    name: &str,
    value: Option<&str>,
    linenum: usize,
    filename: &str,
    diags: &mut D,
) -> Result<bool, ()> {
    let Some(ty) = lookup(CUPSFILES_VARS, name) else {
        diags.log(
            Severity::Error,
            linenum,
            format!("Unknown directive {name} on line {linenum} of {filename}."),
        );
        return Ok(false);
    };
    // PATHNAME: cupsd validates existence at parse time (`access(temp,0)`),
    // except for "internal" and ServerKeychain.
    if ty == VarType::Pathname {
        if let Some(v) = value {
            let joined = join_server_root(server_root, v.to_string());
            let skip = v.eq_ignore_ascii_case("internal")
                || name.eq_ignore_ascii_case("ServerKeychain");
            if !skip && !std::path::Path::new(&joined).exists() {
                diags.log(
                    Severity::Error,
                    linenum,
                    format!(
                        "File or directory for \"{name} {v}\" on line {linenum} of {filename} does not exist."
                    ),
                );
                return Err(());
            }
        }
    }
    coerce(name, ty, value, linenum, filename, diags).map(|v| {
        apply_files(cfg, server_root, name, v);
        true
    })
}

fn lookup(table: &[(&str, VarType)], name: &str) -> Option<VarType> {
    table
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, t)| *t)
}

/// The coercion switch — mirrors `parse_variable`'s `switch (var->type)`.
fn coerce<D: Diag>(
    name: &str,
    ty: VarType,
    value: Option<&str>,
    linenum: usize,
    filename: &str,
    diags: &mut D,
) -> Result<Typed, ()> {
    let mut lerr = |what: &str| -> () {
        diags.log(
            Severity::Error,
            linenum,
            format!("{what} for {name} on line {linenum} of {filename}."),
        );
    };
    match ty {
        VarType::Integer => {
            let Some(v) = value else {
                lerr("Missing integer value");
                return Err(());
            };
            if !v.as_bytes().first().is_some_and(u8::is_ascii_digit) {
                lerr("Bad integer value");
                return Err(());
            }
            // strtol base 0 semantics: 0x hex, 0 octal, else decimal.
            let (digits, radix) = if let Some(h) = v
                .strip_prefix("0x")
                .or_else(|| v.strip_prefix("0X"))
            {
                (h, 16)
            } else if v.len() > 1 && v.starts_with('0') {
                (&v[1..], 8)
            } else {
                (v, 10)
            };
            match i64::from_str_radix(digits, radix) {
                Ok(n) if (0..=i64::from(i32::MAX)).contains(&n) => Ok(Typed::Int(n)),
                _ => {
                    lerr("Bad integer value");
                    Err(())
                }
            }
        }
        VarType::Size => {
            let Some(v) = value else {
                lerr("Missing size value");
                return Err(());
            };
            if !v.as_bytes().first().is_some_and(u8::is_ascii_digit) {
                lerr("Bad size value");
                return Err(());
            }
            let (num, unit) = split_num(v);
            let mut n: f64 = num.parse().map_err(|_| lerr("Bad size value"))?;
            match unit.chars().next().map(|c| c.to_ascii_lowercase()) {
                None => {}
                Some('g') => n *= 1024.0 * 1024.0 * 1024.0,
                Some('m') => n *= 1024.0 * 1024.0,
                Some('k') => n *= 1024.0,
                _ => {
                    lerr("Unknown size units");
                    return Err(());
                }
            }
            if !(0.0..=(i64::MAX as f64)).contains(&n) {
                lerr("Bad size value");
                return Err(());
            }
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            Ok(Typed::Size(n as u64))
        }
        VarType::Perm => {
            let Some(v) = value else {
                lerr("Missing permissions value");
                return Err(());
            };
            if !v.as_bytes().first().is_some_and(u8::is_ascii_digit) {
                lerr("Bad permissions value");
                return Err(());
            }
            match u32::from_str_radix(v, 8) {
                Ok(n) => Ok(Typed::Perm(n)),
                Err(_) => {
                    lerr("Bad permissions value");
                    Err(())
                }
            }
        }
        VarType::Time => {
            let Some(v) = value else {
                lerr("Missing time interval value");
                return Err(());
            };
            // PreserveJob* special case: yes/true/on/enabled → INT_MAX.
            if name.len() >= 11 && name[..11].eq_ignore_ascii_case("PreserveJob") {
                if matches!(
                    v.to_ascii_lowercase().as_str(),
                    "true" | "on" | "enabled" | "yes"
                ) {
                    return Ok(Typed::Time(i64::from(i32::MAX)));
                }
            }
            match v.to_ascii_lowercase().as_str() {
                "false" | "off" | "disabled" | "no" => return Ok(Typed::Time(0)),
                _ => {}
            }
            if !v.as_bytes().first().is_some_and(u8::is_ascii_digit) {
                lerr("Unknown time interval value");
                return Err(());
            }
            let (num, unit) = split_num(v);
            let mut n: f64 = num
                .parse()
                .map_err(|_| lerr("Unknown time interval value"))?;
            match unit.chars().next().map(|c| c.to_ascii_lowercase()) {
                None => {}
                Some('w') => n *= 7.0 * 24.0 * 60.0 * 60.0,
                Some('d') => n *= 24.0 * 60.0 * 60.0,
                Some('h') => n *= 60.0 * 60.0,
                Some('m') => n *= 60.0,
                _ => {
                    lerr("Unknown time interval value");
                    return Err(());
                }
            }
            if !(0.0..=(i32::MAX as f64)).contains(&n) {
                lerr("Bad time value");
                return Err(());
            }
            #[allow(clippy::cast_possible_truncation)]
            Ok(Typed::Time(n as i64))
        }
        VarType::Boolean => {
            let Some(v) = value else {
                lerr("Missing boolean value");
                return Err(());
            };
            let lv = v.to_ascii_lowercase();
            if matches!(lv.as_str(), "true" | "on" | "enabled" | "yes")
                || v.parse::<i64>().is_ok_and(|n| n != 0)
            {
                Ok(Typed::Bool(true))
            } else if matches!(lv.as_str(), "false" | "off" | "disabled" | "no" | "0") {
                Ok(Typed::Bool(false))
            } else {
                diags.log(
                    Severity::Error,
                    linenum,
                    format!("Unknown boolean value {v} on line {linenum} of {filename}."),
                );
                Err(())
            }
        }
        VarType::Pathname | VarType::String => {
            // Note: PATHNAME existence+joining is done by the caller via
            // `Typed::Str` + `apply_files` since it needs ServerRoot.
            let Some(v) = value else {
                lerr(if ty == VarType::Pathname {
                    "Missing pathname value"
                } else {
                    "Missing value"
                });
                return Err(());
            };
            Ok(Typed::Str(v.to_string()))
        }
        VarType::NullString => Ok(match value {
            Some(v) => Typed::Str(v.to_string()),
            None => Typed::Null,
        }),
    }
}

/// Split "123unit" → ("123", "unit").
fn split_num(v: &str) -> (&str, &str) {
    let i = v
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(v.len());
    (&v[..i], &v[i..])
}

/// Store a typed value into `CupsdConfig`.
#[allow(clippy::too_many_lines)]
fn apply_cupsd(c: &mut CupsdConfig, name: &str, v: Typed) {
    macro_rules! i32f {
        ($f:expr) => {
            if let Typed::Int(n) | Typed::Time(n) = v {
                $f = n as i32;
            }
        };
    }
    macro_rules! u64f {
        ($f:expr) => {
            if let Typed::Size(n) = v {
                $f = n;
            }
        };
    }
    macro_rules! boolf {
        ($f:expr) => {
            if let Typed::Bool(b) = v {
                $f = b;
            }
        };
    }
    macro_rules! strf {
        ($f:expr) => {
            match v {
                Typed::Str(s) => $f = Some(s),
                Typed::Null => $f = None,
                _ => {}
            }
        };
    }
    match name.to_ascii_lowercase().as_str() {
        "autopurgejobs" => boolf!(c.job_auto_purge),
        "browsednssdsubtypes" => strf!(c.dnssd_subtypes),
        "browseippsonly" => boolf!(c.browse_ipps_only),
        "browsewebif" => boolf!(c.browse_web_if),
        "browsing" => boolf!(c.browsing),
        "classification" => strf!(c.classification),
        "classifyoverride" => boolf!(c.classify_override),
        "defaultlanguage" => strf!(c.default_language),
        "defaultleaseduration" => i32f!(c.default_lease_duration),
        "defaultpapersize" => strf!(c.default_paper_size),
        "defaultpolicy" => strf!(c.default_policy),
        "defaultshared" => boolf!(c.default_shared),
        "dirtycleaninterval" => i32f!(c.dirty_clean_interval),
        "dnssdcomputername" => strf!(c.dnssd_computer_name),
        "dnssdhostname" => strf!(c.dnssd_host_name),
        "errorpolicy" => strf!(c.error_policy),
        "filterlimit" => i32f!(c.filter_limit),
        "gssservicename" => strf!(c.gss_service_name),
        "idleexittimeout" | "launchdtimeout" => i32f!(c.idle_exit_timeout),
        "jobkilldelay" => i32f!(c.job_kill_delay),
        "jobretrylimit" => i32f!(c.job_retry_limit),
        "jobretryinterval" => i32f!(c.job_retry_interval),
        "keepalive" => boolf!(c.keep_alive),
        "limitrequestbody" | "maxrequestsize" => u64f!(c.max_request_size),
        "logdebughistory" => i32f!(c.log_debug_history),
        "maxactivejobs" => i32f!(c.max_active_jobs),
        "maxclients" => i32f!(c.max_clients),
        "maxclientsperhost" => i32f!(c.max_clients_per_host),
        "maxcopies" => i32f!(c.max_copies),
        "maxevents" => i32f!(c.max_events),
        "maxholdtime" => i32f!(c.max_hold_time),
        "maxjobs" => i32f!(c.max_jobs),
        "maxjobsperprinter" => i32f!(c.max_jobs_per_printer),
        "maxjobsperuser" => i32f!(c.max_jobs_per_user),
        "maxjobtime" => i32f!(c.max_job_time),
        "maxleaseduration" => i32f!(c.max_lease_duration),
        "maxlogsize" => u64f!(c.max_log_size),
        "maxsubscriptions" => i32f!(c.max_subscriptions),
        "maxsubscriptionsperjob" => i32f!(c.max_subscriptions_per_job),
        "maxsubscriptionsperprinter" => i32f!(c.max_subscriptions_per_printer),
        "maxsubscriptionsperuser" => i32f!(c.max_subscriptions_per_user),
        "multipleoperationtimeout" => i32f!(c.multiple_operation_timeout),
        "pagelogformat" => strf!(c.page_log_format),
        "preservejobfiles" => i32f!(c.preserve_job_files),
        "preservejobhistory" => i32f!(c.preserve_job_history),
        "reloadtimeout" => i32f!(c.reload_timeout),
        "rootcertduration" => i32f!(c.root_cert_duration),
        "serveradmin" => strf!(c.server_admin),
        "servername" => strf!(c.server_name),
        "strictconformance" => boolf!(c.strict_conformance),
        "timeout" => i32f!(c.timeout),
        "webinterface" => boolf!(c.web_interface),
        _ => {}
    }
}

/// Store a typed value into `CupsFilesConfig`.
fn apply_files(c: &mut CupsFilesConfig, server_root: &str, name: &str, v: Typed) {
    macro_rules! boolf {
        ($f:expr) => {
            if let Typed::Bool(b) = v {
                $f = b;
            }
        };
    }
    macro_rules! strf {
        ($f:expr) => {
            match v {
                Typed::Str(s) => $f = Some(s),
                Typed::Null => $f = None,
                _ => {}
            }
        };
    }
    match name.to_ascii_lowercase().as_str() {
        "accesslog" => strf!(c.access_log),
        "cachedir" => strf!(c.cache_dir),
        "configfileperm" => {
            if let Typed::Perm(p) = v {
                c.config_file_perm = p;
            }
        }
        "createselfsignedcerts" => boolf!(c.create_self_signed_certs),
        "datadir" => strf!(c.data_dir),
        "documentroot" => strf!(c.document_root),
        "errorlog" => strf!(c.error_log),
        "logfileperm" => {
            if let Typed::Perm(p) = v {
                c.log_file_perm = p;
            }
        }
        "oauthscopes" => strf!(c.oauth_scopes),
        "oauthserver" => strf!(c.oauth_server),
        "pagelog" => strf!(c.page_log),
        "printcap" => strf!(c.printcap),
        "remoteroot" => strf!(c.remote_root),
        "requestroot" => strf!(c.request_root),
        "serverbin" => {
            if let Typed::Str(s) = v {
                c.server_bin = Some(join_server_root(server_root, s));
            }
        }
        "serverkeychain" => {
            if let Typed::Str(s) = v {
                c.server_keychain = Some(join_server_root(server_root, s));
            }
        }
        "serverroot" => {
            if let Typed::Str(s) = v {
                c.server_root = Some(s);
            }
        }
        "statedir" => strf!(c.state_dir),
        "stripuserdomain" => boolf!(c.strip_user_domain),
        "synconclose" => boolf!(c.sync_on_close),
        "systemgroupauthkey" => strf!(c.system_group_auth_key),
        "tempdir" => {
            if let Typed::Str(s) = v {
                c.temp_dir = Some(join_server_root(server_root, s));
            }
        }
        _ => {}
    }
}

/// `PATHNAME` join: absolute stays absolute, relative → `server_root/v`.
fn join_server_root(server_root: &str, v: String) -> String {
    if v.starts_with('/') {
        v
    } else {
        format!("{server_root}/{v}")
    }
}
