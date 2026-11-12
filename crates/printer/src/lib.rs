//! `printer` — the destination registry and `printers.conf`/`classes.conf`
//! persistence, ported from `scheduler/printers.c`.
//!
//! A "printer" and a "class" share one record upstream
//! (`cupsd_printer_t` + `CUPS_PTYPE_CLASS` bit + member array); this
//! crate keeps the same shape so the op layer can treat both uniformly.

#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;

use ipp_codec::{tags, Attribute, Value};

/// IPP `printer-state` enum values.
pub mod pstate {
    /// Idle.
    pub const IDLE: i32 = 3;
    /// Processing a job.
    pub const PROCESSING: i32 = 4;
    /// Stopped (paused).
    pub const STOPPED: i32 = 5;
}

/// `printer-type` bitfield (upstream `cups_ptype_t`).
pub mod ptype {
    /// Local destination.
    pub const LOCAL: i32 = 0x0000_0000;
    /// Implicit class.
    pub const IMPLICIT: i32 = 0x0001_0000;
    /// Class.
    pub const CLASS: i32 = 0x0000_0001;
    /// Remote queue.
    pub const REMOTE: i32 = 0x0000_0002;
    /// Default destination (computed at emit, not stored).
    pub const DEFAULT: i32 = 0x0002_0000;
    /// Not accepting jobs (computed).
    pub const REJECTING: i32 = 0x0008_0000;
    /// Not shared (computed).
    pub const NOT_SHARED: i32 = 0x0020_0000;
    /// Temporary queue.
    pub const TEMPORARY: i32 = 0x1000_0000;
    /// Delete pending (internal).
    pub const DELETE: i32 = 0x0010_0000;
    /// B&W capable.
    pub const BW: i32 = 0x0000_0004;
    /// Color.
    pub const COLOR: i32 = 0x0000_0008;
    /// Duplex.
    pub const DUPLEX: i32 = 0x0000_0010;
    /// Copies.
    pub const COPIES: i32 = 0x0000_0040;
    /// Collate.
    pub const COLLATE: i32 = 0x0000_0080;
    /// Staple.
    pub const STAPLE: i32 = 0x0000_0020;
    /// Punch.
    pub const PUNCH: i32 = 0x0000_0100;
    /// Cover.
    pub const COVER: i32 = 0x0000_0200;
    /// Bind.
    pub const BIND: i32 = 0x0000_0400;
    /// Sort.
    pub const SORT: i32 = 0x0000_0800;
    /// Small media.
    pub const SMALL: i32 = 0x0000_1000;
    /// Medium media.
    pub const MEDIUM: i32 = 0x0000_2000;
    /// Large media.
    pub const LARGE: i32 = 0x0000_4000;
    /// Variable-size media.
    pub const VARIABLE: i32 = 0x0000_8000;
    /// Fax.
    pub const FAX: i32 = 0x0004_0000;
    /// Discovered (network browse) queue.
    pub const DISCOVERED: i32 = 0x0100_0000;
    /// Scanner.
    pub const SCANNER: i32 = 0x0200_0000;
    /// MFP.
    pub const MFP: i32 = 0x0400_0000;
    /// 3D printer.
    pub const PRINT3D: i32 = 0x0400_0000;
}

/// One destination (printer or class).
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)] // flat PTYPE flag surface mirrors upstream
pub struct Printer {
    /// Queue name (sans `ipp://host/printers/`).
    pub name: String,
    /// `printer-id` (stable 1-based; assigned on first save).
    pub printer_id: i32,
    /// `printer-uuid` (`urn:uuid:…`).
    pub uuid: String,
    /// `printer-info` (description).
    pub info: Option<String>,
    /// `printer-location`.
    pub location: Option<String>,
    /// `printer-geo-location` (geo: URI).
    pub geo_location: Option<String>,
    /// `printer-make-and-model`.
    pub make_model: Option<String>,
    /// `printer-organization`.
    pub organization: Option<String>,
    /// `printer-organizational-unit`.
    pub organizational_unit: Option<String>,
    /// `device-uri` — backend target.
    pub device_uri: String,
    /// `PortMonitor` directive.
    pub port_monitor: Option<String>,
    /// IPP `printer-state` (3/4/5).
    pub state: i32,
    /// `printer-state-message`.
    pub state_message: String,
    /// `printer-state-change-time` (epoch).
    pub state_time: i64,
    /// `printer-config-change-time` (epoch).
    pub config_time: i64,
    /// `printer-state-reasons` keywords.
    pub reasons: Vec<String>,
    /// `printer-type` bitmask.
    pub ptype: i32,
    /// `printer-is-accepting-jobs`.
    pub accepting: bool,
    /// `printer-is-shared` (browse/publish).
    pub shared: bool,
    /// Temporary queue (auto-created by driverless discovery).
    pub temporary: bool,
    /// `job-sheets` (start, end banner names).
    pub job_sheets: (String, String),
    /// `QuotaPeriod`.
    pub quota_period: i32,
    /// `PageLimit`.
    pub page_limit: i32,
    /// `KLimit` (kbytes).
    pub k_limit: i32,
    /// `AllowUser`/`DenyUser` names (`deny_users` picks semantics).
    pub users: Vec<String>,
    /// `true` when `users` are a deny list.
    pub deny_users: bool,
    /// `printer-op-policy` name.
    pub op_policy: Option<String>,
    /// `printer-error-policy` name.
    pub error_policy: Option<String>,
    /// `Option name value` job-default options.
    pub options: Vec<(String, String)>,
    /// `auth-info-required` (up to 3 keywords).
    pub auth_info_required: Vec<String>,
    /// `printer-alert` octet string.
    pub alert: Option<String>,
    /// `printer-alert-description`.
    pub alert_description: Option<String>,
    /// Marker attributes (supplies): name→values stored verbatim.
    pub marker_colors: Vec<String>,
    /// `marker-levels`.
    pub marker_levels: Vec<i32>,
    /// `marker-low-levels`.
    pub marker_low_levels: Vec<i32>,
    /// `marker-high-levels`.
    pub marker_high_levels: Vec<i32>,
    /// `marker-message`.
    pub marker_message: String,
    /// `marker-names`.
    pub marker_names: Vec<String>,
    /// `marker-types`.
    pub marker_types: Vec<String>,
    /// `marker-change-time` (epoch).
    pub marker_time: i64,
    /// `printer-dns-sd-name` (DNS-SD registration).
    pub reg_name: Option<String>,
    /// Class members (printer names); empty for real printers.
    pub members: Vec<String>,
}

impl Printer {
    /// Bare new queue — `accepting`, `idle`, unshared, `local` type.
    #[must_use]
    pub fn new(name: impl Into<String>, device_uri: impl Into<String>) -> Self {
        let name = name.into();
        Self {
            uuid: format!("urn:uuid:{}", uuid_v4()),
            name,
            printer_id: 0,
            info: None,
            location: None,
            geo_location: None,
            make_model: None,
            organization: None,
            organizational_unit: None,
            device_uri: device_uri.into(),
            port_monitor: None,
            state: pstate::IDLE,
            state_message: String::new(),
            state_time: now(),
            config_time: now(),
            reasons: Vec::new(),
            ptype: ptype::LOCAL | ptype::BW,
            accepting: true,
            shared: false,
            temporary: false,
            job_sheets: ("none".into(), "none".into()),
            quota_period: 0,
            page_limit: 0,
            k_limit: 0,
            users: Vec::new(),
            deny_users: false,
            op_policy: None,
            error_policy: None,
            options: Vec::new(),
            auth_info_required: Vec::new(),
            alert: None,
            alert_description: None,
            marker_colors: Vec::new(),
            marker_levels: Vec::new(),
            marker_low_levels: Vec::new(),
            marker_high_levels: Vec::new(),
            marker_message: String::new(),
            marker_names: Vec::new(),
            marker_types: Vec::new(),
            marker_time: 0,
            reg_name: None,
            members: Vec::new(),
        }
    }

    /// `true` for classes (`CUPS_PTYPE_CLASS` bit).
    #[must_use]
    pub fn is_class(&self) -> bool {
        self.ptype & ptype::CLASS != 0
    }

    /// Whether `user` may submit — `AllowUser`/`DenyUser` semantics
    /// (upstream `user_allowed()`): empty list = everyone allowed;
    /// otherwise allow-list wins, deny-list blocks.
    #[must_use]
    pub fn user_allowed(&self, username: &str) -> bool {
        if self.users.is_empty() {
            return true;
        }
        let listed = self
            .users
            .iter()
            .any(|u| u.eq_ignore_ascii_case(username) || u == "@ALL");
        if self.deny_users {
            !listed
        } else {
            listed
        }
    }

    /// Effective `printer-type` at emit time (adds the dynamic bits).
    #[must_use]
    pub fn effective_ptype(&self, is_default: bool) -> i32 {
        let mut t = self.ptype;
        if is_default {
            t |= ptype::DEFAULT;
        }
        if !self.accepting {
            t |= ptype::REJECTING;
        }
        if !self.shared {
            t |= ptype::NOT_SHARED;
        }
        t
    }
}

/// The full registry — sorted by name upstream (`cupsArray` sorted by
/// name), so `BTreeMap` gives the same iteration order for
/// `CUPS-Get-Printers`.
#[derive(Debug, Default)]
pub struct Registry {
    /// Destinations by name.
    pub printers: BTreeMap<String, Printer>,
    /// Default queue name (`<DefaultPrinter>`).
    pub default: Option<String>,
    /// `NextPrinterId` counter.
    pub next_printer_id: i32,
    /// Next `job-id` counter (from `classes.conf`/cupsd state; kept
    /// here until the `job` crate owns it).
    pub next_job_id: i32,
}

impl Registry {
    /// Look up a destination by name or URI path (`/printers/x`,
    /// `/classes/x`, bare `x`).
    #[must_use]
    pub fn find(&self, name_or_path: &str) -> Option<&Printer> {
        let name = name_or_path
            .strip_prefix("/printers/")
            .or_else(|| name_or_path.strip_prefix("/classes/"))
            .unwrap_or(name_or_path);
        self.printers.get(name)
    }

    /// The default destination, if any.
    #[must_use]
    pub fn default_printer(&self) -> Option<&Printer> {
        self.default.as_deref().and_then(|n| self.printers.get(n))
    }

    /// `cupsdValidateDest()` — resolve a `printer-uri`/`job-uri` to the
    /// destination. Accepts `ipp(s)://host[:port]/printers|classes/NAME`
    /// and bare `/printers/NAME` paths; also `ipp://host/` for
    /// system-wide ops.
    #[must_use]
    pub fn validate_dest<'a>(&'a self, uri: &str) -> Option<(&'a Printer, bool)> {
        // Extract path after authority.
        let path = if let Some(rest) = uri
            .strip_prefix("ipp://")
            .or_else(|| uri.strip_prefix("ipps://"))
        {
            &rest[rest.find('/')?..]
        } else if uri.starts_with('/') {
            uri
        } else {
            return None;
        };
        let p = self.find(path)?;
        Some((p, p.is_class()))
    }

    /// Insert/replace a printer; first insertion wins `printer_id`.
    pub fn add(&mut self, mut p: Printer) {
        if p.printer_id == 0 {
            p.printer_id = self.next_printer_id;
            self.next_printer_id += 1;
        }
        self.printers.insert(p.name.clone(), p);
    }

    /// Load `printers.conf` (and `classes.conf` — same format).
    /// `DefaultPrinter` sets `default`. Tolerates the upstream
    /// "directives outside a block are ignored" behavior.
    pub fn load_printers_conf<R: std::io::BufRead>(&mut self, r: R) -> Vec<String> {
        let mut errors = Vec::new();
        let mut cur: Option<Printer> = None;
        let mut is_default_block = false;

        for line in cups_config::conf_lines(r).map_while(Result::ok) {
            let name = line.name.as_str();
            let val = line.value.as_deref().unwrap_or("");

            if name.eq_ignore_ascii_case("NextPrinterId") {
                self.next_printer_id = val.parse().unwrap_or(1);
            } else if name.eq_ignore_ascii_case("NextJobId") {
                self.next_job_id = val.parse().unwrap_or(1);
            } else if name.starts_with("<DefaultPrinter")
                || name.starts_with("<Printer")
                || name.starts_with("<Class")
                || name.starts_with("<DefaultClass")
            {
                if cur.is_none() && !val.is_empty() {
                    let mut p = Printer::new(val, "");
                    p.accepting = true;
                    p.state = pstate::IDLE;
                    if name.contains("Class") {
                        p.ptype |= ptype::CLASS;
                    }
                    is_default_block = name.starts_with("<Default");
                    cur = Some(p);
                } else if cur.is_some() {
                    errors.push(format!(
                        "Syntax error on line {} of printers.conf.",
                        line.linenum
                    ));
                }
            } else if name.starts_with("</") {
                if let Some(mut p) = cur.take() {
                    if p.printer_id == 0 {
                        p.printer_id = self.next_printer_id;
                        self.next_printer_id += 1;
                    }
                    if is_default_block {
                        self.default = Some(p.name.clone());
                    }
                    self.printers.insert(p.name.clone(), p);
                }
                is_default_block = false;
            } else if let Some(p) = cur.as_mut() {
                apply_printer_directive(p, name, val);
            }
            // else: stray directive outside a block — upstream ignores.
        }
        errors
    }

    /// Serialize to `printers.conf` — byte-compatible field order with
    /// `cupsdSaveAllPrinters`.
    #[must_use]
    pub fn save_printers_conf(&self) -> Vec<u8> {
        let mut out = String::new();
        out.push_str("# Printer configuration file for CUPS v2.5-rust\n");
        out.push_str("# Written by cupsd\n");
        out.push_str("# DO NOT EDIT THIS FILE WHEN CUPSD IS RUNNING\n\n");
        let _ = writeln!(out, "NextPrinterId {}", self.next_printer_id);

        for p in self.printers.values() {
            if p.is_class() || p.temporary {
                continue;
            }
            write_printer_block(&mut out, p, self.default.as_deref() == Some(&*p.name));
        }
        for p in self.printers.values() {
            if p.is_class() {
                write_printer_block(&mut out, p, self.default.as_deref() == Some(&*p.name));
            }
        }
        out.into_bytes()
    }

    /// Convenience: parse from a file path.
    ///
    /// # Errors
    /// I/O errors other than "not found" propagate.
    pub fn load_printers_file(&mut self, path: &Path) -> std::io::Result<Vec<String>> {
        match std::fs::File::open(path) {
            Ok(f) => Ok(self.load_printers_conf(std::io::BufReader::new(f))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }
}

/// One `<Printer name>` block in `cupsdSaveAllPrinters` order.
#[allow(clippy::too_many_lines, clippy::format_push_string)]
fn write_printer_block(out: &mut String, p: &Printer, is_default: bool) {
    let (open, close) = if is_default {
        ("<DefaultPrinter", "</DefaultPrinter>\n")
    } else {
        ("<Printer", "</Printer>\n")
    };
    out.push_str(&format!("{open} {}>\n", p.name));
    if p.printer_id != 0 {
        out.push_str(&format!("PrinterId {}\n", p.printer_id));
    }
    out.push_str(&format!("UUID {}\n", p.uuid));
    if !p.auth_info_required.is_empty() {
        out.push_str(&format!(
            "AuthInfoRequired {}\n",
            esc(&p.auth_info_required.join(","))
        ));
    }
    if let Some(v) = &p.info {
        out.push_str(&format!("Info {}\n", esc(v)));
    }
    if let Some(v) = &p.location {
        out.push_str(&format!("Location {}\n", esc(v)));
    }
    if let Some(v) = &p.geo_location {
        out.push_str(&format!("GeoLocation {}\n", esc(v)));
    }
    if let Some(v) = &p.make_model {
        out.push_str(&format!("MakeModel {}\n", esc(v)));
    }
    if let Some(v) = &p.organization {
        out.push_str(&format!("Organization {}\n", esc(v)));
    }
    if let Some(v) = &p.organizational_unit {
        out.push_str(&format!("OrganizationalUnit {}\n", esc(v)));
    }
    out.push_str(&format!("DeviceURI {}\n", esc(&p.device_uri)));
    if let Some(v) = &p.port_monitor {
        out.push_str(&format!("PortMonitor {}\n", esc(v)));
    }
    if p.state == pstate::STOPPED {
        out.push_str("State Stopped\n");
        if !p.state_message.is_empty() {
            out.push_str(&format!("StateMessage {}\n", esc(&p.state_message)));
        }
    } else {
        out.push_str("State Idle\n");
    }
    out.push_str(&format!("StateTime {}\n", p.state_time));
    out.push_str(&format!("ConfigTime {}\n", p.config_time));
    for r in &p.reasons {
        if r != "connecting-to-device"
            && r != "cups-insecure-filter-warning"
            && r != "cups-missing-filter-warning"
        {
            out.push_str(&format!("Reason {}\n", esc(r)));
        }
    }
    out.push_str(&format!("Type {}\n", p.ptype));
    out.push_str(if p.accepting {
        "Accepting Yes\n"
    } else {
        "Accepting No\n"
    });
    out.push_str(if p.shared {
        "Shared Yes\n"
    } else {
        "Shared No\n"
    });
    out.push_str(&format!(
        "JobSheets {}\n",
        esc(&format!("{} {}", p.job_sheets.0, p.job_sheets.1))
    ));
    out.push_str(&format!("QuotaPeriod {}\n", p.quota_period));
    out.push_str(&format!("PageLimit {}\n", p.page_limit));
    out.push_str(&format!("KLimit {}\n", p.k_limit));
    for u in &p.users {
        out.push_str(&format!(
            "{} {}\n",
            if p.deny_users {
                "DenyUser"
            } else {
                "AllowUser"
            },
            esc(u)
        ));
    }
    if let Some(v) = &p.op_policy {
        out.push_str(&format!("OpPolicy {}\n", esc(v)));
    }
    if let Some(v) = &p.error_policy {
        out.push_str(&format!("ErrorPolicy {}\n", esc(v)));
    }
    for (n, v) in &p.options {
        out.push_str(&format!("Option {}\n", esc(&format!("{n} {v}"))));
    }
    if !p.marker_colors.is_empty() {
        out.push_str(&format!(
            "Attribute marker-colors {}\n",
            p.marker_colors.join(",")
        ));
    }
    if !p.marker_levels.is_empty() {
        out.push_str(&format!(
            "Attribute marker-levels {}\n",
            int_list(&p.marker_levels)
        ));
    }
    if !p.marker_low_levels.is_empty() {
        out.push_str(&format!(
            "Attribute marker-low-levels {}\n",
            int_list(&p.marker_low_levels)
        ));
    }
    if !p.marker_high_levels.is_empty() {
        out.push_str(&format!(
            "Attribute marker-high-levels {}\n",
            int_list(&p.marker_high_levels)
        ));
    }
    if !p.marker_message.is_empty() {
        out.push_str(&format!(
            "Attribute marker-message {}\n",
            if p.marker_message.is_empty() {
                "\"\"".into()
            } else {
                esc(&p.marker_message)
            }
        ));
    }
    if !p.marker_names.is_empty() {
        out.push_str(&format!(
            "Attribute marker-names {}\n",
            p.marker_names.join(",")
        ));
    }
    if !p.marker_types.is_empty() {
        out.push_str(&format!(
            "Attribute marker-types {}\n",
            p.marker_types.join(",")
        ));
    }
    if p.marker_time != 0 {
        out.push_str(&format!("Attribute marker-change-time {}\n", p.marker_time));
    }
    out.push_str(close);
    out.push('\n');
}

fn int_list(v: &[i32]) -> String {
    v.iter().map(i32::to_string).collect::<Vec<_>>().join(",")
}

/// `cupsFilePutConf` escaping: `\` → `\\`, `#` → `\#`, newline → `\n`,
/// CR → `\r` (no quoting ever).
fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => o.push_str("\\\\"),
            '#' => o.push_str("\\#"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            c => o.push(c),
        }
    }
    o
}

/// Apply one directive inside a `<Printer>` block (the `else if` chain
/// from `cupsdLoadAllPrinters`).
#[allow(clippy::ignored_unit_patterns, clippy::too_many_lines)]
fn apply_printer_directive(p: &mut Printer, name: &str, val: &str) {
    let yes = |v: &str| {
        v.eq_ignore_ascii_case("yes")
            || v.eq_ignore_ascii_case("on")
            || v.eq_ignore_ascii_case("true")
    };
    match () {
        _ if name.eq_ignore_ascii_case("PrinterId") => {
            p.printer_id = val.parse().unwrap_or(0);
        }
        _ if name.eq_ignore_ascii_case("UUID") => p.uuid = val.to_string(),
        _ if name.eq_ignore_ascii_case("AuthInfoRequired") => {
            p.auth_info_required = val.split(',').map(|s| s.trim().to_string()).collect();
        }
        _ if name.eq_ignore_ascii_case("Info") => p.info = Some(val.to_string()),
        _ if name.eq_ignore_ascii_case("Location") => p.location = Some(val.to_string()),
        _ if name.eq_ignore_ascii_case("GeoLocation") => {
            p.geo_location = Some(val.to_string());
        }
        _ if name.eq_ignore_ascii_case("MakeModel") => {
            p.make_model = Some(val.to_string());
        }
        _ if name.eq_ignore_ascii_case("Organization") => {
            p.organization = Some(val.to_string());
        }
        _ if name.eq_ignore_ascii_case("OrganizationalUnit") => {
            p.organizational_unit = Some(val.to_string());
        }
        _ if name.eq_ignore_ascii_case("DeviceURI") => p.device_uri = val.to_string(),
        _ if name.eq_ignore_ascii_case("PortMonitor") => {
            if val.eq_ignore_ascii_case("none") {
                p.port_monitor = None;
            } else {
                p.port_monitor = Some(val.to_string());
            }
        }
        _ if name.eq_ignore_ascii_case("Option") => {
            if let Some((n, v)) = val.split_once(' ') {
                p.options.push((n.to_string(), v.to_string()));
            }
        }
        _ if name.eq_ignore_ascii_case("Reason") => {
            if !p.reasons.iter().any(|r| r == val) {
                p.reasons.push(val.to_string());
            }
        }
        _ if name.eq_ignore_ascii_case("State") => {
            if val.eq_ignore_ascii_case("idle") {
                p.state = pstate::IDLE;
            } else if val.eq_ignore_ascii_case("stopped") {
                p.state = pstate::STOPPED;
            }
        }
        _ if name.eq_ignore_ascii_case("StateMessage") => {
            p.state_message = val.to_string();
        }
        _ if name.eq_ignore_ascii_case("StateTime") => {
            p.state_time = val.parse().unwrap_or(0);
        }
        _ if name.eq_ignore_ascii_case("ConfigTime") => {
            p.config_time = val.parse().unwrap_or(0);
        }
        _ if name.eq_ignore_ascii_case("Accepting") => p.accepting = yes(val),
        _ if name.eq_ignore_ascii_case("Type") => {
            p.ptype = val.parse().unwrap_or(ptype::LOCAL);
        }
        _ if name.eq_ignore_ascii_case("Shared") => p.shared = yes(val),
        _ if name.eq_ignore_ascii_case("JobSheets") => {
            let mut it = val.splitn(2, ' ');
            let a = it.next().unwrap_or("none").to_string();
            let b = it.next().unwrap_or("none").to_string();
            p.job_sheets = (a, b);
        }
        _ if name.eq_ignore_ascii_case("AllowUser") => {
            p.deny_users = false;
            p.users.push(val.to_string());
        }
        _ if name.eq_ignore_ascii_case("DenyUser") => {
            p.deny_users = true;
            p.users.push(val.to_string());
        }
        _ if name.eq_ignore_ascii_case("QuotaPeriod") => {
            p.quota_period = val.parse().unwrap_or(0);
        }
        _ if name.eq_ignore_ascii_case("PageLimit") => {
            p.page_limit = val.parse().unwrap_or(0);
        }
        _ if name.eq_ignore_ascii_case("KLimit") => {
            p.k_limit = val.parse().unwrap_or(0);
        }
        _ if name.eq_ignore_ascii_case("OpPolicy") => {
            p.op_policy = Some(val.to_string());
        }
        _ if name.eq_ignore_ascii_case("ErrorPolicy") => {
            p.error_policy = Some(val.to_string());
        }
        _ if name.eq_ignore_ascii_case("Attribute") => {
            if let Some((an, av)) = val.split_once(' ') {
                match an {
                    "marker-colors" => {
                        p.marker_colors = av.split(',').map(str::to_string).collect();
                    }
                    "marker-levels" => {
                        p.marker_levels = av.split(',').filter_map(|s| s.parse().ok()).collect();
                    }
                    "marker-low-levels" => {
                        p.marker_low_levels =
                            av.split(',').filter_map(|s| s.parse().ok()).collect();
                    }
                    "marker-high-levels" => {
                        p.marker_high_levels =
                            av.split(',').filter_map(|s| s.parse().ok()).collect();
                    }
                    "marker-message" => p.marker_message = av.to_string(),
                    "marker-names" => {
                        p.marker_names = av.split(',').map(str::to_string).collect();
                    }
                    "marker-types" => {
                        p.marker_types = av.split(',').map(str::to_string).collect();
                    }
                    "marker-change-time" => p.marker_time = av.parse().unwrap_or(0),
                    _ => {}
                }
            }
        }
        _ => {}
    }
}

/// Wall-clock epoch seconds.
#[must_use]
pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// RFC 4122 v4 UUID (no external dep — /dev/urandom-free deterministic
/// PRNG seeded from time+pid; upstream uses libuuid which is random).
#[allow(clippy::cast_possible_truncation)] // PRNG intentionally takes low bits
fn uuid_v4() -> String {
    let t = now();
    let p = std::process::id();
    let mut x: u64 =
        u64::try_from(t).unwrap_or(0) << 20 | u64::from(p) << 4 | 0x9e37_79b9_7f4a_7c15;
    let mut gen = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    format!(
        "{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}",
        gen() as u32,
        gen() as u16,
        (gen() as u16) & 0x0fff,
        ((gen() as u16) & 0x3fff) | 0x8000,
        gen() & 0xffff_ffff_ffff
    )
}

/// Build the `printer-state-reasons` IPP attribute (keyword list, or
/// "none" when empty — upstream `add_printer_state_reasons`).
#[must_use]
pub fn state_reasons_attr(p: &Printer) -> Attribute {
    if p.reasons.is_empty() {
        Attribute::new(
            "printer-state-reasons",
            tags::KEYWORD,
            vec![Value::Keyword("none".into())],
        )
    } else {
        Attribute::new(
            "printer-state-reasons",
            tags::KEYWORD,
            p.reasons
                .iter()
                .map(|r| Value::Keyword(r.as_str().into()))
                .collect(),
        )
    }
}

/// Compose an IPP `dateTime` value from epoch seconds (UTC — upstream
/// uses `ippTimeToDate` which is local-time; UTC is the documented
/// deviation for v1, logged in deviations.md).
#[must_use]
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)] // bounded civil fields
pub fn ipp_datetime(epoch: i64) -> Value {
    // Civil-from-days algorithm (Howard Hinnant), avoiding libc gmtime.
    let days = epoch.div_euclid(86_400);
    let secs = epoch.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    Value::DateTime([
        (y >> 8) as u8,
        (y & 0xff) as u8,
        m as u8,
        d as u8,
        (secs / 3600) as u8,
        ((secs % 3600) / 60) as u8,
        (secs % 60) as u8,
        0,
        b'+',
        0,
        0,
    ])
}
