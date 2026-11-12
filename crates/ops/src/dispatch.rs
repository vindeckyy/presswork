//! `cupsdProcessIPPRequest()` — validation preamble + op switch.

use ipp_codec::{ops::op, ops::status, tags, Attribute, IppMessage, Value};
use job::{Job, Jobs};
use printer::{ptype, Printer, Registry};
use std::sync::RwLock;

use crate::common::{copy_printer_attrs, new_response, requested_attrs, send_status};

/// Per-request context — the pieces of global server state handlers
/// consult (the `con`/`cupsd` globals in the C scheduler).
pub struct Ctx<'a> {
    /// Destination registry (shared; admin ops take the write lock).
    pub registry: &'a RwLock<Registry>,
    /// Remote hostname for generated URIs (`httpGetHostname`).
    pub hostname: String,
    /// Listen port for generated URIs.
    pub port: u16,
    /// Whether the connection is TLS (`ipps`/`https` in URIs).
    pub is_encrypted: bool,
    /// Whether the client is on localhost (`!shared` hidden otherwise).
    pub is_local: bool,
    /// Authenticated username if any.
    pub username: Option<String>,
    /// `requesting-user-name` fallback.
    pub requesting_user: Option<String>,
    /// Negotiated response language (`attributes-natural-language`).
    pub language: String,
    /// `DefaultLanguage` config.
    pub default_language: String,
    /// `uri-authentication-supported` for this listener/location.
    pub uri_authentication: String,
    /// `cups-version` string (`CUPS_SVERSION` tail).
    pub cups_version: String,
    /// `Classification` (banner override; empty = per-queue banners).
    pub classification: String,
    /// Banner names present in `Banners` dir.
    pub banners: Vec<String>,
    /// `MultipleOperationTimeout`.
    pub multiple_operation_timeout: i32,
    /// `MaxLeaseDuration`.
    pub max_lease_duration: i32,
    /// `MaxEvents`.
    pub max_events: i32,
    /// Notifier scheme names present in `ServerBin/notifier`.
    pub notifiers: Vec<String>,
    /// `printer-op-policy-supported` (policy names).
    pub policies: Vec<String>,
    /// `server-is-sharing-printers` (`Browsing && BrowseLocalProtocols`).
    pub sharing: bool,
    /// `operations-supported` — the op list the daemon advertises.
    pub operations_supported: Vec<i32>,
    /// StrictConformance mode.
    pub strict: bool,
    /// Queued job count per printer (0 until the `job` crate lands).
    pub queued_job_count: i32,
    /// The job table (P2) — mutated by print/cancel ops.
    pub jobs: &'a RwLock<Jobs>,
    /// MIME database for filter-chain resolution.
    pub mime: &'a mime_db::MimeDb,
    /// `RequestRoot` spool dir.
    pub request_root: std::path::PathBuf,
    /// `ServerBin` dir (filters/backends live under it).
    pub server_bin: std::path::PathBuf,
    /// Raw document bytes that followed the IPP attrs in the request
    /// (Print-Job / Send-Document payload). Empty for ops without a body.
    pub document: &'a [u8],
    /// Filename for the document (`document-name`/`job-name` fallback).
    pub document_name: String,
    /// `CUPS_SERVERROOT` — printers.conf lives at `{root}/printers.conf`.
    pub server_root: std::path::PathBuf,
    /// Client IP for authz host masks.
    pub client_addr: std::net::IpAddr,
    /// Groups the authenticated user belongs to (`@SYSTEM` expansion).
    pub user_groups: Vec<String>,
    /// Configured policies for `authz::op_allowed`.
    pub policy_defs: &'a [cups_config::Policy],
    /// `SystemGroup` names (`@SYSTEM` maps here).
    pub system_groups: Vec<String>,
}

impl<'a> Ctx<'a> {
    /// Short-lived read guard on the registry.
    pub fn reg(&self) -> std::sync::RwLockReadGuard<'_, Registry> {
        self.registry.read().unwrap_or_else(|e| e.into_inner())
    }

    /// Write guard on the registry (admin ops only).
    pub fn reg_write(&self) -> std::sync::RwLockWriteGuard<'_, Registry> {
        self.registry.write().unwrap_or_else(|e| e.into_inner())
    }

    /// Build a context with config-derived defaults.
    #[must_use]
    pub fn new(
        registry: &'a RwLock<Registry>,
        cfg: &'a cups_config::Config,
        port: u16,
        jobs: &'a RwLock<Jobs>,
        mime: &'a mime_db::MimeDb,
    ) -> Self {
        let mut ops: Vec<i32> = vec![
            i32::from(op::PRINT_JOB),
            i32::from(op::VALIDATE_JOB),
            i32::from(op::CREATE_JOB),
            i32::from(op::SEND_DOCUMENT),
            i32::from(op::CANCEL_JOB),
            i32::from(op::GET_JOB_ATTRIBUTES),
            i32::from(op::GET_JOBS),
            i32::from(op::GET_PRINTER_ATTRIBUTES),
            i32::from(op::HOLD_JOB),
            i32::from(op::RELEASE_JOB),
            i32::from(op::PAUSE_PRINTER),
            i32::from(op::RESUME_PRINTER),
            i32::from(op::PURGE_JOBS),
            i32::from(op::SET_PRINTER_ATTRIBUTES),
            i32::from(op::SET_JOB_ATTRIBUTES),
            i32::from(op::GET_PRINTER_SUPPORTED_VALUES),
            i32::from(op::CREATE_PRINTER_SUBSCRIPTIONS),
            i32::from(op::CREATE_JOB_SUBSCRIPTIONS),
            i32::from(op::GET_SUBSCRIPTION_ATTRIBUTES),
            i32::from(op::GET_SUBSCRIPTIONS),
            i32::from(op::RENEW_SUBSCRIPTION),
            i32::from(op::CANCEL_SUBSCRIPTION),
            i32::from(op::GET_NOTIFICATIONS),
            i32::from(op::ENABLE_PRINTER),
            i32::from(op::DISABLE_PRINTER),
            i32::from(op::HOLD_NEW_JOBS),
            i32::from(op::RELEASE_HELD_NEW_JOBS),
            i32::from(op::CANCEL_JOBS),
            i32::from(op::CANCEL_MY_JOBS),
            i32::from(op::CLOSE_JOB),
            i32::from(op::CUPS_GET_DEFAULT),
            i32::from(op::CUPS_GET_PRINTERS),
            i32::from(op::CUPS_ADD_MODIFY_PRINTER),
            i32::from(op::CUPS_DELETE_PRINTER),
            i32::from(op::CUPS_GET_CLASSES),
            i32::from(op::CUPS_ADD_MODIFY_CLASS),
            i32::from(op::CUPS_DELETE_CLASS),
            i32::from(op::CUPS_ACCEPT_JOBS),
            i32::from(op::CUPS_REJECT_JOBS),
            i32::from(op::CUPS_SET_DEFAULT),
            i32::from(op::CUPS_GET_DEVICES),
            i32::from(op::CUPS_GET_PPDS),
            i32::from(op::CUPS_MOVE_JOB),
            i32::from(op::CUPS_AUTHENTICATE_JOB),
            i32::from(op::CUPS_GET_PPD),
            i32::from(op::CUPS_GET_DOCUMENT),
            i32::from(op::RESTART_JOB),
        ];
        ops.sort_unstable();
        Self {
            registry,
            hostname: "localhost".into(),
            port,
            is_encrypted: false,
            is_local: true,
            username: None,
            requesting_user: None,
            language: cfg
                .cupsd
                .default_language
                .clone()
                .unwrap_or_else(|| "en".into()),
            default_language: cfg
                .cupsd
                .default_language
                .clone()
                .unwrap_or_else(|| "en".into()),
            uri_authentication: "none".into(),
            cups_version: format!("{}.{}", 2, 5),
            classification: cfg.cupsd.classification.clone().unwrap_or_default(),
            banners: Vec::new(),
            multiple_operation_timeout: cfg.cupsd.multiple_operation_timeout,
            max_lease_duration: cfg.cupsd.max_lease_duration,
            max_events: cfg.cupsd.max_events,
            notifiers: Vec::new(),
            policies: cfg.cupsd.policies.iter().map(|p| p.name.clone()).collect(),
            policy_defs: &cfg.cupsd.policies,
            sharing: cfg.cupsd.browsing && cfg.cupsd.browse_local_protocols.0 != 0,
            operations_supported: ops,
            strict: cfg.cupsd.strict_conformance,
            queued_job_count: 0,
            jobs,
            mime,
            request_root: cfg
                .files
                .request_root
                .clone()
                .unwrap_or_else(|| "/var/spool/cups".into())
                .into(),
            server_bin: cfg
                .files
                .server_bin
                .clone()
                .unwrap_or_else(|| "/usr/lib/cups".into())
                .into(),
            document: &[],
            document_name: String::new(),
            server_root: std::path::PathBuf::from("/etc/cups"),
            client_addr: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            user_groups: Vec::new(),
            system_groups: cfg.files.system_group_names.clone(),
        }
    }
}

/// `cupsdProcessIPPRequest()` — validate, then run the op switch.
#[must_use]
pub fn dispatch(req: &IppMessage, ctx: &Ctx) -> IppMessage {
    let mut resp = new_response(req, &ctx.default_language);

    // --- Validation preamble (mirrors cupsdProcessIPPRequest order) ---
    if req.version.0 != 1 && req.version.0 != 2 {
        send_status(
            &mut resp,
            status::ERROR_VERSION_NOT_SUPPORTED,
            format!(
                "Bad request version number {}.{}.",
                req.version.0, req.version.1
            ),
        );
        return resp;
    }
    if req.request_id < 1 {
        send_status(
            &mut resp,
            status::ERROR_BAD_REQUEST,
            format!("Bad request ID {}.", req.request_id),
        );
        return resp;
    }
    if req.groups.is_empty() || req.groups[0].attributes.is_empty() {
        send_status(
            &mut resp,
            status::ERROR_BAD_REQUEST,
            "No attributes in request.",
        );
        return resp;
    }

    // Groups must be non-decreasing (tag order).
    {
        let mut prev = 0u8;
        for g in &req.groups {
            if g.tag < prev && g.tag != tags::ZERO {
                send_status(
                    &mut resp,
                    status::ERROR_BAD_REQUEST,
                    format!(
                        "Attribute groups are out of order ({:#x} < {:#x}).",
                        g.tag, prev
                    ),
                );
                return resp;
            }
            prev = g.tag;
        }
    }

    // First two op attrs must be charset + natural-language.
    let op_group = match req.group(tags::OPERATION) {
        Some(g) => g,
        None => {
            send_status(
                &mut resp,
                status::ERROR_BAD_REQUEST,
                "No attributes in request.",
            );
            return resp;
        }
    };
    let charset_ok = op_group
        .attributes
        .first()
        .is_some_and(|a| a.name == "attributes-charset" && a.values.len() == 1)
        && matches!(op_group.attributes[0].first(), Some(Value::Charset(t)) if {
            let s = t.as_str();
            s.eq_ignore_ascii_case("us-ascii") || s.eq_ignore_ascii_case("utf-8")
        });
    let language_ok = op_group
        .attributes
        .get(1)
        .is_some_and(|a| a.name == "attributes-natural-language" && a.values.len() == 1)
        && matches!(op_group.attributes[1].first(), Some(Value::NaturalLanguage(t)) if valid_lang(&t.as_str()));

    if !charset_ok {
        send_status(
            &mut resp,
            status::ERROR_CHARSET,
            "Unsupported \"attributes-charset\" value.".to_string(),
        );
        return resp;
    }
    if !language_ok {
        send_status(
            &mut resp,
            status::ERROR_BAD_REQUEST,
            "Bad \"attributes-natural-language\" value.".to_string(),
        );
        return resp;
    }

    // printer-uri/job-uri required except for the system-wide reads.
    let needs_uri = !matches!(
        req.code,
        x if x == op::CUPS_GET_DEFAULT
            || x == op::CUPS_GET_PRINTERS
            || x == op::CUPS_GET_CLASSES
            || x == op::CUPS_GET_DEVICES
            || x == op::CUPS_GET_PPDS
    );
    let uri_attr = if needs_uri {
        match req
            .find(tags::OPERATION, "printer-uri")
            .or_else(|| req.find(tags::OPERATION, "job-uri"))
        {
            Some(a) => Some(a),
            None => {
                send_status(
                    &mut resp,
                    status::ERROR_BAD_REQUEST,
                    "Missing required attributes.",
                );
                return resp;
            }
        }
    } else {
        req.find(tags::OPERATION, "printer-uri")
            .or_else(|| req.find(tags::OPERATION, "job-uri"))
    };

    // --- The op switch (read-only subset for P1) ---
    run_op(req, &mut resp, ctx, uri_attr);
    resp
}

fn run_op(req: &IppMessage, resp: &mut IppMessage, ctx: &Ctx, uri_attr: Option<&Attribute>) {
    match u32::from(req.code) {
        x if x == u32::from(op::GET_PRINTER_ATTRIBUTES) => {
            get_printer_attrs(req, resp, ctx, uri_attr)
        }
        x if x == u32::from(op::GET_PRINTER_SUPPORTED_VALUES) => {
            get_printer_supported(resp, ctx, uri_attr);
        }
        x if x == u32::from(op::CUPS_GET_DEFAULT) => get_default(req, resp, ctx),
        x if x == u32::from(op::CUPS_GET_PRINTERS) => get_printers(req, resp, ctx, 0),
        x if x == u32::from(op::CUPS_GET_CLASSES) => get_printers(req, resp, ctx, ptype::CLASS),
        x if x == u32::from(op::VALIDATE_JOB) => validate_job(req, resp, ctx, uri_attr),
        x if x == u32::from(op::GET_JOBS) => get_jobs(req, resp, ctx, uri_attr),
        x if x == u32::from(op::PRINT_JOB) => print_job(req, resp, ctx, uri_attr),
        x if x == u32::from(op::CREATE_JOB) => create_job(req, resp, ctx, uri_attr),
        x if x == u32::from(op::SEND_DOCUMENT) => send_document(req, resp, ctx, uri_attr),
        x if x == u32::from(op::CANCEL_JOB) => cancel_job(req, resp, ctx, uri_attr),
        x if x == u32::from(op::GET_JOB_ATTRIBUTES) => get_job_attributes(req, resp, ctx, uri_attr),
        x if x == u32::from(op::CUPS_ADD_MODIFY_PRINTER) => {
            add_modify_printer(req, resp, ctx, uri_attr)
        }
        x if x == u32::from(op::CUPS_DELETE_PRINTER) => delete_printer(req, resp, ctx, uri_attr),
        x if x == u32::from(op::CUPS_SET_DEFAULT) => set_default(req, resp, ctx, uri_attr),
        x if x == u32::from(op::PAUSE_PRINTER) => set_printer_state(req, resp, ctx, uri_attr, 5),
        x if x == u32::from(op::RESUME_PRINTER) => set_printer_state(req, resp, ctx, uri_attr, 3),
        x if x == u32::from(op::CUPS_ACCEPT_JOBS) || x == u32::from(op::ENABLE_PRINTER) => {
            set_accepting(req, resp, ctx, uri_attr, true)
        }
        x if x == u32::from(op::CUPS_REJECT_JOBS) || x == u32::from(op::DISABLE_PRINTER) => {
            set_accepting(req, resp, ctx, uri_attr, false)
        }
        x if x == u32::from(op::SET_PRINTER_ATTRIBUTES) => {
            set_printer_attributes(req, resp, ctx, uri_attr)
        }
        x if x == u32::from(op::CUPS_GET_DEVICES) => get_devices(req, resp, ctx),
        x if x == u32::from(op::CUPS_GET_PPDS) => {
            send_status(
                resp,
                status::ERROR_OPERATION_NOT_SUPPORTED,
                "CUPS-Get-PPDs not supported.",
            );
        }
        x => {
            send_status(
                resp,
                status::ERROR_OPERATION_NOT_SUPPORTED,
                format!(
                    "{} not supported.",
                    ipp_codec::ops::op::name(u16::try_from(x).unwrap_or(0))
                ),
            );
        }
    }
}

/// `get_printer_attrs()` — `Get-Printer-Attributes`.
fn get_printer_attrs(
    req: &IppMessage,
    resp: &mut IppMessage,
    ctx: &Ctx,
    uri_attr: Option<&Attribute>,
) {
    let Some(uri) = uri_attr.and_then(attr_text) else {
        send_status(
            resp,
            status::ERROR_BAD_REQUEST,
            "Missing \"printer-uri\" attribute.",
        );
        return;
    };
    let reg = ctx.reg();
    let Some((p, _is_class)) = reg.validate_dest(&uri) else {
        send_status(
            resp,
            status::ERROR_NOT_FOUND,
            "The printer or class does not exist.",
        );
        return;
    };
    let ra = requested_attrs(req);
    copy_printer_attrs(resp, p, ctx, &ra, ctx.queued_job_count);
    resp.code = status::OK;
}

/// `get_printer_supported()` — `Get-Printer-Supported-Values` returns
/// the admin-define list for Set-Printer-Attributes.
fn get_printer_supported(resp: &mut IppMessage, ctx: &Ctx, uri_attr: Option<&Attribute>) {
    let Some(uri) = uri_attr.and_then(attr_text) else {
        send_status(
            resp,
            status::ERROR_BAD_REQUEST,
            "Missing \"printer-uri\" attribute.",
        );
        return;
    };
    if ctx.reg().validate_dest(&uri).is_none() {
        send_status(
            resp,
            status::ERROR_NOT_FOUND,
            "The printer or class does not exist.",
        );
        return;
    }
    for name in [
        "printer-geo-location",
        "printer-info",
        "printer-location",
        "printer-organization",
        "printer-organizational-unit",
    ] {
        resp.push(
            tags::PRINTER,
            Attribute::new(name, tags::ADMINDEFINE, vec![Value::AdminDefine]),
        );
    }
    resp.code = status::OK;
}

/// `get_default()` — `CUPS-Get-Default`.
fn get_default(req: &IppMessage, resp: &mut IppMessage, ctx: &Ctx) {
    let reg = ctx.reg();
    let Some(p) = reg.default_printer() else {
        send_status(resp, status::ERROR_NOT_FOUND, "No default printer.");
        return;
    };
    let ra = requested_attrs(req);
    copy_printer_attrs(resp, p, ctx, &ra, ctx.queued_job_count);
    resp.code = status::OK;
}

/// `get_printers(type)` — `CUPS-Get-Printers` / `CUPS-Get-Classes` with
/// the upstream filter set (limit, first-printer-name, printer-id,
/// printer-type, printer-type-mask, printer-location, user ACL,
/// !local hides unshared).
fn get_printers(req: &IppMessage, resp: &mut IppMessage, ctx: &Ctx, want_class: i32) {
    if ctx.reg().printers.is_empty() {
        send_status(resp, status::ERROR_NOT_FOUND, "No destinations added.");
        return;
    }
    let limit = int_attr(req, "limit").unwrap_or(10_000_000);
    let first = req
        .find(tags::OPERATION, "first-printer-name")
        .and_then(attr_text);
    let printer_id = int_attr(req, "printer-id");
    if printer_id.is_some_and(|id| id <= 0) {
        send_status(
            resp,
            status::ERROR_ATTRIBUTES_OR_VALUES,
            format!("Bad \"printer-id\" value {}.", printer_id.unwrap_or(0)),
        );
        return;
    }
    let pt_filter = int_attr(req, "printer-type").unwrap_or(0);
    let pt_mask = int_attr(req, "printer-type-mask").unwrap_or(0);
    let loc_filter = req
        .find(tags::OPERATION, "printer-location")
        .and_then(attr_text);
    let username = ctx
        .username
        .clone()
        .or_else(|| {
            req.find(tags::OPERATION, "requesting-user-name")
                .and_then(attr_text)
        })
        .or_else(|| ctx.requesting_user.clone());
    let ra = requested_attrs(req);

    // Start at first-printer-name when given (else BTree head).
    let reg = ctx.reg();
    let mut iter: Vec<&Printer> = reg.printers.values().collect();
    if let Some(first_name) = first {
        if let Some(pos) = iter.iter().position(|p| p.name == first_name) {
            iter = iter.split_off(pos);
        }
    }

    let mut count = 0i64;
    for p in iter {
        if count >= limit {
            break;
        }
        if !ctx.is_local && !p.shared {
            continue;
        }
        if let Some(id) = printer_id {
            if i64::from(p.printer_id) != id {
                continue;
            }
        }
        if want_class != 0 && !p.is_class() {
            continue;
        }
        if want_class == 0 && p.is_class() {
            continue;
        }
        if i64::from(p.effective_ptype(reg.default.as_deref() == Some(p.name.as_str()))) & pt_mask
            != pt_filter
        {
            continue;
        }
        if let Some(loc) = &loc_filter {
            match &p.location {
                Some(l) if l.eq_ignore_ascii_case(loc) => {}
                _ => continue,
            }
        }
        if !p.users.is_empty() {
            if let Some(u) = &username {
                if !p.user_allowed(u) {
                    continue;
                }
            }
        }
        if count > 0 {
            resp.group_mut(tags::PRINTER); // group separator for next printer
        }
        copy_printer_attrs(resp, p, ctx, &ra, ctx.queued_job_count);
        count += 1;
    }
    resp.code = status::OK;
}

/// `validate_job()` — P1 subset: dest must exist + accept jobs.
/// Full option/template validation lands with the job crate (P2).
fn validate_job(req: &IppMessage, resp: &mut IppMessage, ctx: &Ctx, uri_attr: Option<&Attribute>) {
    let Some(uri) = uri_attr.and_then(attr_text) else {
        send_status(
            resp,
            status::ERROR_BAD_REQUEST,
            "Missing \"printer-uri\" attribute.",
        );
        return;
    };
    let reg = ctx.reg();
    let Some((p, _)) = reg.validate_dest(&uri) else {
        send_status(
            resp,
            status::ERROR_NOT_FOUND,
            "The printer or class does not exist.",
        );
        return;
    };
    if !p.accepting {
        send_status(
            resp,
            status::ERROR_NOT_ACCEPTING_JOBS,
            "Destination is not accepting jobs.",
        );
        return;
    }
    let _ = req;
    resp.code = status::OK;
}

/// `get_jobs()` — returns an empty job list until the `job` crate
/// lands (status OK with no job groups is a valid empty answer).
fn get_jobs(req: &IppMessage, resp: &mut IppMessage, ctx: &Ctx, uri_attr: Option<&Attribute>) {
    let Some(uri) = uri_attr.and_then(attr_text) else {
        send_status(
            resp,
            status::ERROR_BAD_REQUEST,
            "Missing \"printer-uri\" attribute.",
        );
        return;
    };
    let reg = ctx.reg();
    let Some((p, _)) = reg.validate_dest(&uri) else {
        send_status(
            resp,
            status::ERROR_NOT_FOUND,
            "The printer or class does not exist.",
        );
        return;
    };
    let which = req
        .find(tags::OPERATION, "which-jobs")
        .and_then(attr_text)
        .unwrap_or_else(|| "not-completed".into());
    let jobs = ctx.jobs.read().unwrap_or_else(|e| e.into_inner());
    for j in jobs.for_printer(&p.name) {
        let done = j.state.is_final();
        let emit = match which.as_str() {
            "completed" => done,
            "all" => true,
            _ => !done, // "not-completed" default
        };
        if emit {
            add_job_group(resp, j, ctx);
        }
    }
    resp.code = status::OK;
}

/// String payload of an attr's first value (text/name/uri/keyword).
fn attr_text(a: &Attribute) -> Option<String> {
    match a.first()? {
        Value::Text(t)
        | Value::Name(t)
        | Value::Uri(t)
        | Value::Keyword(t)
        | Value::UriScheme(t) => Some(t.as_str().to_string()),
        _ => None,
    }
}

/// Integer/enum attribute first value.
fn attr_int(a: &Attribute) -> Option<i64> {
    match a.first()? {
        Value::Integer(i) | Value::Enum(i) => Some(i64::from(*i)),
        _ => None,
    }
}

/// Integer payload of an op-group attr.
fn int_attr(req: &IppMessage, name: &str) -> Option<i64> {
    req.find(tags::OPERATION, name)
        .and_then(|a| a.first())
        .and_then(|v| match v {
            Value::Integer(i) | Value::Enum(i) => Some(i64::from(*i)),
            _ => None,
        })
}

/// Basic `attributes-natural-language` sanity — RFC 3066 token shape.
fn valid_lang(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 35
        && s.split('-')
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_alphanumeric()))
}

// ==================== P2: job operations ====================

/// `print_job()` — Print-Job: one document + one new job in a single op.
/// Validates dest, spools `ctx.document` to `d%05d-001`, creates the job
/// pending, and returns the job group.
fn print_job(req: &IppMessage, resp: &mut IppMessage, ctx: &Ctx, uri_attr: Option<&Attribute>) {
    let Some((dest, _)) = validate_accepting(ctx, resp, uri_attr) else {
        return;
    };
    let format = req
        .find(tags::OPERATION, "document-format")
        .and_then(attr_text)
        .unwrap_or_else(|| "application/octet-stream".into());
    let title = req
        .find(tags::OPERATION, "job-name")
        .and_then(attr_text)
        .or_else(|| {
            req.find(tags::OPERATION, "document-name")
                .and_then(attr_text)
        })
        .unwrap_or_else(|| ctx.document_name.clone());
    let user = ctx
        .requesting_user
        .clone()
        .or_else(|| {
            req.find(tags::OPERATION, "requesting-user-name")
                .and_then(attr_text)
        })
        .unwrap_or_else(|| "anonymous".into());
    let copies = req
        .find(tags::OPERATION, "copies")
        .and_then(attr_int)
        .map_or(1, |v| v.max(1) as i32);

    let mut jobs = ctx.jobs.write().unwrap_or_else(|e| e.into_inner());
    let id = jobs.alloc_id();
    let mut job = Job::new(id, dest.clone(), user);
    job.title = title;
    job.copies = copies;
    job.format = format.clone();
    job.attrs = req
        .groups
        .iter()
        .find(|g| g.tag == tags::JOB)
        .map(|g| g.attributes.clone())
        .unwrap_or_default();

    // Spool the document.
    let data = job::Job::data_path(&ctx.request_root, id, 1);
    if let Err(e) = std::fs::write(&data, ctx.document) {
        send_status(resp, status::ERROR_INTERNAL, &format!("spool write: {e}"));
        return;
    }
    let filetype = sniff(&ctx.mime, &data, &format);
    job.files.push(job::JobFile {
        num: 1,
        filetype,
        size: ctx.document.len() as u64,
        name: ctx.document_name.clone(),
        format,
    });
    if jobs.add(&ctx.request_root, job).is_err() {
        send_status(resp, status::ERROR_INTERNAL, "cannot save job");
        return;
    }
    resp.code = status::OK;
    add_job_group(resp, jobs.get(id).unwrap(), ctx);
}

/// `create_job()` — allocates an empty job awaiting Send-Document(s).
fn create_job(req: &IppMessage, resp: &mut IppMessage, ctx: &Ctx, uri_attr: Option<&Attribute>) {
    let Some((dest, _)) = validate_accepting(ctx, resp, uri_attr) else {
        return;
    };
    let user = ctx
        .requesting_user
        .clone()
        .or_else(|| {
            req.find(tags::OPERATION, "requesting-user-name")
                .and_then(attr_text)
        })
        .unwrap_or_else(|| "anonymous".into());
    let mut jobs = ctx.jobs.write().unwrap_or_else(|e| e.into_inner());
    let id = jobs.alloc_id();
    let mut job = Job::new(id, dest.clone(), user);
    job.state = job::JobState::PendingHeld; // awaiting documents
    job.reasons = vec!["job-data-insufficient".into()];
    job.title = req
        .find(tags::OPERATION, "job-name")
        .and_then(attr_text)
        .unwrap_or_default();
    job.attrs = req
        .groups
        .iter()
        .find(|g| g.tag == tags::JOB)
        .map(|g| g.attributes.clone())
        .unwrap_or_default();
    if jobs.add(&ctx.request_root, job).is_err() {
        send_status(resp, status::ERROR_INTERNAL, "cannot save job");
        return;
    }
    resp.code = status::OK;
    add_job_group(resp, jobs.get(id).unwrap(), ctx);
}

/// `send_document()` — attach a document to an existing Create-Job job.
fn send_document(req: &IppMessage, resp: &mut IppMessage, ctx: &Ctx, uri_attr: Option<&Attribute>) {
    let Some(id) = job_id(req, uri_attr) else {
        send_status(resp, status::ERROR_NOT_FOUND, "Job not found.");
        return;
    };
    let mut jobs = ctx.jobs.write().unwrap_or_else(|e| e.into_inner());
    let Some(job) = jobs.get_mut(id) else {
        send_status(resp, status::ERROR_NOT_FOUND, "Job not found.");
        return;
    };
    let num = job.files.len() as u32 + 1;
    let data = job::Job::data_path(&ctx.request_root, id, num);
    if std::fs::write(&data, ctx.document).is_err() {
        send_status(resp, status::ERROR_INTERNAL, "spool write");
        return;
    }
    let format = req
        .find(tags::OPERATION, "document-format")
        .and_then(attr_text)
        .unwrap_or_else(|| job.format.clone());
    let filetype = sniff(&ctx.mime, &data, &format);
    job.files.push(job::JobFile {
        num,
        filetype,
        size: ctx.document.len() as u64,
        name: ctx.document_name.clone(),
        format,
    });
    // `last-document` flag finalizes the job.
    let last = req
        .find(tags::OPERATION, "last-document")
        .and_then(|a| a.values.first())
        .is_some_and(|v| matches!(v, Value::Boolean(true)));
    if last {
        job.state = job::JobState::Pending;
        job.reasons = vec!["job-incoming".into()];
    }
    let _ = jobs.save(&ctx.request_root, id);
    resp.code = status::OK;
    add_job_group(resp, jobs.get(id).unwrap(), ctx);
}

/// `cancel_job()` — cancel + purge a job (state -> canceled, files removed).
fn cancel_job(req: &IppMessage, resp: &mut IppMessage, ctx: &Ctx, uri_attr: Option<&Attribute>) {
    let Some(id) = job_id(req, uri_attr) else {
        send_status(resp, status::ERROR_NOT_FOUND, "Job not found.");
        return;
    };
    let mut jobs = ctx.jobs.write().unwrap_or_else(|e| e.into_inner());
    if jobs.get(id).is_none() {
        send_status(resp, status::ERROR_NOT_FOUND, "Job not found.");
        return;
    }
    if let Some(j) = jobs.get_mut(id) {
        j.state = job::JobState::Canceled;
        j.completed_at = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
        );
        let _ = j.save(&ctx.request_root);
    }
    resp.code = status::OK;
    add_job_group(resp, jobs.get(id).unwrap(), ctx);
}

/// `get_job_attributes()` — one job's full attribute set.
fn get_job_attributes(
    req: &IppMessage,
    resp: &mut IppMessage,
    ctx: &Ctx,
    uri_attr: Option<&Attribute>,
) {
    let Some(id) = job_id(req, uri_attr) else {
        send_status(resp, status::ERROR_NOT_FOUND, "Job not found.");
        return;
    };
    let jobs = ctx.jobs.read().unwrap_or_else(|e| e.into_inner());
    let Some(job) = jobs.get(id) else {
        send_status(resp, status::ERROR_NOT_FOUND, "Job not found.");
        return;
    };
    resp.code = status::OK;
    add_job_group(resp, job, ctx);
}

// ---------- job helpers ----------

/// Validate printer-uri exists + accepts jobs; returns `(queue-name, uri)`.
fn validate_accepting(
    ctx: &Ctx,
    resp: &mut IppMessage,
    uri_attr: Option<&Attribute>,
) -> Option<(String, String)> {
    let Some(uri) = uri_attr.and_then(attr_text) else {
        send_status(resp, status::ERROR_BAD_REQUEST, "Missing \"printer-uri\".");
        return None;
    };
    let (name, accepting) = {
        let reg = ctx.reg();
        match reg.validate_dest(&uri) {
            Some((p, _)) => (p.name.clone(), p.accepting),
            None => {
                send_status(
                    resp,
                    status::ERROR_NOT_FOUND,
                    "The printer or class does not exist.",
                );
                return None;
            }
        }
    };
    if !accepting {
        send_status(
            resp,
            status::ERROR_NOT_ACCEPTING_JOBS,
            "Destination is not accepting jobs.",
        );
        return None;
    }
    Some((name, uri))
}

/// Resolve the job-id from `job-uri`/`job-id` attrs.
fn job_id(req: &IppMessage, uri_attr: Option<&Attribute>) -> Option<i32> {
    // `job-id` integer first, else parse `job-uri` trailing id.
    if let Some(a) = req.find(tags::OPERATION, "job-id") {
        if let Some(Value::Integer(i) | Value::Enum(i)) = a.values.first() {
            return Some(*i);
        }
    }
    uri_attr
        .and_then(attr_text)
        .and_then(|u| u.rsplit('/').next().and_then(|s| s.parse().ok()))
}

/// Sniff the real MIME type of a spool file when the client said
/// octet-stream, else trust the declared format.
fn sniff(mime: &mime_db::MimeDb, path: &std::path::Path, declared: &str) -> String {
    if declared != "application/octet-stream" {
        return declared.into();
    }
    let mut head = [0u8; 8192];
    let n = std::fs::File::open(path)
        .and_then(|mut f| std::io::Read::read(&mut f, &mut head))
        .unwrap_or(0);
    mime.detect(path.to_str().unwrap_or(""), &head[..n])
        .map(|t| t.name())
        .unwrap_or_else(|| declared.into())
}

/// Emit a `job` attribute group into `resp` for `job` (`cupsdCopyJob`).
fn add_job_group(resp: &mut IppMessage, job: &Job, ctx: &Ctx) {
    let g = resp.group_mut(tags::JOB);
    let mut add = |name: &str, tag: u8, v: Value| {
        if g.find(name).is_none() {
            g.attributes.push(Attribute::new(name, tag, vec![v]));
        }
    };
    let scheme = if ctx.is_encrypted { "ipps" } else { "ipp" };
    add("job-id", tags::INTEGER, Value::Integer(job.id));
    add(
        "job-uri",
        tags::URI,
        Value::Text(format!("{scheme}://{}:{}/jobs/{}", ctx.hostname, ctx.port, job.id).into()),
    );
    add(
        "job-printer-uri",
        tags::URI,
        Value::Text(
            format!(
                "{scheme}://{}:{}/printers/{}",
                ctx.hostname, ctx.port, job.dest
            )
            .into(),
        ),
    );
    add("job-state", tags::ENUM, Value::Enum(job.state as i32));
    add(
        "job-state-reasons",
        tags::KEYWORD,
        Value::Keyword(job.reasons.first().cloned().unwrap_or_default().into()),
    );
    add(
        "job-originating-user-name",
        tags::NAME,
        Value::Name(job.username.clone().into()),
    );
    add(
        "job-name",
        tags::NAME,
        Value::Name(job.title.clone().into()),
    );
    add("job-priority", tags::INTEGER, Value::Integer(job.priority));
    add("copies", tags::INTEGER, Value::Integer(job.copies));
    add(
        "document-format",
        tags::MIMETYPE,
        Value::Text(job.format.clone().into()),
    );
    add(
        "time-at-creation",
        tags::INTEGER,
        Value::Integer(job.created_at as i32),
    );
    if let Some(t) = job.completed_at {
        add("time-at-completed", tags::INTEGER, Value::Integer(t as i32));
    }
}

/// `get_devices()` — run `cups-deviced` and emit each discovered device as
/// `device-class/device-uri/device-make-and-model/device-info/device-id`
/// (`CUPS-Get-Devices`, P3).
fn get_devices(_req: &IppMessage, resp: &mut IppMessage, ctx: &Ctx) {
    let deviced = ctx.server_bin.join("cups-deviced");
    let backend_dir = ctx.server_bin.join("backend");
    let out = std::process::Command::new(&deviced)
        .args(["0", "0", "15", &backend_dir.to_string_lossy()])
        .output();
    let Ok(out) = out else {
        send_status(resp, status::ERROR_INTERNAL, "cannot run cups-deviced");
        return;
    };
    resp.code = status::OK;
    let g = resp.group_mut(tags::OPERATION);
    let _ = g;
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        // `class uri "make-model" "info" ["device-id"]`
        let mut it = line.splitn(3, ' ');
        let (Some(class_), Some(uri), rest) = (it.next(), it.next(), it.next()) else {
            continue;
        };
        let q = quoted_fields(rest.unwrap_or(""));
        let (mm, info, devid) = (
            q.first().cloned().unwrap_or_default(),
            q.get(1).cloned().unwrap_or_default(),
            q.get(2).cloned().unwrap_or_default(),
        );
        let g = resp.group_mut(tags::OPERATION);
        g.attributes.push(Attribute::new(
            "device-class",
            tags::KEYWORD,
            vec![Value::Keyword(class_.into())],
        ));
        g.attributes.push(Attribute::new(
            "device-uri",
            tags::URI,
            vec![Value::Uri(uri.into())],
        ));
        g.attributes.push(Attribute::new(
            "device-make-and-model",
            tags::TEXT,
            vec![Value::Text(mm.into())],
        ));
        g.attributes.push(Attribute::new(
            "device-info",
            tags::TEXT,
            vec![Value::Text(info.into())],
        ));
        if !devid.is_empty() {
            g.attributes.push(Attribute::new(
                "device-id",
                tags::TEXT,
                vec![Value::Text(devid.into())],
            ));
        }
    }
}

/// Split `"a" "b" "c"` quoted fields (handles embedded spaces).
fn quoted_fields(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut inq = false;
    for c in s.chars() {
        match c {
            '"' => {
                if inq {
                    out.push(std::mem::take(&mut cur));
                }
                inq = !inq;
            }
            c if inq => cur.push(c),
            _ => {}
        }
    }
    out
}

// ==================== P4: admin operations ====================

/// `authorize` — is this subject allowed `op` under the `default` policy?
/// Localhost requests pass; remote go through `authz::op_allowed` against
/// the configured `<Policy>` blocks (P4).
fn authorize(ctx: &Ctx, resp: &mut IppMessage, op: u32) -> bool {
    if ctx.is_local && ctx.system_groups.is_empty() {
        return true; // local admin, no SystemGroup configured
    }
    let user = ctx.username.as_deref().or(ctx.requesting_user.as_deref());
    let subj = authz::Subject {
        user,
        groups: &ctx.user_groups,
        addr: ctx.client_addr,
        host: &ctx.hostname,
        encrypted: ctx.is_encrypted,
    };
    if authz::op_allowed(ctx.policy_defs, Some("default"), op, &subj) {
        true
    } else {
        send_status(
            resp,
            status::ERROR_FORBIDDEN,
            "You do not have permission to access this resource.",
        );
        false
    }
}

/// Persist `printers.conf` after a registry mutation.
fn save_printers(ctx: &Ctx) {
    let reg = ctx.reg();
    let bytes = reg.save_printers_conf();
    drop(reg);
    let path = ctx.server_root.join("printers.conf");
    let tmp = path.with_extension("N");
    if std::fs::write(&tmp, &bytes).is_ok() {
        let _ = std::fs::rename(&tmp, &path);
    }
}

/// Resolve the queue name from `printer-uri` (`.../printers/NAME`).
fn printer_name_from_uri(uri_attr: Option<&Attribute>) -> Option<String> {
    uri_attr.and_then(attr_text).and_then(|u| {
        u.rsplit("/printers/")
            .next()
            .map(str::to_string)
            .filter(|n| !n.is_empty() && !n.contains('/'))
    })
}

/// `add_modify_printer()` — `CUPS-Add-Modify-Printer` (0x4003).
/// Creates the queue if absent, else updates the set attributes, then
/// persists `printers.conf`.
fn add_modify_printer(
    req: &IppMessage,
    resp: &mut IppMessage,
    ctx: &Ctx,
    uri_attr: Option<&Attribute>,
) {
    if !authorize(ctx, resp, u32::from(op::CUPS_ADD_MODIFY_PRINTER)) {
        return;
    }
    let Some(name) = printer_name_from_uri(uri_attr) else {
        send_status(resp, status::ERROR_BAD_REQUEST, "Bad printer-uri.");
        return;
    };
    let pg = req.groups.iter().find(|g| g.tag == tags::PRINTER);
    let attr = |n: &str| -> Option<&Attribute> {
        pg.and_then(|g| g.find(n))
            .or_else(|| req.find(tags::OPERATION, n))
    };
    let mut reg = ctx.reg_write();
    let exists = reg.printers.contains_key(&name);
    let device_uri = attr("device-uri")
        .and_then(attr_text)
        .unwrap_or_else(|| "file:///dev/null".into());
    let mut p = if exists {
        reg.printers.remove(&name).unwrap()
    } else {
        Printer::new(name.clone(), device_uri.clone())
    };
    if let Some(v) = attr("device-uri").and_then(attr_text) {
        p.device_uri = v;
    }
    if let Some(v) = attr("printer-info").and_then(attr_text) {
        p.info = Some(v);
    }
    if let Some(v) = attr("printer-location").and_then(attr_text) {
        p.location = Some(v);
    }
    if let Some(v) = attr("printer-geo-location").and_then(attr_text) {
        p.geo_location = Some(v);
    }
    if let Some(v) = attr("printer-make-and-model").and_then(attr_text) {
        p.make_model = Some(v);
    }
    if let Some(v) = attr("printer-state").and_then(attr_int) {
        p.state = v as i32;
        p.state_time = printer::now();
    }
    if let Some(a) = attr("printer-is-accepting-jobs") {
        if let Some(Value::Boolean(b)) = a.values.first() {
            p.accepting = *b;
        }
    }
    if let Some(a) = attr("printer-is-shared") {
        if let Some(Value::Boolean(b)) = a.values.first() {
            p.shared = *b;
        }
    }
    if let Some(v) = attr("printer-op-policy").and_then(attr_text) {
        p.op_policy = Some(v);
    }
    if let Some(v) = attr("printer-error-policy").and_then(attr_text) {
        p.error_policy = Some(v);
    }
    if !exists {
        p.state = 3; // idle
        p.state_time = printer::now();
        p.config_time = printer::now();
        p.accepting = true;
    }
    reg.add(p);
    drop(reg);
    save_printers(ctx);
    resp.code = status::OK;
}

/// `delete_printer()` — `CUPS-Delete-Printer` (0x4004).
fn delete_printer(
    _req: &IppMessage,
    resp: &mut IppMessage,
    ctx: &Ctx,
    uri_attr: Option<&Attribute>,
) {
    if !authorize(ctx, resp, u32::from(op::CUPS_DELETE_PRINTER)) {
        return;
    }
    let Some(name) = printer_name_from_uri(uri_attr) else {
        send_status(resp, status::ERROR_BAD_REQUEST, "Bad printer-uri.");
        return;
    };
    let mut reg = ctx.reg_write();
    if reg.printers.remove(&name).is_none() {
        send_status(resp, status::ERROR_NOT_FOUND, "The printer does not exist.");
        return;
    }
    if reg.default.as_deref() == Some(name.as_str()) {
        reg.default = None;
    }
    drop(reg);
    save_printers(ctx);
    resp.code = status::OK;
}

/// `set_default()` — `CUPS-Set-Default` (0x400a).
fn set_default(_req: &IppMessage, resp: &mut IppMessage, ctx: &Ctx, uri_attr: Option<&Attribute>) {
    if !authorize(ctx, resp, u32::from(op::CUPS_SET_DEFAULT)) {
        return;
    }
    let Some(name) = printer_name_from_uri(uri_attr) else {
        send_status(resp, status::ERROR_BAD_REQUEST, "Bad printer-uri.");
        return;
    };
    let mut reg = ctx.reg_write();
    if !reg.printers.contains_key(&name) {
        send_status(resp, status::ERROR_NOT_FOUND, "The printer does not exist.");
        return;
    }
    reg.default = Some(name);
    drop(reg);
    save_printers(ctx);
    resp.code = status::OK;
}

/// `pause`/`resume` — `Pause-Printer` (0x0010) / `Resume-Printer` (0x0011).
fn set_printer_state(
    _req: &IppMessage,
    resp: &mut IppMessage,
    ctx: &Ctx,
    uri_attr: Option<&Attribute>,
    state: i32,
) {
    let op = if state == 5 {
        op::PAUSE_PRINTER
    } else {
        op::RESUME_PRINTER
    };
    if !authorize(ctx, resp, u32::from(op)) {
        return;
    }
    let Some(name) = printer_name_from_uri(uri_attr) else {
        send_status(resp, status::ERROR_BAD_REQUEST, "Bad printer-uri.");
        return;
    };
    let mut reg = ctx.reg_write();
    let Some(p) = reg.printers.get_mut(&name) else {
        send_status(resp, status::ERROR_NOT_FOUND, "The printer does not exist.");
        return;
    };
    p.state = state;
    p.state_time = printer::now();
    drop(reg);
    save_printers(ctx);
    resp.code = status::OK;
}

/// `accept`/`reject` — `CUPS-Accept-Jobs`/`CUPS-Reject-Jobs` and the
/// `Enable/Disable-Printer` aliases.
fn set_accepting(
    req: &IppMessage,
    resp: &mut IppMessage,
    ctx: &Ctx,
    uri_attr: Option<&Attribute>,
    accepting: bool,
) {
    let op = if accepting {
        op::CUPS_ACCEPT_JOBS
    } else {
        op::CUPS_REJECT_JOBS
    };
    if !authorize(ctx, resp, u32::from(op)) {
        return;
    }
    let Some(name) = printer_name_from_uri(uri_attr) else {
        send_status(resp, status::ERROR_BAD_REQUEST, "Bad printer-uri.");
        return;
    };
    let mut reg = ctx.reg_write();
    let Some(p) = reg.printers.get_mut(&name) else {
        send_status(resp, status::ERROR_NOT_FOUND, "The printer does not exist.");
        return;
    };
    p.accepting = accepting;
    if !accepting {
        if let Some(r) = req
            .find(tags::OPERATION, "printer-state-message")
            .and_then(attr_text)
        {
            p.state_message = r;
        }
        if let Some(reasons) = req.find(tags::OPERATION, "printer-state-reasons") {
            p.reasons = reasons
                .values
                .iter()
                .filter_map(|v| match v {
                    Value::Keyword(t) | Value::Text(t) => Some(t.to_string()),
                    _ => None,
                })
                .collect();
        }
    } else {
        p.reasons.clear();
    }
    drop(reg);
    save_printers(ctx);
    resp.code = status::OK;
}

/// `set_printer_attributes()` — `Set-Printer-Attributes` (0x0013).
fn set_printer_attributes(
    req: &IppMessage,
    resp: &mut IppMessage,
    ctx: &Ctx,
    uri_attr: Option<&Attribute>,
) {
    if !authorize(ctx, resp, u32::from(op::SET_PRINTER_ATTRIBUTES)) {
        return;
    }
    let Some(name) = printer_name_from_uri(uri_attr) else {
        send_status(resp, status::ERROR_BAD_REQUEST, "Bad printer-uri.");
        return;
    };
    let mut reg = ctx.reg_write();
    let Some(p) = reg.printers.get_mut(&name) else {
        send_status(resp, status::ERROR_NOT_FOUND, "The printer does not exist.");
        return;
    };
    for g in &req.groups {
        if g.tag != tags::PRINTER && g.tag != tags::OPERATION {
            continue;
        }
        for a in &g.attributes {
            match a.name.as_str().as_ref() {
                "device-uri" => {
                    if let Some(v) = attr_text(a) {
                        p.device_uri = v;
                    }
                }
                "printer-info" => {
                    if let Some(v) = attr_text(a) {
                        p.info = Some(v);
                    }
                }
                "printer-location" => {
                    if let Some(v) = attr_text(a) {
                        p.location = Some(v);
                    }
                }
                "printer-geo-location" => {
                    if let Some(v) = attr_text(a) {
                        p.geo_location = Some(v);
                    }
                }
                "printer-make-and-model" => {
                    if let Some(v) = attr_text(a) {
                        p.make_model = Some(v);
                    }
                }
                "printer-is-accepting-jobs" => {
                    if let Some(Value::Boolean(b)) = a.values.first() {
                        p.accepting = *b;
                    }
                }
                "printer-is-shared" => {
                    if let Some(Value::Boolean(b)) = a.values.first() {
                        p.shared = *b;
                    }
                }
                "printer-state" => {
                    if let Some(v) = attr_int(a) {
                        p.state = v as i32;
                        p.state_time = printer::now();
                    }
                }
                "printer-op-policy" => {
                    if let Some(v) = attr_text(a) {
                        p.op_policy = Some(v);
                    }
                }
                "printer-error-policy" => {
                    if let Some(v) = attr_text(a) {
                        p.error_policy = Some(v);
                    }
                }
                "printer-is-temporary" => {
                    if let Some(Value::Boolean(b)) = a.values.first() {
                        p.temporary = *b;
                    }
                }
                _ => {}
            }
        }
    }
    drop(reg);
    save_printers(ctx);
    resp.code = status::OK;
}
