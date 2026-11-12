//! `cupsdProcessIPPRequest()` — validation preamble + op switch.

use ipp_codec::{ops::op, ops::status, tags, Attribute, IppMessage, Value};
use printer::{ptype, Printer, Registry};

use crate::common::{copy_printer_attrs, new_response, requested_attrs, send_status};

/// Per-request context — the pieces of global server state handlers
/// consult (the `con`/`cupsd` globals in the C scheduler).
pub struct Ctx<'a> {
    /// Destination registry (shared, read-locked by the daemon).
    pub registry: &'a Registry,
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
}

impl<'a> Ctx<'a> {
    /// Build a context with config-derived defaults.
    #[must_use]
    pub fn new(registry: &'a Registry, cfg: &'a cups_config::Config, port: u16) -> Self {
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
            sharing: cfg.cupsd.browsing && cfg.cupsd.browse_local_protocols.0 != 0,
            operations_supported: ops,
            strict: cfg.cupsd.strict_conformance,
            queued_job_count: 0,
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
        x if x == u32::from(op::CUPS_GET_DEVICES) || x == u32::from(op::CUPS_GET_PPDS) => {
            // P3/P7 dependencies (cups-deviced, PPD index).
            send_status(
                resp,
                status::ERROR_OPERATION_NOT_SUPPORTED,
                format!(
                    "{} not supported.",
                    ipp_codec::ops::op::name(u16::try_from(x).unwrap_or(0))
                ),
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
    let Some((p, _is_class)) = ctx.registry.validate_dest(&uri) else {
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
    if ctx.registry.validate_dest(&uri).is_none() {
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
    let Some(p) = ctx.registry.default_printer() else {
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
    if ctx.registry.printers.is_empty() {
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
    let mut iter: Vec<&Printer> = ctx.registry.printers.values().collect();
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
        if i64::from(p.effective_ptype(ctx.registry.default.as_deref() == Some(p.name.as_str())))
            & pt_mask
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
    let Some((p, _)) = ctx.registry.validate_dest(&uri) else {
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
    if ctx.registry.validate_dest(&uri).is_none() {
        send_status(
            resp,
            status::ERROR_NOT_FOUND,
            "The printer or class does not exist.",
        );
        return;
    }
    let _ = req;
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
