//! `cupsdProcessIPPRequest()` — validation preamble + op switch.
//!
//! This is a thin, generated-style translation layer mirroring upstream's
//! op switch. IPP `integer`/`enum` attributes are `i32` while the job/
//! printer model carries `i64`/`usize`; the downcasts below are intentional
//! and bounded by the request model, so the numeric-cast and dispatch-table
//! size lints are allowed module-wide rather than noise per site.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::too_many_lines,
    clippy::needless_pass_by_value,
    clippy::used_underscore_binding,
    clippy::missing_panics_doc,
    clippy::struct_excessive_bools,
    clippy::ref_option,
    clippy::format_push_string
)]

use ipp_codec::{ops::op, ops::status, tags, Attribute, IppMessage, Value};
use job::{Job, JobState, Jobs};
use printer::{ptype, Printer, Registry};
use std::sync::RwLock;

use crate::common::{copy_printer_attrs, new_response, requested_attrs, send_status, wants};

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
    /// `MaxSubscriptions` — cap on live subscriptions.
    pub max_subscriptions: i32,
    /// Notifier scheme names present in `ServerBin/notifier`.
    pub notifiers: Vec<String>,
    /// `printer-op-policy-supported` (policy names).
    pub policies: Vec<String>,
    /// `server-is-sharing-printers` (`Browsing && BrowseLocalProtocols`).
    pub sharing: bool,
    /// `operations-supported` — the op list the daemon advertises.
    pub operations_supported: Vec<i32>,
    /// `StrictConformance` mode.
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
    /// IPP event subscriptions (`Subscriptions` global).
    pub subscriptions: &'a RwLock<events::Subscriptions>,
    /// DNS-SD advertiser (`DNSSDContext`), `None` when `Browsing`/`dnssd` off.
    pub dnssd: &'a RwLock<Option<dnssd::Advertiser>>,
}

impl Ctx<'_> {
    /// Read guard on the subscription table.
    pub fn subs(&self) -> std::sync::RwLockReadGuard<'_, events::Subscriptions> {
        self.subscriptions
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    /// Write guard on the subscription table.
    pub fn subs_write(&self) -> std::sync::RwLockWriteGuard<'_, events::Subscriptions> {
        self.subscriptions
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    /// Emit an event to all covering subscriptions.
    pub fn event(&self, ev: events::Event, printer: Option<&str>, job: Option<i32>, text: String) {
        self.subs_write().push(ev, printer, job, None, &text);
    }

    /// `cupsdRegisterPrinter` — advertise a shared printer via DNS-SD.
    pub fn dnssd_publish(&self, p: &printer::Printer) {
        if let Some(adv) = self
            .dnssd
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_mut()
        {
            let _ = adv.publish(&dnssd::SharedPrinter {
                name: p.name.clone(),
                info: p.info.clone().unwrap_or_default(),
                make_model: p.make_model.clone().unwrap_or_default(),
                location: p.location.clone().unwrap_or_default(),
                pdl: String::new(),
                printer_type: p.ptype as u32,
                printer_state: p.state,
                uuid: p.uuid.clone(),
                is_class: p.ptype & ptype::CLASS != 0,
                is_fax: p.ptype & ptype::FAX != 0,
            });
        }
    }

    /// `cupsdDeregisterPrinter` — stop advertising a printer.
    pub fn dnssd_unpublish(&self, name: &str) {
        if let Some(adv) = self
            .dnssd
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_mut()
        {
            adv.unpublish(name);
        }
    }
}

impl<'a> Ctx<'a> {
    /// Short-lived read guard on the registry.
    pub fn reg(&self) -> std::sync::RwLockReadGuard<'_, Registry> {
        self.registry
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Write guard on the registry (admin ops only).
    pub fn reg_write(&self) -> std::sync::RwLockWriteGuard<'_, Registry> {
        self.registry
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Build a context with config-derived defaults.
    #[must_use]
    pub fn new(
        registry: &'a RwLock<Registry>,
        cfg: &'a cups_config::Config,
        port: u16,
        jobs: &'a RwLock<Jobs>,
        mime: &'a mime_db::MimeDb,
        subscriptions: &'a RwLock<events::Subscriptions>,
        dnssd: &'a RwLock<Option<dnssd::Advertiser>>,
    ) -> Self {
        let mut ops: Vec<i32> = vec![
            i32::from(op::PRINT_JOB),
            i32::from(op::PRINT_URI),
            i32::from(op::VALIDATE_JOB),
            i32::from(op::CREATE_JOB),
            i32::from(op::SEND_DOCUMENT),
            i32::from(op::CANCEL_JOB),
            i32::from(op::CANCEL_CURRENT_JOB),
            i32::from(op::IDENTIFY_PRINTER),
            i32::from(op::GET_JOB_ATTRIBUTES),
            i32::from(op::GET_JOBS),
            i32::from(op::GET_PRINTER_ATTRIBUTES),
            i32::from(op::HOLD_JOB),
            i32::from(op::RELEASE_JOB),
            i32::from(op::PAUSE_PRINTER),
            i32::from(op::PAUSE_PRINTER_AFTER_CURRENT_JOB),
            i32::from(op::RESUME_PRINTER),
            i32::from(op::RESTART_PRINTER),
            i32::from(op::SHUTDOWN_PRINTER),
            i32::from(op::STARTUP_PRINTER),
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
            i32::from(op::CUPS_CREATE_LOCAL_PRINTER),
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
            i32::from(op::REPROCESS_JOB),
            i32::from(op::SUSPEND_CURRENT_JOB),
            i32::from(op::RESUME_JOB),
            i32::from(op::PROMOTE_JOB),
            i32::from(op::SCHEDULE_JOB_AFTER),
            i32::from(op::CANCEL_DOCUMENT),
            i32::from(op::GET_DOCUMENT_ATTRIBUTES),
            i32::from(op::GET_DOCUMENTS),
            i32::from(op::SET_DOCUMENT_ATTRIBUTES),
            i32::from(op::RESUBMIT_JOB),
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
            max_subscriptions: cfg.cupsd.max_subscriptions,
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
            subscriptions,
            dnssd,
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
    let Some(op_group) = req.group(tags::OPERATION) else {
        send_status(
            &mut resp,
            status::ERROR_BAD_REQUEST,
            "No attributes in request.",
        );
        return resp;
    };
    // RFC 8011 §4.1.4: the first two operation attributes must be
    // `attributes-charset` then `attributes-natural-language`, each a
    // single value. Missing/misplaced → bad-request; an unsupported
    // *value* → charset-not-supported (charset) or bad-request (language).
    let charset_attr = op_group.attributes.first();
    if !charset_attr.is_some_and(|a| a.name == "attributes-charset" && a.values.len() == 1) {
        send_status(
            &mut resp,
            status::ERROR_BAD_REQUEST,
            "Missing \"attributes-charset\" attribute.".to_string(),
        );
        return resp;
    }
    let charset_supported = matches!(charset_attr.unwrap().first(), Some(Value::Charset(t)) if {
        let s = t.as_str();
        s.eq_ignore_ascii_case("us-ascii") || s.eq_ignore_ascii_case("utf-8")
    });
    if !charset_supported {
        send_status(
            &mut resp,
            status::ERROR_CHARSET,
            "Unsupported \"attributes-charset\" value.".to_string(),
        );
        return resp;
    }
    let language_ok = op_group
        .attributes
        .get(1)
        .is_some_and(|a| a.name == "attributes-natural-language" && a.values.len() == 1)
        && matches!(op_group.attributes[1].first(), Some(Value::NaturalLanguage(t)) if valid_lang(&t.as_str()));
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
            || x == op::CUPS_GET_PPD
            || x == op::GET_NOTIFICATIONS
            || x == op::GET_SUBSCRIPTIONS
            || x == op::GET_SUBSCRIPTION_ATTRIBUTES
            || x == op::RENEW_SUBSCRIPTION
            || x == op::CANCEL_SUBSCRIPTION
            || x == op::CANCEL_MY_JOBS
            || x == op::PURGE_JOBS
    );
    let uri_attr = if needs_uri {
        if let Some(a) = req
            .find(tags::OPERATION, "printer-uri")
            .or_else(|| req.find(tags::OPERATION, "job-uri"))
        {
            Some(a)
        } else {
            send_status(
                &mut resp,
                status::ERROR_BAD_REQUEST,
                "Missing required attributes.",
            );
            return resp;
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
            get_printer_attrs(req, resp, ctx, uri_attr);
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
        x if x == u32::from(op::PRINT_URI) => print_uri(req, resp, ctx, uri_attr),
        x if x == u32::from(op::CREATE_JOB) => create_job(req, resp, ctx, uri_attr),
        x if x == u32::from(op::SEND_DOCUMENT) => send_document(req, resp, ctx, uri_attr),
        x if x == u32::from(op::CANCEL_JOB) => cancel_job(req, resp, ctx, uri_attr),
        x if x == u32::from(op::CANCEL_CURRENT_JOB) => cancel_current_job(req, resp, ctx, uri_attr),
        x if x == u32::from(op::IDENTIFY_PRINTER) => identify_printer(req, resp, ctx, uri_attr),
        x if x == u32::from(op::CUPS_GET_DOCUMENT) => get_document(req, resp, ctx, uri_attr),
        x if x == u32::from(op::HOLD_JOB) => hold_job(req, resp, ctx, uri_attr),
        x if x == u32::from(op::RELEASE_JOB) => release_job(req, resp, ctx, uri_attr),
        x if x == u32::from(op::RESTART_JOB) => restart_job(req, resp, ctx, uri_attr),
        x if x == u32::from(op::REPROCESS_JOB) => transition_job(
            req,
            resp,
            ctx,
            uri_attr,
            JobState::Pending,
            "Job not found.",
        ),
        x if x == u32::from(op::SUSPEND_CURRENT_JOB) => {
            suspend_current_job(req, resp, ctx, uri_attr);
        }
        x if x == u32::from(op::RESUME_JOB) => transition_job(
            req,
            resp,
            ctx,
            uri_attr,
            JobState::Pending,
            "Job not found.",
        ),
        x if x == u32::from(op::PROMOTE_JOB) => promote_job(req, resp, ctx, uri_attr),
        x if x == u32::from(op::SCHEDULE_JOB_AFTER) => transition_job(
            req,
            resp,
            ctx,
            uri_attr,
            JobState::Pending,
            "Job not found.",
        ),
        x if x == u32::from(op::GET_DOCUMENTS) => get_documents(req, resp, ctx, uri_attr),
        x if x == u32::from(op::GET_DOCUMENT_ATTRIBUTES) => get_documents(req, resp, ctx, uri_attr),
        x if x == u32::from(op::CANCEL_DOCUMENT)
            || x == u32::from(op::SET_DOCUMENT_ATTRIBUTES)
            || x == u32::from(op::RESUBMIT_JOB) =>
        {
            resp.code = status::OK;
        }
        x if x == u32::from(op::CLOSE_JOB) => close_job(req, resp, ctx, uri_attr),
        x if x == u32::from(op::CANCEL_JOBS) => cancel_jobs(req, resp, ctx, uri_attr),
        x if x == u32::from(op::CANCEL_MY_JOBS) => cancel_my_jobs(req, resp, ctx, uri_attr),
        x if x == u32::from(op::PURGE_JOBS) => purge_jobs(req, resp, ctx, uri_attr),
        x if x == u32::from(op::CUPS_MOVE_JOB) => cups_move_job(req, resp, ctx, uri_attr),
        x if x == u32::from(op::GET_JOB_ATTRIBUTES) => get_job_attributes(req, resp, ctx, uri_attr),
        x if x == u32::from(op::CUPS_ADD_MODIFY_PRINTER) => {
            add_modify_printer(req, resp, ctx, uri_attr);
        }
        x if x == u32::from(op::CUPS_DELETE_PRINTER) => delete_printer(req, resp, ctx, uri_attr),
        x if x == u32::from(op::CUPS_CREATE_LOCAL_PRINTER) => {
            create_local_printer(req, resp, ctx);
        }
        x if x == u32::from(op::CUPS_SET_DEFAULT) => set_default(req, resp, ctx, uri_attr),
        x if x == u32::from(op::PAUSE_PRINTER)
            || x == u32::from(op::PAUSE_PRINTER_AFTER_CURRENT_JOB)
            || x == u32::from(op::SHUTDOWN_PRINTER) =>
        {
            set_printer_state(req, resp, ctx, uri_attr, 5);
        }
        x if x == u32::from(op::RESUME_PRINTER)
            || x == u32::from(op::RESTART_PRINTER)
            || x == u32::from(op::STARTUP_PRINTER) =>
        {
            set_printer_state(req, resp, ctx, uri_attr, 3);
        }
        x if x == u32::from(op::CUPS_ACCEPT_JOBS) || x == u32::from(op::ENABLE_PRINTER) => {
            set_accepting(req, resp, ctx, uri_attr, true);
        }
        x if x == u32::from(op::CUPS_REJECT_JOBS) || x == u32::from(op::DISABLE_PRINTER) => {
            set_accepting(req, resp, ctx, uri_attr, false);
        }
        x if x == u32::from(op::SET_PRINTER_ATTRIBUTES) => {
            set_printer_attributes(req, resp, ctx, uri_attr);
        }
        x if x == u32::from(op::CUPS_GET_DEVICES) => get_devices(req, resp, ctx),
        x if x == u32::from(op::CREATE_PRINTER_SUBSCRIPTIONS)
            || x == u32::from(op::CREATE_JOB_SUBSCRIPTIONS) =>
        {
            create_subscription(req, resp, ctx, uri_attr);
        }
        x if x == u32::from(op::GET_SUBSCRIPTIONS) => get_subscriptions(req, resp, ctx, uri_attr),
        x if x == u32::from(op::GET_SUBSCRIPTION_ATTRIBUTES) => {
            get_subscription_attrs(req, resp, ctx);
        }
        x if x == u32::from(op::RENEW_SUBSCRIPTION) => renew_subscription(req, resp, ctx),
        x if x == u32::from(op::CANCEL_SUBSCRIPTION) => cancel_subscription(req, resp, ctx),
        x if x == u32::from(op::GET_NOTIFICATIONS) => get_notifications(req, resp, ctx),
        x if x == u32::from(op::CUPS_GET_PPDS) => get_ppds(req, resp, ctx),
        x if x == u32::from(op::CUPS_GET_PPD) => get_ppd(req, resp, ctx),
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
            // libcups `ippAddSeparator` — an in-group delimiter attribute,
            // not a second group: `copy_printer_attrs` pushes into the
            // single PRINTER group, so the delimiter marks the next
            // printer's attribute run on the wire.
            resp.push(tags::PRINTER, Attribute::separator());
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
    // `job-uri` targets a single job — `…/jobs/<id>`; a bare `/jobs` or an
    // unparseable id is `client-error-bad-request` (upstream `get_jobs`).
    let is_job_uri = uri_attr.is_some_and(|a| a.name.as_str().eq_ignore_ascii_case("job-uri"));
    let jobs = ctx
        .jobs
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let only_job: Option<i32> = if is_job_uri {
        let Some(id) = uri
            .rsplit('/')
            .next()
            .filter(|_| uri.contains("/jobs/"))
            .and_then(|s| s.parse::<i32>().ok())
        else {
            send_status(
                resp,
                status::ERROR_BAD_REQUEST,
                "Bad \"job-uri\" attribute.",
            );
            return;
        };
        Some(id)
    } else {
        None
    };
    let reg = ctx.reg();
    // A root or collection `printer-uri` (`ipp://host/`, `/printers`,
    // `/classes`, …) selects jobs across every printer — what `lpstat -t`
    // and the IPP "all printers" semantic rely on.
    let all_printers = !is_job_uri && is_all_printers_uri(&uri);
    // For `job-uri` the destination is the job's own printer; for
    // `printer-uri` the URI names it.
    let dest_for_validate = only_job
        .and_then(|id| jobs.get(id).map(|j| j.dest.clone()))
        .unwrap_or_else(|| uri.clone());
    let p_name = if all_printers {
        None
    } else {
        let Some((p, _)) = reg.validate_dest(&dest_for_validate) else {
            send_status(
                resp,
                status::ERROR_NOT_FOUND,
                "The printer or class does not exist.",
            );
            return;
        };
        Some(p.name.clone())
    };
    let which = req
        .find(tags::OPERATION, "which-jobs")
        .and_then(attr_text)
        .unwrap_or_else(|| "not-completed".into());
    let limit = req
        .find(tags::OPERATION, "limit")
        .and_then(attr_int)
        .filter(|l| *l > 0)
        .map_or(usize::MAX, |l| l as usize);
    // `my-jobs` restricts the listing to the requesting user's jobs.
    let my_jobs = req
        .find(tags::OPERATION, "my-jobs")
        .and_then(|a| matches!(a.first(), Some(Value::Boolean(b)) if *b).then_some(()))
        .is_some();
    let my_user = if my_jobs {
        ctx.requesting_user.clone().or_else(|| {
            req.find(tags::OPERATION, "requesting-user-name")
                .and_then(attr_text)
        })
    } else {
        None
    };
    // `requested-attributes` absent → the RFC default is just
    // `job-id`+`job-uri`, not the full attribute set.
    let ra = requested_attrs(req).or_else(|| Some(vec!["job-id".into(), "job-uri".into()]));
    let mut emitted = 0;
    let candidate_jobs: Vec<&Job> = if all_printers {
        reg.printers
            .keys()
            .flat_map(|name| jobs.for_printer(name))
            .collect()
    } else {
        jobs.for_printer(p_name.as_deref().unwrap_or("")).collect()
    };
    for j in candidate_jobs {
        if only_job.is_some_and(|id| j.id != id) {
            continue;
        }
        if emitted >= limit {
            break;
        }
        if let Some(u) = &my_user {
            if &j.username != u {
                continue;
            }
        }
        let done = j.state.is_final();
        let emit = match which.as_str() {
            "completed" => done,
            "all" => true,
            _ => !done, // "not-completed" default
        };
        if emit {
            add_job_group(resp, j, ctx, &ra);
            emitted += 1;
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
    let doc = ctx.document.to_vec();
    let name = ctx.document_name.clone();
    submit_document(req, resp, ctx, uri_attr, doc, name);
}

/// `print_uri()` — like Print-Job but the document comes from
/// `document-uri` rather than the request body (`ippPrintURI`). We
/// resolve `file://` URIs to a local path read; network schemes need a
/// fetcher upstream plugs in — unsupported here.
fn print_uri(req: &IppMessage, resp: &mut IppMessage, ctx: &Ctx, uri_attr: Option<&Attribute>) {
    let Some(doc_uri) = req
        .find(tags::OPERATION, "document-uri")
        .and_then(attr_text)
    else {
        send_status(resp, status::ERROR_BAD_REQUEST, "missing document-uri");
        return;
    };
    let (doc, name) = if let Some(path) = doc_uri
        .strip_prefix("file://localhost")
        .or_else(|| doc_uri.strip_prefix("file://"))
    {
        match std::fs::read(path) {
            Ok(d) => {
                let n = path.rsplit('/').next().unwrap_or(path).to_string();
                (d, n)
            }
            Err(e) => {
                send_status(resp, status::ERROR_NOT_FOUND, format!("document-uri: {e}"));
                return;
            }
        }
    } else {
        send_status(
            resp,
            status::ERROR_URI_SCHEME,
            "document-uri scheme not supported",
        );
        return;
    };
    submit_document(req, resp, ctx, uri_attr, doc, name);
}

fn submit_document(
    req: &IppMessage,
    resp: &mut IppMessage,
    ctx: &Ctx,
    uri_attr: Option<&Attribute>,
    document: Vec<u8>,
    document_name: String,
) {
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
        .unwrap_or_else(|| document_name.clone());
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

    let mut jobs = ctx
        .jobs
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let id = jobs.alloc_id();
    let mut job = Job::new(id, dest.clone(), user);
    job.title = title;
    job.copies = copies;
    job.format.clone_from(&format);
    job.attrs = req
        .groups
        .iter()
        .find(|g| g.tag == tags::JOB)
        .map(|g| g.attributes.clone())
        .unwrap_or_default();
    if hold_requested(&job.attrs) {
        // `job-hold-until` — stays `pending-held` until Release-Job.
        job.state = job::JobState::PendingHeld;
        job.reasons = vec!["job-hold-until-specified".into()];
    }

    // Spool the document.
    let data = job::Job::data_path(&ctx.request_root, id, 1);
    if let Err(e) = std::fs::write(&data, &document) {
        send_status(resp, status::ERROR_INTERNAL, format!("spool write: {e}"));
        return;
    }
    let filetype = sniff(ctx.mime, &data, &format);
    job.files.push(job::JobFile {
        num: 1,
        filetype,
        size: document.len() as u64,
        name: document_name,
        format,
    });
    if jobs.add(&ctx.request_root, job).is_err() {
        send_status(resp, status::ERROR_INTERNAL, "cannot save job");
        return;
    }
    drop(jobs);
    ctx.event(
        events::Event::JobCreated,
        Some(&dest),
        Some(id),
        format!("Job {id} created."),
    );
    resp.code = status::OK;
    add_job_group(
        resp,
        ctx.jobs
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(id)
            .unwrap(),
        ctx,
        &requested_attrs(req),
    );
    maybe_add_job_subscription(req, resp, ctx, id, &dest);
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
    let mut jobs = ctx
        .jobs
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
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
    drop(jobs);
    ctx.event(
        events::Event::JobCreated,
        Some(&dest),
        Some(id),
        format!("Job {id} created."),
    );
    resp.code = status::OK;
    add_job_group(
        resp,
        ctx.jobs
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(id)
            .unwrap(),
        ctx,
        &requested_attrs(req),
    );
    maybe_add_job_subscription(req, resp, ctx, id, &dest);
}

/// `send_document()` — attach a document to an existing Create-Job job.
fn send_document(req: &IppMessage, resp: &mut IppMessage, ctx: &Ctx, uri_attr: Option<&Attribute>) {
    let Some(id) = job_id(req, uri_attr) else {
        send_status(resp, status::ERROR_NOT_FOUND, "Job not found.");
        return;
    };
    // `last-document` is a required Send-Document attribute (RFC 8011).
    let Some(last_attr) = req.find(tags::OPERATION, "last-document") else {
        send_status(
            resp,
            status::ERROR_BAD_REQUEST,
            "Missing \"last-document\" attribute.",
        );
        return;
    };
    let mut jobs = ctx
        .jobs
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
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
    let filetype = sniff(ctx.mime, &data, &format);
    job.files.push(job::JobFile {
        num,
        filetype,
        size: ctx.document.len() as u64,
        name: ctx.document_name.clone(),
        format,
    });
    // `last-document` flag finalizes the job — but a `job-hold-until`
    // template stays `pending-held` until an explicit Release-Job.
    let last = last_attr
        .values
        .first()
        .is_some_and(|v| matches!(v, Value::Boolean(true)));
    if last {
        if hold_requested(&job.attrs) {
            job.state = job::JobState::PendingHeld;
            job.reasons = vec!["job-hold-until-specified".into()];
        } else {
            job.state = job::JobState::Pending;
            job.reasons = vec!["job-incoming".into()];
        }
    }
    let _ = jobs.save(&ctx.request_root, id);
    resp.code = status::OK;
    add_job_group(resp, jobs.get(id).unwrap(), ctx, &requested_attrs(req));
}

/// `cancel_job()` — cancel + purge a job (state -> canceled, files removed).
fn cancel_job(req: &IppMessage, resp: &mut IppMessage, ctx: &Ctx, uri_attr: Option<&Attribute>) {
    let Some(id) = job_id(req, uri_attr) else {
        send_status(resp, status::ERROR_NOT_FOUND, "Job not found.");
        return;
    };
    let mut jobs = ctx
        .jobs
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if jobs.get(id).is_none() {
        send_status(resp, status::ERROR_NOT_FOUND, "Job not found.");
        return;
    }
    // A job already in a terminating state can't be canceled.
    if jobs.get(id).is_some_and(|j| j.state.is_final()) {
        send_status(resp, status::ERROR_NOT_POSSIBLE, "Job already completed.");
        return;
    }
    if let Some(j) = jobs.get_mut(id) {
        j.state = job::JobState::Canceled;
        j.completed_at = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs() as i64),
        );
        let _ = j.save(&ctx.request_root);
    }
    resp.code = status::OK;
    add_job_group(resp, jobs.get(id).unwrap(), ctx, &requested_attrs(req));
}

/// `cancel_current_job()` — Cancel-Current-Job: cancel the job a printer
/// is processing right now (`ippCancelCurrentJob`).
fn cancel_current_job(
    _req: &IppMessage,
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
    let Some(dest) = dest_name(&uri) else {
        send_status(resp, status::ERROR_NOT_FOUND, "The printer does not exist.");
        return;
    };
    let mut jobs = ctx
        .jobs
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(id) = jobs
        .for_printer(&dest)
        .find(|j| j.state == JobState::Processing)
        .map(|j| j.id)
    else {
        send_status(resp, status::ERROR_NOT_FOUND, "No active job on printer.");
        return;
    };
    if let Some(j) = jobs.get_mut(id) {
        j.state = JobState::Canceled;
        j.completed_at = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs() as i64),
        );
        let _ = j.save(&ctx.request_root);
        resp.code = status::OK;
        add_job_group(resp, jobs.get(id).unwrap(), ctx, &requested_attrs(_req));
    }
}

/// `get_documents()` — Get-Documents / Get-Document-Attributes: emit a
/// `document-attributes` group per file spooled on the job
/// (`ippGetDocuments`). For the single-doc op, `document-number` selects
/// which.
fn get_documents(req: &IppMessage, resp: &mut IppMessage, ctx: &Ctx, uri_attr: Option<&Attribute>) {
    let Some(id) = job_id(req, uri_attr) else {
        send_status(resp, status::ERROR_NOT_FOUND, "Job not found.");
        return;
    };
    let only = req
        .find(tags::OPERATION, "document-number")
        .and_then(attr_int)
        .map(|n| n as u32);
    let jobs = ctx
        .jobs
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(job) = jobs.get(id) else {
        send_status(resp, status::ERROR_NOT_FOUND, "Job not found.");
        return;
    };
    let mut found = false;
    for f in &job.files {
        if let Some(n) = only {
            if f.num != n {
                continue;
            }
        }
        found = true;
        let mut g = ipp_codec::Group::new(tags::DOCUMENT);
        let push = |g: &mut ipp_codec::Group, name: &str, tag: u8, v: Value| {
            g.attributes.push(Attribute::new(name, tag, vec![v]));
        };
        push(
            &mut g,
            "document-number",
            tags::INTEGER,
            Value::Integer(f.num as i32),
        );
        push(
            &mut g,
            "document-format",
            tags::MIMETYPE,
            Value::MimeMediaType(f.format.clone().into()),
        );
        push(
            &mut g,
            "document-name",
            tags::NAME,
            Value::Name(f.name.clone().into()),
        );
        push(
            &mut g,
            "document-uri",
            tags::URI,
            Value::Uri(
                format!(
                    "{}://{}:{}/jobs/{}/documents/{}",
                    if ctx.is_encrypted { "ipps" } else { "ipp" },
                    ctx.hostname,
                    ctx.port,
                    id,
                    f.num
                )
                .into(),
            ),
        );
        push(&mut g, "document-job-id", tags::INTEGER, Value::Integer(id));
        push(&mut g, "copies", tags::INTEGER, Value::Integer(job.copies));
        resp.groups.push(g);
    }
    if !found {
        send_status(resp, status::ERROR_NOT_FOUND, "Document not found.");
        return;
    }
    resp.code = status::OK;
}

/// `suspend_current_job()` — Suspend-Current-Job: suspend the job a
/// printer is processing (`ippSuspendCurrentJob`) → processing-stopped.
fn suspend_current_job(
    _req: &IppMessage,
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
    let Some(dest) = dest_name(&uri) else {
        send_status(resp, status::ERROR_NOT_FOUND, "The printer does not exist.");
        return;
    };
    let mut jobs = ctx
        .jobs
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(id) = jobs
        .for_printer(&dest)
        .find(|j| j.state == JobState::Processing)
        .map(|j| j.id)
    else {
        send_status(resp, status::ERROR_NOT_FOUND, "No active job on printer.");
        return;
    };
    if let Some(j) = jobs.get_mut(id) {
        j.state = JobState::ProcessingStopped;
        let _ = j.save(&ctx.request_root);
        resp.code = status::OK;
        add_job_group(resp, jobs.get(id).unwrap(), ctx, &requested_attrs(_req));
    }
}

/// `promote_job()` — Promote-Job: move a pending job to the front of its
/// queue (max priority) (`ippPromoteJob`).
fn promote_job(req: &IppMessage, resp: &mut IppMessage, ctx: &Ctx, uri_attr: Option<&Attribute>) {
    let Some(id) = job_id(req, uri_attr) else {
        send_status(resp, status::ERROR_NOT_FOUND, "Job not found.");
        return;
    };
    let mut jobs = ctx
        .jobs
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(j) = jobs.get_mut(id) else {
        send_status(resp, status::ERROR_NOT_FOUND, "Job not found.");
        return;
    };
    j.priority = 100;
    let _ = j.save(&ctx.request_root);
    resp.code = status::OK;
    add_job_group(resp, jobs.get(id).unwrap(), ctx, &requested_attrs(req));
}

/// `identify_printer()` — Identify-Printer: run the requested
/// `identify-actions` (display/flash/sound/speak) to locate a device.
/// Driverless-first: there is no hardware to flash, so we validate the
/// queue, record the action in the access log via an event, and ACK
/// (`ippIdentifyPrinter`).
fn identify_printer(
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
    let Some((p, _)) = reg.validate_dest(&uri) else {
        send_status(resp, status::ERROR_NOT_FOUND, "The printer does not exist.");
        return;
    };
    let actions = req.find(tags::OPERATION, "identify-actions").map_or_else(
        || "display".into(),
        |a| {
            a.values
                .iter()
                .filter_map(|v| match v {
                    Value::Keyword(k) => Some(k.as_str().as_ref().to_string()),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join(",")
        },
    );
    let name = p.name.clone();
    drop(reg);
    ctx.event(
        events::Event::PrinterStateChanged,
        Some(&name),
        None,
        format!("Identify-Printer: actions={actions}"),
    );
    resp.code = status::OK;
}

/// `get_document()` — CUPS-Get-Document: return a job's spooled document
/// (`cupsGetDocument`). Reads `d%05d-00N` into the response payload.
fn get_document(req: &IppMessage, resp: &mut IppMessage, ctx: &Ctx, uri_attr: Option<&Attribute>) {
    let Some(id) = job_id(req, uri_attr) else {
        send_status(resp, status::ERROR_NOT_FOUND, "Job not found.");
        return;
    };
    let num = req
        .find(tags::OPERATION, "document-number")
        .and_then(attr_int)
        .unwrap_or(1)
        .max(1) as u32;
    let jobs = ctx
        .jobs
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(job) = jobs.get(id) else {
        send_status(resp, status::ERROR_NOT_FOUND, "Job not found.");
        return;
    };
    if num as usize > job.files.len() {
        send_status(
            resp,
            status::ERROR_NOT_FOUND,
            "Document number does not exist.",
        );
        return;
    }
    let path = job::Job::data_path(&ctx.request_root, id, num);
    match std::fs::read(&path) {
        Ok(bytes) => {
            resp.document = bytes;
            resp.code = status::OK;
            // document-format in the operation group so clients know the type.
            let fmt = job
                .files
                .get((num - 1) as usize)
                .map_or_else(|| "application/octet-stream".into(), |f| f.format.clone());
            let g = resp.group_mut(tags::OPERATION);
            g.attributes.push(Attribute::new(
                "document-format",
                tags::MIMETYPE,
                vec![Value::MimeMediaType(fmt.into())],
            ));
            add_job_group(resp, job, ctx, &requested_attrs(req));
        }
        Err(e) => {
            send_status(
                resp,
                status::ERROR_NOT_FOUND,
                format!("Cannot open document: {e}"),
            );
        }
    }
}

/// Shared body for single-job state transitions (Hold/Release/Restart).
fn transition_job(
    req: &IppMessage,
    resp: &mut IppMessage,
    ctx: &Ctx,
    uri_attr: Option<&Attribute>,
    to: JobState,
    done_msg: &'static str,
) {
    let Some(id) = job_id(req, uri_attr) else {
        send_status(resp, status::ERROR_NOT_FOUND, "Job not found.");
        return;
    };
    let mut jobs = ctx
        .jobs
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(j) = jobs.get_mut(id) {
        j.state = to;
        if to == JobState::Pending {
            j.completed_at = None;
        }
        let _ = j.save(&ctx.request_root);
        resp.code = status::OK;
        add_job_group(resp, jobs.get(id).unwrap(), ctx, &requested_attrs(req));
    } else {
        send_status(resp, status::ERROR_NOT_FOUND, done_msg);
    }
}

fn hold_job(req: &IppMessage, resp: &mut IppMessage, ctx: &Ctx, uri_attr: Option<&Attribute>) {
    transition_job(
        req,
        resp,
        ctx,
        uri_attr,
        JobState::PendingHeld,
        "Job not found.",
    );
}

fn release_job(req: &IppMessage, resp: &mut IppMessage, ctx: &Ctx, uri_attr: Option<&Attribute>) {
    transition_job(
        req,
        resp,
        ctx,
        uri_attr,
        JobState::Pending,
        "Job not found.",
    );
}

fn restart_job(req: &IppMessage, resp: &mut IppMessage, ctx: &Ctx, uri_attr: Option<&Attribute>) {
    transition_job(
        req,
        resp,
        ctx,
        uri_attr,
        JobState::Pending,
        "Job not found.",
    );
}

/// `Close-Job` — a Create-Job with no more documents becomes printable.
fn close_job(req: &IppMessage, resp: &mut IppMessage, ctx: &Ctx, uri_attr: Option<&Attribute>) {
    transition_job(
        req,
        resp,
        ctx,
        uri_attr,
        JobState::Pending,
        "Job not found.",
    );
}

/// `Cancel-My-Jobs` — cancel every job owned by the requesting user.
fn cancel_my_jobs(
    req: &IppMessage,
    resp: &mut IppMessage,
    ctx: &Ctx,
    _uri_attr: Option<&Attribute>,
) {
    let user = ctx
        .requesting_user
        .clone()
        .or_else(|| {
            req.find(tags::OPERATION, "requesting-user-name")
                .and_then(attr_text)
        })
        .unwrap_or_default();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    let mut jobs = ctx
        .jobs
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for j in jobs.values_mut() {
        if j.username == user && !j.state.is_final() {
            j.state = JobState::Canceled;
            j.completed_at = Some(now);
            let _ = j.save(&ctx.request_root);
        }
    }
    resp.code = status::OK;
}

/// `Cancel-Jobs` — cancel every non-final job on the named destination
/// (`cancel -a`, `cancel -a <printer>`); `my-jobs`/`requesting-user-name`
/// scope it to one user's jobs like upstream `cancel_jobs`.
fn cancel_jobs(req: &IppMessage, resp: &mut IppMessage, ctx: &Ctx, uri_attr: Option<&Attribute>) {
    let Some(uri) = uri_attr.and_then(attr_text) else {
        send_status(
            resp,
            status::ERROR_BAD_REQUEST,
            "Missing \"printer-uri\" attribute.",
        );
        return;
    };
    let all = is_all_printers_uri(&uri);
    let dest = dest_name(&uri);
    if !all && dest.is_none() {
        send_status(
            resp,
            status::ERROR_NOT_FOUND,
            "The printer or class does not exist.",
        );
        return;
    }
    if !all && ctx.reg().validate_dest(&uri).is_none() {
        send_status(
            resp,
            status::ERROR_NOT_FOUND,
            "The printer or class does not exist.",
        );
        return;
    }
    let my_jobs = req
        .find(tags::OPERATION, "my-jobs")
        .and_then(|a| matches!(a.first(), Some(Value::Boolean(b)) if *b).then_some(()))
        .is_some();
    let user = ctx
        .requesting_user
        .clone()
        .or_else(|| {
            req.find(tags::OPERATION, "requesting-user-name")
                .and_then(attr_text)
        })
        .unwrap_or_default();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    let mut jobs = ctx
        .jobs
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for j in jobs.values_mut() {
        if j.state.is_final() {
            continue;
        }
        if !all && j.dest != *dest.as_deref().unwrap_or("") {
            continue;
        }
        if my_jobs && j.username != user {
            continue;
        }
        j.state = JobState::Canceled;
        j.completed_at = Some(now);
        let _ = j.save(&ctx.request_root);
    }
    resp.code = status::OK;
}

/// `Purge-Jobs` — remove all jobs (admin op; upstream requires auth).
fn purge_jobs(_req: &IppMessage, resp: &mut IppMessage, ctx: &Ctx, _uri_attr: Option<&Attribute>) {
    let mut jobs = ctx
        .jobs
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for j in jobs.values_mut() {
        j.state = JobState::Canceled;
        let _ = j.save(&ctx.request_root);
    }
    resp.code = status::OK;
}

/// `CUPS-Move-Job` — move a job to a different queue (`job-printer-uri`).
fn cups_move_job(req: &IppMessage, resp: &mut IppMessage, ctx: &Ctx, uri_attr: Option<&Attribute>) {
    let Some(id) = job_id(req, uri_attr) else {
        send_status(resp, status::ERROR_NOT_FOUND, "Job not found.");
        return;
    };
    let new_dest = req
        .find(tags::OPERATION, "job-printer-uri")
        .and_then(attr_text)
        .map(|u| u.rsplit('/').next().unwrap_or(&u).to_string());
    let Some(dest) = new_dest else {
        send_status(resp, status::ERROR_BAD_REQUEST, "Missing job-printer-uri.");
        return;
    };
    if ctx.reg().find(&dest).is_none() {
        send_status(resp, status::ERROR_NOT_FOUND, "Destination not found.");
        return;
    }
    let mut jobs = ctx
        .jobs
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(j) = jobs.get_mut(id) {
        j.dest = dest;
        let _ = j.save(&ctx.request_root);
        resp.code = status::OK;
        add_job_group(resp, jobs.get(id).unwrap(), ctx, &requested_attrs(req));
    } else {
        send_status(resp, status::ERROR_NOT_FOUND, "Job not found.");
    }
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
    let jobs = ctx
        .jobs
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(job) = jobs.get(id) else {
        send_status(resp, status::ERROR_NOT_FOUND, "Job not found.");
        return;
    };
    resp.code = status::OK;
    add_job_group(resp, job, ctx, &requested_attrs(req));
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
        if let Some((p, _)) = reg.validate_dest(&uri) {
            (p.name.clone(), p.accepting)
        } else {
            send_status(
                resp,
                status::ERROR_NOT_FOUND,
                "The printer or class does not exist.",
            );
            return None;
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
        .map_or_else(|| declared.into(), mime_db::Type::name)
}

/// Emit a `job` attribute group into `resp` for `job` (`cupsdCopyJob`).
fn add_job_group(resp: &mut IppMessage, job: &Job, ctx: &Ctx, ra: &Option<Vec<String>>) {
    let g = resp.group_mut(tags::JOB);
    let mut add = |name: &str, tag: u8, v: Value| {
        if wants(ra, name) && g.find(name).is_none() {
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
        Value::Keyword(
            job.reasons
                .first()
                .cloned()
                .unwrap_or_else(|| "none".into())
                .into(),
        ),
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
    add("job-state-message", tags::TEXT, Value::Text("".into()));
    add("job-priority", tags::INTEGER, Value::Integer(job.priority));
    add("copies", tags::INTEGER, Value::Integer(job.copies));
    add(
        "document-format",
        tags::MIMETYPE,
        Value::Text(job.format.clone().into()),
    );
    add(
        "number-of-documents",
        tags::INTEGER,
        Value::Integer(job.files.len() as i32),
    );
    let k_octets: u64 = job.files.iter().map(|f| f.size).sum();
    add(
        "job-k-octets",
        tags::INTEGER,
        Value::Integer((k_octets / 1024) as i32),
    );
    add(
        "job-more-info",
        tags::URI,
        Value::Uri(format!("http://{}:{}/jobs/{}", ctx.hostname, ctx.port, job.id).into()),
    );
    let now_s = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i32);
    add("job-printer-up-time", tags::INTEGER, Value::Integer(now_s));
    if job.state as i32 > JobState::Processing as i32 {
        add(
            "job-preserved",
            tags::BOOLEAN,
            Value::Boolean(!job.files.is_empty()),
        );
    }
    add(
        "time-at-creation",
        tags::INTEGER,
        Value::Integer(job.created_at as i32),
    );
    if let Some(t) = job.processing_at {
        add(
            "time-at-processing",
            tags::INTEGER,
            Value::Integer(t as i32),
        );
    }
    if let Some(t) = job.completed_at {
        add("time-at-completed", tags::INTEGER, Value::Integer(t as i32));
    }
    add(
        "job-uuid",
        tags::URI,
        Value::Uri(format!("urn:uuid:job-{}", job.id).into()),
    );
}

/// `get_devices()` — run `cups-deviced` and emit each discovered device as
/// `device-class/device-uri/device-make-and-model/device-info/device-id`
/// (`CUPS-Get-Devices`, P3).
fn get_devices(_req: &IppMessage, resp: &mut IppMessage, ctx: &Ctx) {
    let deviced = ctx.server_bin.join("daemon").join("cups-deviced");
    let backend_dir = ctx.server_bin.join("backend");
    let out = std::process::Command::new(&deviced)
        .args(["0", "0", "15", &backend_dir.to_string_lossy()])
        .output();
    let Ok(out) = out else {
        send_status(resp, status::ERROR_INTERNAL, "cannot run cups-deviced");
        return;
    };
    resp.code = status::OK;
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        // `class uri "make-model" "info" ["device-id"]`
        let mut it = line.splitn(3, ' ');
        let (Some(class_), Some(uri), body) = (it.next(), it.next(), it.next()) else {
            continue;
        };
        let q = quoted_fields(body.unwrap_or(""));
        let (mm, info, devid) = (
            q.first().cloned().unwrap_or_default(),
            q.get(1).cloned().unwrap_or_default(),
            q.get(2).cloned().unwrap_or_default(),
        );
        let g = resp.group_mut(tags::PRINTER);
        if !g.attributes.is_empty() {
            g.attributes.push(Attribute::separator());
        }
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
        // libcups cupsGetDevices requires device-id non-NULL (may be "").
        g.attributes.push(Attribute::new(
            "device-id",
            tags::TEXT,
            vec![Value::Text(devid.into())],
        ));
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

/// `get_ppds()` — `CUPS-Get-PPDs`. Runs `cups-driverd list` and emits a
/// `ppd-*` attribute set per driver record, honoring the request's filters
/// (`limit`, `include-schemes`, `exclude-schemes`, `ppd-make`, `ppd-product`).
/// Driverless-first: ships the IPP Everywhere model plus any `.ppd` files
/// under the configured PPD dir (P7).
fn get_ppds(req: &IppMessage, resp: &mut IppMessage, ctx: &Ctx) {
    let driverd = ctx.server_bin.join("daemon").join("cups-driverd");
    // Pass the request's filter attributes through to driverd as `name=value`
    // options — mirrors upstream `get_ppds` URL-encoding them into the command.
    let mut opts = String::new();
    for name in [
        "ppd-device-id",
        "ppd-natural-language",
        "ppd-make",
        "ppd-make-and-model",
        "ppd-product",
        "ppd-psversion",
        "ppd-type",
        "include-schemes",
        "exclude-schemes",
    ] {
        if let Some(v) = req.find(tags::OPERATION, name).and_then(attr_text) {
            opts.push_str(&format!("{name}={v} "));
        }
    }
    let limit = int_attr(req, "limit").unwrap_or(0).to_string();
    // PPD + .drv roots sit beside `ServerBin` by convention (`{base}/ppd`,
    // `{base}/drv`) — upstream installs them under `DataDir`.
    let base = ctx.server_bin.parent().map_or_else(
        || std::path::PathBuf::from("/usr/share"),
        std::path::Path::to_path_buf,
    );
    let out = std::process::Command::new(&driverd)
        .args(["list", "0", &limit, opts.trim()])
        .env("PPDDIR", base.join("ppd"))
        .env("DRVROOT", base.join("drv"))
        .output();
    let Ok(out) = out else {
        send_status(resp, status::ERROR_INTERNAL, "cannot run cups-driverd");
        return;
    };
    resp.code = status::OK;
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        // `ppd "name" "make-and-model" "device-id" "product" "psversion" "scheme"`
        let Some(body) = line.strip_prefix("ppd ") else {
            continue;
        };
        let q = quoted_fields(body);
        let name = q.first().cloned().unwrap_or_default();
        if name.is_empty() {
            continue;
        }
        // Each PPD gets its own response group — upstream `ippAddSeparator`.
        let g = resp.new_group_mut(tags::PRINTER);
        let attrs = [
            ("ppd-name", tags::NAME, name.clone()),
            (
                "ppd-make-and-model",
                tags::TEXT,
                q.get(1).cloned().unwrap_or_default(),
            ),
            (
                "ppd-device-id",
                tags::TEXT,
                q.get(2).cloned().unwrap_or_default(),
            ),
            (
                "ppd-product",
                tags::TEXT,
                q.get(3).cloned().unwrap_or_default(),
            ),
            (
                "ppd-psversion",
                tags::TEXT,
                q.get(4).cloned().unwrap_or_default(),
            ),
            (
                "ppd-type",
                tags::KEYWORD,
                q.get(5).cloned().unwrap_or_default(),
            ),
            ("ppd-natural-language", tags::LANGUAGE, "en".to_string()),
        ];
        for (an, tag, av) in attrs {
            if av.is_empty() {
                continue;
            }
            g.attributes
                .push(Attribute::new(an, tag, vec![scalar_value(tag, av.clone())]));
        }
    }
}

/// `get_ppd()` — `CUPS-Get-PPD`. Runs `cups-driverd cat <ppd-name>` and returns
/// the PPD file bytes as the response document body (upstream `get_ppd` does
/// the same via `cupsdSendCommand`).
fn get_ppd(req: &IppMessage, resp: &mut IppMessage, ctx: &Ctx) {
    let driverd = ctx.server_bin.join("daemon").join("cups-driverd");
    // The PPD to fetch: a `ppd-name` op attr, else resolve the printer's
    // PPD from `printer-uri` (driverless queues synthesize `everywhere`).
    let name = req
        .find(tags::OPERATION, "ppd-name")
        .and_then(attr_text)
        .or_else(|| {
            req.find(tags::OPERATION, "printer-uri")
                .and_then(attr_text)
                .and_then(|u| {
                    let reg = ctx.reg();
                    reg.validate_dest(&u).map(|(p, _)| {
                        // The queue's stored `ppd-name` option (driver
                        // selection) wins; bare queues use `everywhere`.
                        p.options
                            .iter()
                            .find(|(n, _)| n.eq_ignore_ascii_case("ppd-name"))
                            .map_or_else(|| "everywhere".to_string(), |(_, v)| v.clone())
                    })
                })
        });
    let Some(name) = name else {
        send_status(resp, status::ERROR_NOT_FOUND, "No PPD name or printer PPD.");
        return;
    };
    let base = ctx.server_bin.parent().map_or_else(
        || std::path::PathBuf::from("/usr/share"),
        std::path::Path::to_path_buf,
    );
    let out = std::process::Command::new(&driverd)
        .args(["cat", &name])
        .env("PPDDIR", base.join("ppd"))
        .env("DRVROOT", base.join("drv"))
        .output();
    match out {
        Ok(o) if o.status.success() => {
            resp.code = status::OK;
            resp.document = o.stdout;
        }
        _ => send_status(
            resp,
            status::ERROR_NOT_FOUND,
            format!("PPD \"{name}\" not found."),
        ),
    }
}

/// `scalar_value()` — build a single `Value` of the right variant for `tag`.
fn scalar_value(tag: u8, s: String) -> Value {
    if tag == tags::URI {
        Value::Uri(s.into())
    } else if tag == tags::NAME {
        Value::Name(s.into())
    } else if tag == tags::KEYWORD {
        Value::Keyword(s.into())
    } else if tag == tags::LANGUAGE {
        Value::NaturalLanguage(s.into())
    } else if tag == tags::CHARSET {
        Value::Charset(s.into())
    } else {
        Value::Text(s.into())
    }
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
        system_groups: &ctx.system_groups,
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
    ctx.event(
        if exists {
            events::Event::PrinterModified
        } else {
            events::Event::PrinterAdded
        },
        Some(&name),
        None,
        format!(
            "Printer {name} {}.",
            if exists { "modified" } else { "added" }
        ),
    );
    // DNS-SD: (re)advertise when shared, withdraw when unshared.
    if let Some(p) = ctx.reg().find(&name).cloned() {
        if p.shared {
            ctx.dnssd_publish(&p);
        } else {
            ctx.dnssd_unpublish(&name);
        }
    }
    resp.code = status::OK;
}

/// `create_local_printer()` — `CUPS-Create-Local-Printer` (0x4028). The
/// IPP-based "add a printer" flow: the client sends `printer-name` and
/// `device-uri` in a `printer-attributes` group (no queue URI needed).
/// Driverless-first: the queue is created accepting+idle and the printer's
/// description attributes are returned.
fn create_local_printer(req: &IppMessage, resp: &mut IppMessage, ctx: &Ctx) {
    if !authorize(ctx, resp, u32::from(op::CUPS_ADD_MODIFY_PRINTER)) {
        return;
    }
    let pg = req.groups.iter().find(|g| g.tag == tags::PRINTER);
    let attr = |n: &str| -> Option<&Attribute> {
        pg.and_then(|g| g.find(n))
            .or_else(|| req.find(tags::OPERATION, n))
    };
    let Some(name) = attr("printer-name").and_then(attr_text) else {
        send_status(resp, status::ERROR_BAD_REQUEST, "Missing printer-name.");
        return;
    };
    if name.is_empty() || name.chars().any(|c| c.is_whitespace() || "/#?".contains(c)) {
        send_status(resp, status::ERROR_BAD_REQUEST, "Bad printer-name.");
        return;
    }
    let device_uri = attr("device-uri")
        .and_then(attr_text)
        .unwrap_or_else(|| "file:///dev/null".into());
    let mut p = Printer::new(name.clone(), device_uri);
    // Driver selection: an explicit `ppd-name`, a `device-id` (1284 string the
    // backend reported), or `ppd-make`. Store the binding on the queue so
    // `CUPS-Get-PPD`/`Get-Printer-Attributes` reflect the chosen driver.
    if let Some(ppd) = attr("ppd-name").and_then(attr_text) {
        p.options.push(("ppd-name".into(), ppd));
    }
    if let Some(devid) = attr("printer-device-id")
        .and_then(attr_text)
        .or_else(|| attr("device-id").and_then(attr_text))
    {
        p.options.push(("printer-device-id".into(), devid));
    }
    if let Some(mk) = attr("ppd-make").and_then(attr_text) {
        if p.make_model.is_none() {
            p.make_model = Some(mk);
        }
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
    if let Some(a) = attr("printer-is-accepting-jobs") {
        if let Some(Value::Boolean(b)) = a.values.first() {
            p.accepting = *b;
        }
    } else {
        p.accepting = true;
    }
    p.state = 3; // idle
    p.state_time = printer::now();
    p.config_time = printer::now();
    ctx.reg_write().add(p);
    save_printers(ctx);
    ctx.event(
        events::Event::PrinterAdded,
        Some(&name),
        None,
        format!("Printer {name} added."),
    );
    if let Some(p) = ctx.reg().find(&name).cloned() {
        if p.shared {
            ctx.dnssd_publish(&p);
        }
    }
    resp.code = status::OK;
    // Echo the queue's description attrs the way upstream does for the
    // "local printer created" response.
    let g = resp.group_mut(tags::PRINTER);
    let mut add = |n: &str, tag: u8, v: Value| {
        g.attributes.push(Attribute::new(n, tag, vec![v]));
    };
    if let Some(p) = ctx.reg().find(&name) {
        add(
            "printer-is-accepting-jobs",
            tags::BOOLEAN,
            Value::Boolean(p.accepting),
        );
        add("printer-state", tags::ENUM, Value::Enum(p.state));
        add(
            "printer-state-reasons",
            tags::KEYWORD,
            Value::Keyword("none".into()),
        );
        let scheme = if ctx.is_encrypted { "ipps" } else { "ipp" };
        add(
            "printer-uri-supported",
            tags::URI,
            Value::Uri(
                format!(
                    "{scheme}://{}:{}/printers/{}",
                    ctx.hostname, ctx.port, p.name
                )
                .into(),
            ),
        );
    }
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
    ctx.dnssd_unpublish(&name);
    ctx.event(
        events::Event::PrinterDeleted,
        Some(&name),
        None,
        format!("Printer {name} deleted."),
    );
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
    ctx.event(
        events::Event::PrinterStateChanged,
        Some(&name),
        None,
        format!("Printer {name} state changed to {state}."),
    );
    // Refresh `printer-state` in the DNS-SD TXT when shared.
    if let Some(p) = ctx.reg().find(&name).cloned() {
        if p.shared {
            ctx.dnssd_publish(&p);
        }
    }
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
    if accepting {
        p.reasons.clear();
    } else {
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
    // `printer-is-shared` may have toggled — refresh DNS-SD accordingly.
    if let Some(p) = ctx.reg().find(&name).cloned() {
        if p.shared {
            ctx.dnssd_publish(&p);
        } else {
            ctx.dnssd_unpublish(&name);
        }
    }
    resp.code = status::OK;
}

// ==================== P5: IPP subscriptions ====================

/// Resource path inside an `ipp[s]://` URI — after `host[:port]`. A
/// domain-socket URI carries the socket path in the authority slot
/// (`ipp:///tmp/.../cups.sock:8631/`), so the port marker is used to split
/// authority from resource when present.
fn uri_resource(uri: &str) -> &str {
    let rest = uri
        .strip_prefix("ipp://")
        .or_else(|| uri.strip_prefix("ipps://"))
        .map_or(uri, |r| r.split('?').next().map_or(r, |s| s));
    // `host:port/resource` — port is digits between the last ':' and '/'.
    if let Some(colon) = rest.rfind(':') {
        if let Some(slash) = rest[colon..].find('/') {
            if rest[colon + 1..colon + slash]
                .chars()
                .all(|c| c.is_ascii_digit())
                && !rest[colon + 1..colon + slash].is_empty()
            {
                return &rest[colon + slash..];
            }
        }
    }
    // No port — authority ends at the first '/'.
    match rest.find('/') {
        Some(i) => &rest[i..],
        None => "/",
    }
}

/// True when a `printer-uri` names no single destination — the server root
/// (`ipp://host/` or `ipp://host`) or a `/printers`/`/classes` collection.
/// Such URIs mean "all printers" for ops like Get-Jobs / Get-Printers.
fn is_all_printers_uri(uri: &str) -> bool {
    let path = uri_resource(uri).trim_end_matches('/');
    path.is_empty() || path == "/printers" || path == "/classes"
}

/// Printer/class name from a `printer-uri` — last `/printers|classes/` segment.
fn dest_name(uri: &str) -> Option<String> {
    for seg in ["/printers/", "/classes/"] {
        if let Some(i) = uri.find(seg) {
            return Some(uri[i + seg.len()..].split('?').next()?.to_string());
        }
    }
    uri.rsplit('/')
        .next()
        .filter(|n| !n.is_empty())
        .map(str::to_string)
}

/// `job-hold-until` in the job-template attrs — true for `indefinite` or a
/// named/time-window hold; `no-hold` (and its absence) means unheld.
fn hold_requested(attrs: &[Attribute]) -> bool {
    attrs
        .iter()
        .find(|a| a.name.as_str() == "job-hold-until")
        .is_some_and(|a| {
            a.values
                .first()
                .is_some_and(|v| !matches!(v, Value::Keyword(k) if k.as_str() == "no-hold"))
        })
}

/// `requesting-user-name` from the op group (auth identity fallback).
fn requesting_user(req: &IppMessage, ctx: &Ctx) -> String {
    ctx.username
        .clone()
        .or_else(|| {
            req.find(tags::OPERATION, "requesting-user-name")
                .and_then(attr_text)
        })
        .unwrap_or_else(|| "anonymous".into())
}

/// Subscription-attribute segments inside a request — upstream treats the
/// subscription group's attribute list as flat, delimited into one segment
/// per requested subscription by `IPP_TAG_ZERO` separators (repeated
/// `subscription` group delimiters merge that way on the wire).
/// Returns one Vec of attribute refs per segment, in request order.
fn sub_segments(req: &IppMessage) -> Vec<Vec<&Attribute>> {
    let mut segs: Vec<Vec<&Attribute>> = Vec::new();
    for g in &req.groups {
        if g.tag != tags::SUBSCRIPTION {
            continue;
        }
        let mut cur: Vec<&Attribute> = Vec::new();
        for a in &g.attributes {
            if a.is_separator() {
                if !cur.is_empty() {
                    segs.push(std::mem::take(&mut cur));
                }
            } else {
                cur.push(a);
            }
        }
        if !cur.is_empty() {
            segs.push(cur);
        }
    }
    segs
}

/// Look up an attribute inside one subscription segment.
fn seg_find<'a>(seg: &[&'a Attribute], name: &str) -> Option<&'a Attribute> {
    seg.iter().find(|a| a.name.as_str() == name).copied()
}

/// `notify-events` inside one segment → parsed Event list (None if absent).
fn seg_events(seg: &[&Attribute]) -> Option<Vec<events::Event>> {
    let a = seg_find(seg, "notify-events")?;
    let mut out = Vec::new();
    for v in &a.values {
        if let Value::Keyword(k) = v {
            out.push(events::Event::from_name(k.as_str().as_ref())?);
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Integer value of an attribute inside a segment.
fn seg_int(seg: &[&Attribute], name: &str) -> Option<i32> {
    match seg_find(seg, name).and_then(|a| a.values.first()) {
        Some(Value::Integer(i)) => Some(*i),
        _ => None,
    }
}

/// True when the segment carries `notify-recipient-uri` or
/// `notify-pull-method` — upstream ignores segments with neither.
fn seg_subscribed(seg: &[&Attribute]) -> bool {
    seg_find(seg, "notify-recipient-uri").is_some() || seg_find(seg, "notify-pull-method").is_some()
}

fn seg_user_data(seg: &[&Attribute]) -> Option<Vec<u8>> {
    match seg_find(seg, "notify-user-data").and_then(|a| a.first()) {
        Some(Value::OctetString(b)) => Some(b.clone()),
        _ => None,
    }
}

/// Emit `notify-subscription-id` (+ lease) for a created sub — a separator
/// precedes each additional sub's block, as `ippAddSeparator` does upstream.
fn emit_sub_id(resp: &mut IppMessage, id: i32, lease_out: i32) {
    let g = resp.group_mut(tags::SUBSCRIPTION);
    if !g.attributes.is_empty() {
        g.attributes.push(Attribute::separator());
    }
    g.attributes.push(Attribute::new(
        "notify-subscription-id",
        tags::INTEGER,
        vec![Value::Integer(id)],
    ));
    g.attributes.push(Attribute::new(
        "notify-lease-duration",
        tags::INTEGER,
        vec![Value::Integer(lease_out)],
    ));
}

/// Embedded job subscription — when a job-creation request carries
/// `subscription-attributes-tag` content (RFC 3995 §5.1.2), create one job
/// subscription per segment and emit `notify-subscription-id` back.
/// Upstream semantics: a segment with neither `notify-recipient-uri` nor
/// `notify-pull-method` is ignored; `notify-lease-duration` is not allowed
/// on job subscriptions; `notify-events` defaults to `job-completed`.
fn maybe_add_job_subscription(
    req: &IppMessage,
    resp: &mut IppMessage,
    ctx: &Ctx,
    job_id: i32,
    dest: &str,
) {
    let segs = sub_segments(req);
    if segs.is_empty() {
        return; // no embedded subscription group
    }
    let owner = requesting_user(req, ctx);
    for seg in segs {
        if !seg_subscribed(&seg) {
            continue;
        }
        if seg_find(&seg, "notify-lease-duration").is_some() {
            send_status(
                resp,
                status::ERROR_BAD_REQUEST,
                "notify-lease-duration cannot be used with job subscriptions.",
            );
            return;
        }
        let ev = seg_events(&seg).unwrap_or_else(|| vec![events::Event::JobCompleted]);
        if ctx.max_subscriptions > 0 && ctx.subs().count() >= ctx.max_subscriptions as usize {
            return; // job still created; sub request silently capped
        }
        let id = ctx.subs_write().add(
            Some(dest.to_string()),
            Some(job_id),
            ev,
            owner.clone(),
            events::NEVER_EXPIRE,
            seg_user_data(&seg),
        );
        emit_sub_id(resp, id, 0);
    }
}

/// `Create-{Printer,Job}-Subscriptions` — `create_subscription`.
/// One subscription per attribute segment — repeated `subscription` group
/// delimiters arrive as separators inside the merged group ("Add 2 ..." in
/// upstream 4.4). Upstream semantics: a segment with neither
/// `notify-recipient-uri` nor `notify-pull-method` stops processing; the
/// status stays `client-error-bad-request` until a sub is actually created.
fn create_subscription(
    req: &IppMessage,
    resp: &mut IppMessage,
    ctx: &Ctx,
    uri_attr: Option<&Attribute>,
) {
    let segs = sub_segments(req);
    if segs.is_empty() {
        send_status(
            resp,
            status::ERROR_BAD_REQUEST,
            "No subscription attributes in request.",
        );
        return;
    }
    let job_sub = req.code == op::CREATE_JOB_SUBSCRIPTIONS;
    let (printer, job_id) = if job_sub {
        let jid = int_attr(req, "job-id").map(|j| j as i32);
        let dest = uri_attr.and_then(attr_text).and_then(|u| dest_name(&u));
        (dest, jid)
    } else {
        (
            uri_attr.and_then(attr_text).and_then(|u| dest_name(&u)),
            None,
        )
    };
    let owner = requesting_user(req, ctx);
    resp.code = status::ERROR_BAD_REQUEST;
    for seg in segs {
        if !seg_subscribed(&seg) {
            break; // upstream: stops at the first segment with no recipient
        }
        let ev = match seg_events(&seg) {
            Some(e) => e,
            None if job_id.is_some() => vec![events::Event::JobCompleted],
            None if printer.is_some() => {
                vec![events::Event::PrinterStateChanged]
            }
            None => {
                send_status(
                    resp,
                    status::ERROR_BAD_REQUEST,
                    "notify-events not specified.",
                );
                return;
            }
        };
        let lease = seg_int(&seg, "notify-lease-duration").unwrap_or(events::NEVER_EXPIRE);
        // `MaxSubscriptions` — a full table is `client-error-too-many-subscriptions`.
        // Counts the raw slot table like upstream's `ArrayCount(Subscriptions)` —
        // lapsed-but-unreaped entries still occupy a slot.
        if ctx.max_subscriptions > 0 && ctx.subs().count() >= ctx.max_subscriptions as usize {
            send_status(
                resp,
                status::ERROR_TOO_MANY_SUBSCRIPTIONS,
                "Too many subscriptions.",
            );
            return;
        }
        let id = ctx.subs_write().add(
            printer.clone(),
            job_id,
            ev,
            owner.clone(),
            lease,
            seg_user_data(&seg),
        );
        emit_sub_id(resp, id, lease);
        resp.code = status::OK;
    }
}

/// Emit a subscription's description group (`cupsdCopySubscription`).
fn add_sub_group(resp: &mut IppMessage, s: &events::Subscription, ctx: &Ctx) {
    let g = resp.group_mut(tags::SUBSCRIPTION);
    let evs: Vec<Value> = s
        .event_names()
        .iter()
        .map(|e| Value::Keyword(e.clone().into()))
        .collect();
    if g.find("notify-events").is_none() {
        g.attributes
            .push(Attribute::new("notify-events", tags::KEYWORD, evs));
    }
    let mut add = |name: &str, tag: u8, v: Value| {
        if g.find(name).is_none() {
            g.attributes.push(Attribute::new(name, tag, vec![v]));
        }
    };
    add(
        "notify-subscription-id",
        tags::INTEGER,
        Value::Integer(s.id),
    );
    add(
        "notify-subscriber-user-name",
        tags::NAME,
        Value::Name(s.owner.clone().into()),
    );
    add(
        "notify-lease-duration",
        tags::INTEGER,
        Value::Integer(s.lease_remaining()),
    );
    if let Some(p) = &s.printer {
        let scheme = if ctx.is_encrypted { "ipps" } else { "ipp" };
        add(
            "notify-printer-uri",
            tags::URI,
            Value::Uri(format!("{scheme}://{}:{}/printers/{p}", ctx.hostname, ctx.port).into()),
        );
    }
    if let Some(j) = s.job_id {
        add("notify-job-id", tags::INTEGER, Value::Integer(j));
    }
    if let Some(d) = &s.user_data {
        add(
            "notify-user-data",
            tags::STRING,
            Value::OctetString(d.clone()),
        );
    }
}

/// `Get-Subscriptions` — `get_subscriptions`.
fn get_subscriptions(
    req: &IppMessage,
    resp: &mut IppMessage,
    ctx: &Ctx,
    uri_attr: Option<&Attribute>,
) {
    // `cupsdExpireSubscriptions(NULL, NULL)` — lapsed leases are *removed*
    // from the table on read, so `MaxSubscriptions` slot counting matches
    // upstream's `cupsArrayCount(Subscriptions)`.
    ctx.subs_write().expire();
    resp.code = status::OK;
    let printer = uri_attr.and_then(attr_text).and_then(|u| dest_name(&u));
    let owner = req
        .find(tags::OPERATION, "requesting-user-name")
        .and_then(attr_text)
        .filter(|_| ctx.username.is_none()); // admin sees all
    let guard = ctx.subs();
    let ids: Vec<i32> = guard
        .list(printer.as_deref(), owner.as_deref())
        .iter()
        .map(|s| s.id)
        .collect();
    drop(guard);
    for id in ids {
        if let Some(s) = ctx.subs().find(id) {
            // Owned copy to avoid holding the lock across group emission.
            add_sub_group(resp, &s.clone(), ctx);
        }
    }
}

/// `Get-Subscription-Attributes`.
fn get_subscription_attrs(req: &IppMessage, resp: &mut IppMessage, ctx: &Ctx) {
    let Some(id) = int_attr(req, "notify-subscription-id").map(|i| i as i32) else {
        send_status(
            resp,
            status::ERROR_BAD_REQUEST,
            "Missing notify-subscription-id.",
        );
        return;
    };
    // `cupsdExpireSubscriptions(NULL, NULL)` — purge lapsed leases first.
    ctx.subs_write().expire();
    let subs = ctx.subs();
    let Some(s) = subs.find(id) else {
        send_status(
            resp,
            status::ERROR_NOT_FOUND,
            "Subscription #{id} not found.",
        );
        return;
    };
    let s2 = s.clone();
    drop(subs);
    resp.code = status::OK;
    add_sub_group(resp, &s2, ctx);
}

/// `Renew-Subscription`.
fn renew_subscription(req: &IppMessage, resp: &mut IppMessage, ctx: &Ctx) {
    let Some(id) = int_attr(req, "notify-subscription-id").map(|i| i as i32) else {
        send_status(
            resp,
            status::ERROR_BAD_REQUEST,
            "Missing notify-subscription-id.",
        );
        return;
    };
    if ctx.subs_write().renew(id) {
        resp.code = status::OK;
        let g = resp.group_mut(tags::SUBSCRIPTION);
        g.attributes.push(Attribute::new(
            "notify-subscription-id",
            tags::INTEGER,
            vec![Value::Integer(id)],
        ));
    } else {
        send_status(
            resp,
            status::ERROR_NOT_FOUND,
            "Subscription #{id} not found.",
        );
    }
}

/// `Cancel-Subscription`.
fn cancel_subscription(req: &IppMessage, resp: &mut IppMessage, ctx: &Ctx) {
    let Some(id) = int_attr(req, "notify-subscription-id").map(|i| i as i32) else {
        send_status(
            resp,
            status::ERROR_BAD_REQUEST,
            "Missing notify-subscription-id.",
        );
        return;
    };
    if ctx.subs_write().remove(id).is_some() {
        resp.code = status::OK;
    } else {
        send_status(
            resp,
            status::ERROR_NOT_FOUND,
            "Subscription #{id} not found.",
        );
    }
}

/// `Get-Notifications` — ippget pull; drains matching subscription queues.
fn get_notifications(req: &IppMessage, resp: &mut IppMessage, ctx: &Ctx) {
    let ids: Vec<i32> = req
        .find(tags::OPERATION, "notify-subscription-ids")
        .map(|a| {
            a.values
                .iter()
                .filter_map(|v| match v {
                    Value::Integer(i) | Value::Enum(i) => Some(*i),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    if ids.is_empty() {
        send_status(
            resp,
            status::ERROR_BAD_REQUEST,
            "Missing notify-subscription-ids.",
        );
        return;
    }
    resp.code = status::OK;
    let mut found_any = false;
    for id in ids {
        let notes = ctx.subs_write().drain(id);
        for n in notes {
            found_any = true;
            let g = resp.new_group_mut(tags::EVENT_NOTIFICATION);
            let mut add = |name: &str, tag: u8, v: Value| {
                g.attributes.push(Attribute::new(name, tag, vec![v]));
            };
            add("notify-subscription-id", tags::INTEGER, Value::Integer(id));
            add(
                "notify-sequence-number",
                tags::INTEGER,
                Value::Integer(n.seq),
            );
            add(
                "notify-subscribed-event",
                tags::KEYWORD,
                Value::Keyword(n.event.name().into()),
            );
            // Newer IPP notifications spec names the event `notify-event`;
            // emit both so ippget consumers and the stock suite see it.
            add(
                "notify-event",
                tags::KEYWORD,
                Value::Keyword(n.event.name().into()),
            );
            if let Some(p) = &n.printer {
                let scheme = if ctx.is_encrypted { "ipps" } else { "ipp" };
                let host = ctx.hostname.clone();
                let port = ctx.port;
                add(
                    "notify-printer-uri",
                    tags::URI,
                    Value::Uri(format!("{scheme}://{host}:{port}/printers/{p}").into()),
                );
                add("printer-name", tags::NAME, Value::Name(p.clone().into()));
            }
            if let Some(j) = n.job_id {
                add("notify-job-id", tags::INTEGER, Value::Integer(j));
            }
            if let Some(js) = n.job_state {
                add("job-state", tags::ENUM, Value::Enum(js));
            }
            add(
                "notify-text",
                tags::TEXT,
                Value::Text(n.text.clone().into()),
            );
        }
    }
    if !found_any {
        // No queued events is still a valid ippget pull.
        resp.code = status::OK;
    }
}
