//! Shared response-construction helpers — ports of `ippNewResponse`,
//! `send_ipp_status`, `copy_printer_attrs`, `create_requested_array`,
//! and the `CommonData` attribute block from `cupsdCreateCommonData`.

use ipp_codec::{tags, Attribute, IppMessage, Value};
use printer::{ipp_datetime, now, ptype, state_reasons_attr, Printer};

use crate::dispatch::Ctx;

/// `ippNewResponse()` — response message seeded from the request:
/// same version + request-id, `attributes-charset` echoed from the
/// request's first op attr when valid (else `utf-8`), same for
/// `attributes-natural-language` (else `DefaultLanguage`).
pub fn new_response(req: &IppMessage, default_language: &str) -> IppMessage {
    let mut resp = IppMessage::new(0);
    resp.version = req.version;
    resp.request_id = req.request_id;

    let op = req.group(tags::OPERATION);
    let charset = op
        .and_then(|g| g.attributes.first())
        .filter(|a| a.name == "attributes-charset" && a.values.len() == 1)
        .and_then(|a| a.first())
        .and_then(|v| match v {
            Value::Charset(t) => Some(t.clone()),
            _ => None,
        });
    let language = op
        .and_then(|g| g.attributes.get(1))
        .filter(|a| a.name == "attributes-natural-language" && a.values.len() == 1)
        .and_then(|a| a.first())
        .and_then(|v| match v {
            Value::NaturalLanguage(t) => Some(t.clone()),
            _ => None,
        });

    resp.push(
        tags::OPERATION,
        Attribute::new(
            "attributes-charset",
            tags::CHARSET,
            vec![Value::Charset(charset.unwrap_or_else(|| "utf-8".into()))],
        ),
    );
    resp.push(
        tags::OPERATION,
        Attribute::new(
            "attributes-natural-language",
            tags::LANGUAGE,
            vec![Value::NaturalLanguage(
                language.unwrap_or_else(|| default_language.into()),
            )],
        ),
    );
    resp
}

/// `send_ipp_status()` — set the response status code and append a
/// `status-message` text attr to the operation group.
pub fn send_status(resp: &mut IppMessage, code: u16, message: impl Into<String>) {
    resp.code = code;
    resp.push(
        tags::OPERATION,
        Attribute::new(
            "status-message",
            tags::TEXT,
            vec![Value::Text(message.into().into())],
        ),
    );
}

/// `ippCreateRequestedArray()` — names from the request's
/// `requested-attributes` keyword attr; `None` = all attrs.
#[must_use]
pub fn requested_attrs(req: &IppMessage) -> Option<Vec<String>> {
    let attr = req.find(tags::OPERATION, "requested-attributes")?;
    let names: Vec<String> = attr
        .values
        .iter()
        .filter_map(|v| match v {
            Value::Keyword(t) | Value::Name(t) => Some(t.as_str().to_string()),
            _ => None,
        })
        .collect();
    if names.is_empty() {
        None
    } else {
        Some(names)
    }
}

/// IPP job-attribute names — the bases for `xxx-default`/`xxx-supported`
/// job-template attributes (RFC 8011 §5.2 + media-col).
const JOB_ATTRS: &[&str] = &[
    "copies",
    "finishings",
    "job-hold-until",
    "job-priority",
    "job-sheets",
    "media",
    "media-col",
    "multiple-document-handling",
    "number-up",
    "orientation-requested",
    "output-bin",
    "page-ranges",
    "print-color-mode",
    "print-quality",
    "print-scaling",
    "printer-resolution",
    "sides",
    "jpeg-k-octets",
    "jpeg-x-dimension",
    "jpeg-y-dimension",
    "pdf-k-octets",
    "pdf-versions",
    "print-as-raster",
];

/// Is `name` a job-template attribute (`xxx-default`, `xxx-supported`
/// whose base is a job attribute, or a media-col database/ready entry)?
fn is_job_template(name: &str) -> bool {
    if matches!(
        name,
        "media-col-database" | "media-col-ready" | "media-ready"
    ) {
        return true;
    }
    let base = name
        .strip_suffix("-default")
        .or_else(|| name.strip_suffix("-supported"))
        .or_else(|| name.strip_suffix("-ready"));
    match base {
        Some(b) => JOB_ATTRS.contains(&b) || b.starts_with("media-"),
        None => JOB_ATTRS.contains(&name),
    }
}

/// `cupsArrayFind(ra, name)` — `requested-attributes` filter predicate.
/// The list may name individual attributes *or* an attribute group:
/// `all` (everything), `printer-description` (non-template attrs),
/// `job-template` (job-template attrs), `printer-defaults`, …
/// When `requested-attributes` is absent (`ra` is `None`), or when it
/// only names a *group* (`all`, `job-template`, …), the huge opt-in
/// media database collections are still withheld — they are emitted only
/// when named literally, matching upstream.
pub fn wants(ra: &Option<Vec<String>>, name: &str) -> bool {
    let opt_in_only = matches!(name, "media-col-database" | "media-size-database");
    match ra {
        None => !opt_in_only,
        Some(ra) => ra.iter().any(|n| {
            n == name
                || (!opt_in_only
                    && (n == "all"
                        || (n == "job-template" && is_job_template(name))
                        || (n == "printer-description" && !is_job_template(name))
                        || (n == "printer-defaults" && name.ends_with("-default"))
                        || (n == "document-format" && name.starts_with("document-format"))))
        }),
    }
}

/// URI assembly mirroring `httpAssembleURIf` for queue URIs:
/// `ipp://host[:port]/{printers|classes}/{name}` (ipps when encrypted).
pub fn queue_uri(ctx: &Ctx, is_class: bool, name: &str) -> String {
    let scheme = if ctx.is_encrypted { "ipps" } else { "ipp" };
    let sub = if is_class { "classes" } else { "printers" };
    format!("{scheme}://{}:{}/{}/{}", ctx.hostname, ctx.port, sub, name)
}

/// Web-URI assembly (`/icons/`, `/printers/`, strings) — http(s).
fn web_uri(ctx: &Ctx, path: &str) -> String {
    let scheme = if ctx.is_encrypted { "https" } else { "http" };
    format!("{scheme}://{}:{}{}", ctx.hostname, ctx.port, path)
}

/// `copy_attrs()` — copy stored attrs to `group`, filtered by
/// `requested-attributes`. Skips our op-only attrs.
pub fn copy_attrs(
    resp: &mut IppMessage,
    group_tag: u8,
    attrs: &[Attribute],
    ra: &Option<Vec<String>>,
) {
    for a in attrs {
        if a.is_separator() {
            continue;
        }
        if wants(ra, a.name.as_str().as_ref()) {
            resp.push(group_tag, a.clone());
        }
    }
}

/// `copy_printer_attrs()` — the full port: dynamic per-request attrs
/// (computed), then the stored `printer->attrs`, then `CommonData`.
pub fn copy_printer_attrs(
    resp: &mut IppMessage,
    p: &Printer,
    ctx: &Ctx,
    ra: &Option<Vec<String>>,
    queued_job_count: i32,
) {
    let curtime = now();
    let is_default = ctx.reg().default.as_deref() == Some(p.name.as_str());
    let pr = tags::PRINTER;

    let add = |resp: &mut IppMessage, name: &str, tag: u8, v: Value| {
        if wants(ra, name) {
            resp.push(pr, Attribute::new(name, tag, vec![v]));
        }
    };

    if wants(ra, "marker-change-time") && p.marker_time != 0 {
        add(
            resp,
            "marker-change-time",
            tags::INTEGER,
            Value::Integer(p.marker_time as i32),
        );
    }

    // member-uris for classes.
    if !p.members.is_empty() && wants(ra, "member-uris") {
        let vals: Vec<Value> = p
            .members
            .iter()
            .map(|m| {
                let member_is_class = ctx
                    .reg()
                    .printers
                    .get(m.as_str())
                    .is_some_and(Printer::is_class);
                Value::Uri(queue_uri(ctx, member_is_class, m).into())
            })
            .collect();
        resp.push(pr, Attribute::new("member-uris", tags::URI, vals));
    }
    if !p.members.is_empty() && wants(ra, "member-names") {
        let vals: Vec<Value> = p
            .members
            .iter()
            .map(|m| Value::Name(m.as_str().into()))
            .collect();
        resp.push(pr, Attribute::new("member-names", tags::NAME, vals));
    }

    if let Some(a) = &p.alert {
        add(
            resp,
            "printer-alert",
            tags::STRING,
            Value::OctetString(a.clone().into_bytes()),
        );
    }
    if let Some(a) = &p.alert_description {
        add(
            resp,
            "printer-alert-description",
            tags::TEXT,
            Value::Text(a.as_str().into()),
        );
    }

    add(
        resp,
        "printer-config-change-date-time",
        tags::DATE,
        ipp_datetime(p.config_time),
    );
    add(
        resp,
        "printer-config-change-time",
        tags::INTEGER,
        Value::Integer(p.config_time as i32),
    );
    add(
        resp,
        "printer-current-time",
        tags::DATE,
        ipp_datetime(curtime),
    );

    if wants(ra, "printer-dns-sd-name") {
        match &p.reg_name {
            Some(r) => add(
                resp,
                "printer-dns-sd-name",
                tags::NAME,
                Value::Name(r.as_str().into()),
            ),
            None => add(resp, "printer-dns-sd-name", tags::NOVALUE, Value::NoValue),
        }
    }
    if let Some(ep) = &p.error_policy {
        add(
            resp,
            "printer-error-policy",
            tags::NAME,
            Value::Name(ep.as_str().into()),
        );
    }
    if wants(ra, "printer-error-policy-supported") {
        if p.is_class() {
            add(
                resp,
                "printer-error-policy-supported",
                tags::NAME,
                Value::Name("retry-current-job".into()),
            );
        } else {
            let errs = [
                "abort-job",
                "retry-current-job",
                "retry-job",
                "stop-printer",
            ];
            resp.push(
                pr,
                Attribute::new(
                    "printer-error-policy-supported",
                    tags::NAME,
                    errs.iter().map(|e| Value::Name((*e).into())).collect(),
                ),
            );
        }
    }
    if wants(ra, "printer-icons") {
        add(
            resp,
            "printer-icons",
            tags::URI,
            Value::Uri(web_uri(ctx, &format!("/icons/{}.png", p.name)).into()),
        );
    }
    add(
        resp,
        "printer-is-accepting-jobs",
        tags::BOOLEAN,
        Value::Boolean(p.accepting),
    );
    add(
        resp,
        "printer-is-shared",
        tags::BOOLEAN,
        Value::Boolean(p.shared),
    );
    add(
        resp,
        "printer-is-temporary",
        tags::BOOLEAN,
        Value::Boolean(p.temporary),
    );
    if wants(ra, "printer-more-info") {
        add(
            resp,
            "printer-more-info",
            tags::URI,
            Value::Uri(
                web_uri(
                    ctx,
                    &format!(
                        "/{}/{}",
                        if p.is_class() { "classes" } else { "printers" },
                        p.name
                    ),
                )
                .into(),
            ),
        );
    }
    if let Some(op) = &p.op_policy {
        add(
            resp,
            "printer-op-policy",
            tags::NAME,
            Value::Name(op.as_str().into()),
        );
    }
    add(resp, "printer-state", tags::ENUM, Value::Enum(p.state));
    add(
        resp,
        "printer-state-change-date-time",
        tags::DATE,
        ipp_datetime(p.state_time),
    );
    add(
        resp,
        "printer-state-change-time",
        tags::INTEGER,
        Value::Integer(p.state_time as i32),
    );
    add(
        resp,
        "printer-state-message",
        tags::TEXT,
        Value::Text(p.state_message.as_str().into()),
    );
    if wants(ra, "printer-state-reasons") {
        resp.push(pr, state_reasons_attr(p));
    }
    if wants(ra, "printer-strings-uri") {
        add(
            resp,
            "printer-strings-uri",
            tags::URI,
            Value::Uri(web_uri(ctx, &format!("/strings/{}.strings", ctx.language)).into()),
        );
    }
    if wants(ra, "printer-type") {
        add(
            resp,
            "printer-type",
            tags::ENUM,
            Value::Enum(p.effective_ptype(is_default)),
        );
    }
    add(
        resp,
        "printer-up-time",
        tags::INTEGER,
        Value::Integer(curtime as i32),
    );
    if wants(ra, "printer-uri-supported") {
        add(
            resp,
            "printer-uri-supported",
            tags::URI,
            Value::Uri(queue_uri(ctx, p.is_class(), &p.name).into()),
        );
    }
    add(
        resp,
        "queued-job-count",
        tags::INTEGER,
        Value::Integer(queued_job_count),
    );
    add(
        resp,
        "uri-security-supported",
        tags::KEYWORD,
        Value::Keyword(if ctx.is_encrypted { "tls" } else { "none" }.into()),
    );
    if wants(ra, "uri-authentication-supported") {
        add(
            resp,
            "uri-authentication-supported",
            tags::KEYWORD,
            Value::Keyword(ctx.uri_authentication.as_str().into()),
        );
    }

    // Stored printer attrs (printer->attrs) — for P1 the static set.
    copy_attrs(resp, pr, &stored_attrs(p, ctx), ra);

    // CommonData — the shared "every queue reports these" block.
    let cd = common_data(ctx);
    copy_attrs(resp, pr, &cd, ra);
}

fn add1(v: &mut Vec<Attribute>, name: &str, tag: u8, val: Value) {
    v.push(Attribute::new(name, tag, vec![val]));
}
fn addn(v: &mut Vec<Attribute>, name: &str, tag: u8, vals: Vec<Value>) {
    v.push(Attribute::new(name, tag, vals));
}

/// `printer->attrs` — the stored attribute set `cupsdSetPrinterAttrs`
/// builds for a queue. Driverless-first: this is the raw/basic set;
/// PPD-derived attrs join at P7.
fn stored_attrs(p: &Printer, _ctx: &Ctx) -> Vec<Attribute> {
    let mut v: Vec<Attribute> = Vec::with_capacity(64);
    let kw = |s: &str| Value::Keyword(s.into());

    add1(
        &mut v,
        "color-supported",
        tags::BOOLEAN,
        Value::Boolean(p.ptype & ptype::COLOR != 0),
    );
    if !p.uuid.is_empty() {
        add1(
            &mut v,
            "printer-uuid",
            tags::URI,
            Value::Uri(p.uuid.as_str().into()),
        );
    }
    addn(
        &mut v,
        "document-format-supported",
        tags::MIMETYPE,
        vec![
            Value::MimeMediaType("application/octet-stream".into()),
            Value::MimeMediaType("application/pdf".into()),
            Value::MimeMediaType("application/postscript".into()),
            Value::MimeMediaType("image/jpeg".into()),
            Value::MimeMediaType("image/png".into()),
            Value::MimeMediaType("image/pwg-raster".into()),
            Value::MimeMediaType("image/urf".into()),
        ],
    );
    add1(
        &mut v,
        "document-format-default",
        tags::MIMETYPE,
        Value::MimeMediaType("application/octet-stream".into()),
    );
    add1(
        &mut v,
        "device-uri",
        tags::URI,
        Value::Uri(p.device_uri.as_str().into()),
    );
    // `printer-device-id` is per-queue — a stored `Option printer-device-id`
    // (set by driver selection / Set-Printer-Attributes) wins over the
    // driverless default.
    let devid = p
        .options
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("printer-device-id"))
        .map(|(_, v)| v.clone())
        .unwrap_or_else(|| "MFG:presswork;MDL:ipp-everywhere;CMD:PWG-Raster;".into());
    add1(
        &mut v,
        "printer-device-id",
        tags::TEXT,
        Value::Text(devid.into()),
    );
    add1(&mut v, "finishings-supported", tags::ENUM, Value::Enum(3));
    add1(&mut v, "finishings-default", tags::ENUM, Value::Enum(3));
    add1(
        &mut v,
        "printer-info",
        tags::TEXT,
        Value::Text(p.info.as_deref().unwrap_or(&p.name).into()),
    );
    add1(
        &mut v,
        "printer-location",
        tags::TEXT,
        Value::Text(p.location.as_deref().unwrap_or("").into()),
    );
    if let Some(g) = &p.geo_location {
        add1(
            &mut v,
            "printer-geo-location",
            tags::URI,
            Value::Uri(g.as_str().into()),
        );
    }
    add1(
        &mut v,
        "printer-make-and-model",
        tags::TEXT,
        Value::Text(
            p.make_model
                .as_deref()
                .unwrap_or_else(|| {
                    // Upstream falls back to a driver/backend-derived name;
                    // for a bare queue it reports the device-uri scheme.
                    p.device_uri
                        .split("://")
                        .next()
                        .filter(|s| !s.is_empty())
                        .unwrap_or("Unknown")
                })
                .into(),
        ),
    );
    if let Some(o) = &p.organization {
        add1(
            &mut v,
            "printer-organization",
            tags::TEXT,
            Value::Text(o.as_str().into()),
        );
    }
    if let Some(o) = &p.organizational_unit {
        add1(
            &mut v,
            "printer-organizational-unit",
            tags::TEXT,
            Value::Text(o.as_str().into()),
        );
    }
    if !p.auth_info_required.is_empty() {
        addn(
            &mut v,
            "auth-info-required",
            tags::KEYWORD,
            p.auth_info_required.iter().map(|s| kw(s)).collect(),
        );
    }
    add1(
        &mut v,
        "printer-name",
        tags::NAME,
        Value::Name(p.name.as_str().into()),
    );
    add1(
        &mut v,
        "printer-id",
        tags::INTEGER,
        Value::Integer(p.printer_id),
    );
    addn(
        &mut v,
        "job-creation-attributes-supported",
        tags::KEYWORD,
        vec![
            kw("copies"),
            kw("finishings"),
            kw("ipp-attribute-fidelity"),
            kw("job-hold-until"),
            kw("job-name"),
            kw("job-priority"),
            kw("job-sheets"),
            kw("media"),
            kw("media-col"),
            kw("multiple-document-handling"),
            kw("number-up"),
            kw("output-bin"),
            kw("orientation-requested"),
            kw("page-ranges"),
            kw("print-color-mode"),
            kw("print-quality"),
            kw("printer-resolution"),
            kw("sides"),
        ],
    );
    if !p.marker_names.is_empty() {
        addn(
            &mut v,
            "marker-names",
            tags::NAME,
            p.marker_names
                .iter()
                .map(|s| Value::Name(s.as_str().into()))
                .collect(),
        );
    }
    if !p.marker_levels.is_empty() {
        addn(
            &mut v,
            "marker-levels",
            tags::INTEGER,
            p.marker_levels.iter().map(|i| Value::Integer(*i)).collect(),
        );
    }
    if !p.marker_low_levels.is_empty() {
        addn(
            &mut v,
            "marker-low-levels",
            tags::INTEGER,
            p.marker_low_levels
                .iter()
                .map(|i| Value::Integer(*i))
                .collect(),
        );
    }
    if !p.marker_high_levels.is_empty() {
        addn(
            &mut v,
            "marker-high-levels",
            tags::INTEGER,
            p.marker_high_levels
                .iter()
                .map(|i| Value::Integer(*i))
                .collect(),
        );
    }
    if !p.marker_types.is_empty() {
        addn(
            &mut v,
            "marker-types",
            tags::KEYWORD,
            p.marker_types.iter().map(|s| kw(s)).collect(),
        );
    }
    if !p.marker_colors.is_empty() {
        addn(
            &mut v,
            "marker-colors",
            tags::NAME,
            p.marker_colors
                .iter()
                .map(|s| Value::Name(s.as_str().into()))
                .collect(),
        );
    }
    if !p.marker_message.is_empty() {
        add1(
            &mut v,
            "marker-message",
            tags::TEXT,
            Value::Text(p.marker_message.as_str().into()),
        );
    }
    v
}

/// `CommonData` — `cupsdCreateCommonData()`. Config-dependent values
/// come from `ctx` (which carries the loaded `Config`).
#[must_use]
pub fn common_data(ctx: &Ctx) -> Vec<Attribute> {
    const K_SUPPORTED: i32 = i32::MAX;
    let mut v: Vec<Attribute> = Vec::with_capacity(64);
    let kw = |s: &str| Value::Keyword(s.into());
    let nm = |s: &str| Value::Name(s.into());

    add1(
        &mut v,
        "charset-configured",
        tags::CHARSET,
        Value::Charset("utf-8".into()),
    );
    addn(
        &mut v,
        "charset-supported",
        tags::CHARSET,
        vec![
            Value::Charset("us-ascii".into()),
            Value::Charset("utf-8".into()),
        ],
    );
    addn(
        &mut v,
        "compression-supported",
        tags::KEYWORD,
        vec![kw("none"), kw("gzip")],
    );
    add1(
        &mut v,
        "cups-version",
        tags::TEXT,
        Value::Text(ctx.cups_version.as_str().into()),
    );
    add1(
        &mut v,
        "generated-natural-language-supported",
        tags::LANGUAGE,
        Value::NaturalLanguage(ctx.default_language.as_str().into()),
    );
    addn(
        &mut v,
        "ipp-versions-supported",
        tags::KEYWORD,
        ["1.0", "1.1", "2.0", "2.1"].iter().map(|s| kw(s)).collect(),
    );
    add1(
        &mut v,
        "ippget-event-life",
        tags::INTEGER,
        Value::Integer(15),
    );
    add1(
        &mut v,
        "job-cancel-after-supported",
        tags::RANGE,
        Value::Range {
            low: 0,
            high: i32::MAX,
        },
    );
    addn(
        &mut v,
        "job-hold-until-supported",
        tags::KEYWORD,
        [
            "no-hold",
            "indefinite",
            "day-time",
            "evening",
            "night",
            "second-shift",
            "third-shift",
            "weekend",
        ]
        .iter()
        .map(|s| kw(s))
        .collect(),
    );
    add1(
        &mut v,
        "job-ids-supported",
        tags::BOOLEAN,
        Value::Boolean(true),
    );
    add1(
        &mut v,
        "job-k-octets-supported",
        tags::RANGE,
        Value::Range {
            low: 0,
            high: K_SUPPORTED,
        },
    );
    add1(
        &mut v,
        "job-priority-supported",
        tags::INTEGER,
        Value::Integer(100),
    );
    addn(
        &mut v,
        "job-settable-attributes-supported",
        tags::KEYWORD,
        [
            "copies",
            "finishings",
            "job-hold-until",
            "job-name",
            "job-priority",
            "media",
            "media-col",
            "multiple-document-handling",
            "number-up",
            "output-bin",
            "orientation-requested",
            "page-ranges",
            "print-color-mode",
            "print-quality",
            "printer-resolution",
            "sides",
        ]
        .iter()
        .map(|s| kw(s))
        .collect(),
    );
    addn(
        &mut v,
        "job-sheets-col-supported",
        tags::KEYWORD,
        ["job-sheets", "media", "media-col"]
            .iter()
            .map(|s| kw(s))
            .collect(),
    );
    if ctx.classification.is_empty() {
        addn(
            &mut v,
            "job-sheets-supported",
            tags::NAME,
            std::iter::once(nm("none"))
                .chain(ctx.banners.iter().map(|b| nm(b)))
                .collect(),
        );
    } else {
        add1(
            &mut v,
            "job-sheets-supported",
            tags::NAME,
            Value::Name(ctx.classification.as_str().into()),
        );
    }
    add1(
        &mut v,
        "jpeg-k-octets-supported",
        tags::RANGE,
        Value::Range {
            low: 0,
            high: K_SUPPORTED,
        },
    );
    add1(
        &mut v,
        "jpeg-x-dimension-supported",
        tags::RANGE,
        Value::Range {
            low: 0,
            high: 65535,
        },
    );
    add1(
        &mut v,
        "jpeg-y-dimension-supported",
        tags::RANGE,
        Value::Range {
            low: 1,
            high: 65535,
        },
    );
    addn(
        &mut v,
        "media-col-supported",
        tags::KEYWORD,
        [
            "media-bottom-margin",
            "media-left-margin",
            "media-right-margin",
            "media-size",
            "media-source",
            "media-top-margin",
            "media-type",
        ]
        .iter()
        .map(|s| kw(s))
        .collect(),
    );
    // `media-col-default` — the resolved default media collection
    // (na_letter_8.5x11in, 3 mm margins). Nested `media-size` collection.
    let mut media_col = Vec::new();
    media_col.push(Attribute::new(
        "media-size",
        tags::BEGIN_COLLECTION,
        vec![Value::Collection(vec![
            Attribute::new("x-dimension", tags::INTEGER, vec![Value::Integer(21590)]),
            Attribute::new("y-dimension", tags::INTEGER, vec![Value::Integer(27940)]),
        ])],
    ));
    for m in [
        "media-top-margin",
        "media-bottom-margin",
        "media-left-margin",
        "media-right-margin",
    ] {
        media_col.push(Attribute::new(m, tags::INTEGER, vec![Value::Integer(300)]));
    }
    media_col.push(Attribute::new(
        "media-source",
        tags::KEYWORD,
        vec![kw("auto")],
    ));
    media_col.push(Attribute::new(
        "media-type",
        tags::KEYWORD,
        vec![kw("stationery")],
    ));
    add1(
        &mut v,
        "media-col-default",
        tags::BEGIN_COLLECTION,
        Value::Collection(media_col),
    );
    addn(
        &mut v,
        "multiple-document-handling-supported",
        tags::KEYWORD,
        [
            "separate-documents-uncollated-copies",
            "separate-documents-collated-copies",
        ]
        .iter()
        .map(|s| kw(s))
        .collect(),
    );
    add1(
        &mut v,
        "multiple-document-jobs-supported",
        tags::BOOLEAN,
        Value::Boolean(true),
    );
    add1(
        &mut v,
        "multiple-operation-time-out",
        tags::INTEGER,
        Value::Integer(ctx.multiple_operation_timeout),
    );
    add1(
        &mut v,
        "multiple-operation-time-out-action",
        tags::KEYWORD,
        kw("process-job"),
    );
    // Job-template defaults + the media database. `media-col-database`
    // is a `1setOf collection` listing the media the printer can handle.
    add1(&mut v, "copies-default", tags::INTEGER, Value::Integer(1));
    add1(
        &mut v,
        "copies-supported",
        tags::RANGE,
        Value::Range { low: 1, high: 9999 },
    );
    add1(
        &mut v,
        "media-default",
        tags::KEYWORD,
        kw("na_letter_8.5x11in"),
    );
    addn(
        &mut v,
        "media-supported",
        tags::KEYWORD,
        [
            "na_letter_8.5x11in",
            "na_legal_8.5x14in",
            "iso_a4_210x297mm",
            "na_number-10_4.125x9.5in",
        ]
        .iter()
        .map(|s| kw(s))
        .collect(),
    );
    let media_col_db = |x: i32, y: i32| {
        Value::Collection(vec![
            Attribute::new(
                "media-size",
                tags::BEGIN_COLLECTION,
                vec![Value::Collection(vec![
                    Attribute::new("x-dimension", tags::INTEGER, vec![Value::Integer(x)]),
                    Attribute::new("y-dimension", tags::INTEGER, vec![Value::Integer(y)]),
                ])],
            ),
            Attribute::new("media-type", tags::KEYWORD, vec![kw("stationery")]),
            Attribute::new("media-source", tags::KEYWORD, vec![kw("auto")]),
        ])
    };
    addn(
        &mut v,
        "media-col-database",
        tags::BEGIN_COLLECTION,
        vec![
            media_col_db(21590, 27940), // na_letter_8.5x11in
            media_col_db(21590, 35560), // na_legal_8.5x14in
            media_col_db(21000, 29700), // iso_a4_210x297mm
        ],
    );
    add1(
        &mut v,
        "number-up-default",
        tags::INTEGER,
        Value::Integer(1),
    );
    add1(
        &mut v,
        "orientation-requested-default",
        tags::ENUM,
        Value::Enum(3), // portrait
    );
    add1(&mut v, "print-quality-default", tags::ENUM, Value::Enum(4));
    add1(
        &mut v,
        "print-color-mode-default",
        tags::KEYWORD,
        kw("auto"),
    );
    add1(&mut v, "sides-default", tags::KEYWORD, kw("one-sided"));
    addn(
        &mut v,
        "sides-supported",
        tags::KEYWORD,
        ["one-sided", "two-sided-long-edge", "two-sided-short-edge"]
            .iter()
            .map(|s| kw(s))
            .collect(),
    );
    // PWG 5100.12 §6.2 required printer/job-template attributes.
    add1(&mut v, "output-bin-default", tags::KEYWORD, kw("face-down"));
    add1(
        &mut v,
        "output-bin-supported",
        tags::KEYWORD,
        kw("face-down"),
    );
    addn(
        &mut v,
        "print-quality-supported",
        tags::ENUM,
        vec![Value::Enum(3), Value::Enum(4), Value::Enum(5)],
    );
    let res600 = Value::Resolution {
        x: 600,
        y: 600,
        units: 3, // dots-per-inch
    };
    add1(
        &mut v,
        "printer-resolution-default",
        tags::RESOLUTION,
        res600.clone(),
    );
    addn(
        &mut v,
        "printer-resolution-supported",
        tags::RESOLUTION,
        vec![res600.clone(), res600],
    );
    addn(
        &mut v,
        "media-size-supported",
        tags::BEGIN_COLLECTION,
        [
            (21590, 27940),
            (21590, 35560),
            (21000, 29700),
            (10477, 24130),
        ]
        .iter()
        .map(|&(x, y)| {
            Value::Collection(vec![
                Attribute::new("x-dimension", tags::INTEGER, vec![Value::Integer(x)]),
                Attribute::new("y-dimension", tags::INTEGER, vec![Value::Integer(y)]),
            ])
        })
        .collect(),
    );
    addn(
        &mut v,
        "media-type-supported",
        tags::KEYWORD,
        [
            "stationery",
            "stationery-letterhead",
            "cardstock",
            "envelope",
        ]
        .iter()
        .map(|s| kw(s))
        .collect(),
    );
    add1(
        &mut v,
        "pages-per-minute",
        tags::INTEGER,
        Value::Integer(30),
    );
    // ── IPP Everywhere (PWG 5100.14) required attributes ─────────────
    // Job hold/sheets.
    add1(
        &mut v,
        "job-hold-until-default",
        tags::KEYWORD,
        kw("no-hold"),
    );
    add1(
        &mut v,
        "job-priority-default",
        tags::INTEGER,
        Value::Integer(50),
    );
    add1(
        &mut v,
        "job-sheets-default",
        tags::NAME,
        Value::Name("none".into()),
    );
    // Ready media: the media-col actually loaded + its names.
    addn(
        &mut v,
        "media-col-ready",
        tags::BEGIN_COLLECTION,
        vec![media_col_db(21590, 27940)],
    );
    addn(
        &mut v,
        "media-ready",
        tags::KEYWORD,
        ["na_letter_8.5x11in"].iter().map(|s| kw(s)).collect(),
    );
    addn(
        &mut v,
        "media-source-supported",
        tags::KEYWORD,
        ["auto", "main", "manual", "by-pass-tray"]
            .iter()
            .map(|s| kw(s))
            .collect(),
    );
    // Media margins (hundredths of mm).
    for (name, mm) in [
        ("media-bottom-margin-supported", 635),
        ("media-top-margin-supported", 635),
        ("media-left-margin-supported", 635),
        ("media-right-margin-supported", 635),
    ] {
        add1(&mut v, name, tags::INTEGER, Value::Integer(mm));
    }
    addn(
        &mut v,
        "overrides-supported",
        tags::KEYWORD,
        [
            "document-number",
            "document-numbers",
            "output-pages",
            "pages",
            "orientation-requested",
            "media",
            "media-col",
            "sides",
        ]
        .iter()
        .map(|s| kw(s))
        .collect(),
    );
    addn(
        &mut v,
        "print-color-mode-supported",
        tags::KEYWORD,
        ["auto", "color", "monochrome"]
            .iter()
            .map(|s| kw(s))
            .collect(),
    );
    for (base, kwv) in [
        ("print-content-optimize", "auto"),
        ("print-rendering-intent", "auto"),
    ] {
        add1(&mut v, &format!("{base}-default"), tags::KEYWORD, kw(kwv));
        addn(
            &mut v,
            &format!("{base}-supported"),
            tags::KEYWORD,
            ["auto"].iter().map(|s| kw(s)).collect(),
        );
    }
    addn(
        &mut v,
        "pwg-raster-document-resolution-supported",
        tags::RESOLUTION,
        vec![
            Value::Resolution {
                x: 600,
                y: 600,
                units: 3,
            },
            Value::Resolution {
                x: 1200,
                y: 1200,
                units: 3,
            },
        ],
    );
    add1(
        &mut v,
        "pwg-raster-document-sheet-back",
        tags::KEYWORD,
        kw("normal"),
    );
    addn(
        &mut v,
        "pwg-raster-document-type-supported",
        tags::KEYWORD,
        ["black_1", "sgray_8", "srgb_8", "srgb_16"]
            .iter()
            .map(|s| kw(s))
            .collect(),
    );
    // Notifications.
    addn(
        &mut v,
        "notify-events-default",
        tags::KEYWORD,
        ["none"].iter().map(|s| kw(s)).collect(),
    );
    add1(
        &mut v,
        "notify-lease-duration-default",
        tags::INTEGER,
        Value::Integer(ctx.max_lease_duration),
    );
    // Identify + feature + misc printer-description.
    addn(
        &mut v,
        "identify-actions-default",
        tags::KEYWORD,
        ["display"].iter().map(|s| kw(s)).collect(),
    );
    addn(
        &mut v,
        "identify-actions-supported",
        tags::KEYWORD,
        ["display", "sound"].iter().map(|s| kw(s)).collect(),
    );
    addn(
        &mut v,
        "ipp-features-supported",
        tags::KEYWORD,
        ["ipp-everywhere", "subscription-object", "document-object"]
            .iter()
            .map(|s| kw(s))
            .collect(),
    );
    add1(
        &mut v,
        "preferred-attributes-supported",
        tags::BOOLEAN,
        Value::Boolean(true),
    );
    add1(
        &mut v,
        "printer-message-from-operator",
        tags::TEXT,
        Value::Text("".into()),
    );
    // `printer-alert`/`printer-supply` are RFC 3995 Printer-MIB-encoded
    // octet strings, not IPP collections.
    add1(
        &mut v,
        "printer-alert",
        tags::STRING,
        Value::OctetString(vec![0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
    );
    add1(
        &mut v,
        "printer-alert-description",
        tags::TEXT,
        Value::Text("ready".into()),
    );
    addn(
        &mut v,
        "reference-uri-schemes-supported",
        tags::URISCHEME,
        ["file", "ftp", "http", "https", "ipp", "ipps"]
            .iter()
            .map(|s| Value::UriScheme((*s).into()))
            .collect(),
    );
    add1(
        &mut v,
        "printer-geo-location",
        tags::UNKNOWN,
        Value::Unknown,
    );
    add1(
        &mut v,
        "printer-organization",
        tags::TEXT,
        Value::Text("".into()),
    );
    add1(
        &mut v,
        "printer-organizational-unit",
        tags::TEXT,
        Value::Text("".into()),
    );
    add1(
        &mut v,
        "printer-supply",
        tags::STRING,
        Value::OctetString(vec![0x01, 0x04, 0xff, 0xff, 0xff, 0xff, 0x00]),
    );
    add1(
        &mut v,
        "printer-supply-description",
        tags::TEXT,
        Value::Text("toner".into()),
    );
    add1(
        &mut v,
        "printer-supply-info-uri",
        tags::URI,
        Value::Uri("https://localhost/supplies".into()),
    );
    add1(
        &mut v,
        "natural-language-configured",
        tags::LANGUAGE,
        Value::NaturalLanguage(ctx.default_language.as_str().into()),
    );
    addn(
        &mut v,
        "notify-attributes-supported",
        tags::KEYWORD,
        [
            "printer-state-change-time",
            "notify-lease-expiration-time",
            "notify-subscriber-user-name",
        ]
        .iter()
        .map(|s| kw(s))
        .collect(),
    );
    add1(
        &mut v,
        "notify-lease-duration-supported",
        tags::RANGE,
        Value::Range {
            low: 0,
            high: if ctx.max_lease_duration == 0 {
                i32::MAX
            } else {
                ctx.max_lease_duration
            },
        },
    );
    add1(
        &mut v,
        "notify-max-events-supported",
        tags::INTEGER,
        Value::Integer(ctx.max_events),
    );
    addn(
        &mut v,
        "notify-events-supported",
        tags::KEYWORD,
        [
            "job-completed",
            "job-config-changed",
            "job-created",
            "job-progress",
            "job-state-changed",
            "job-stopped",
            "printer-added",
            "printer-changed",
            "printer-config-changed",
            "printer-deleted",
            "printer-finishings-changed",
            "printer-media-changed",
            "printer-modified",
            "printer-restarted",
            "printer-shutdown",
            "printer-state-changed",
            "printer-stopped",
            "server-audit",
            "server-restarted",
            "server-started",
            "server-stopped",
        ]
        .iter()
        .map(|s| kw(s))
        .collect(),
    );
    add1(
        &mut v,
        "notify-pull-method-supported",
        tags::KEYWORD,
        kw("ippget"),
    );
    if !ctx.notifiers.is_empty() {
        addn(
            &mut v,
            "notify-schemes-supported",
            tags::KEYWORD,
            ctx.notifiers.iter().map(|n| kw(n)).collect(),
        );
    }
    addn(
        &mut v,
        "number-up-supported",
        tags::INTEGER,
        [1, 2, 4, 6, 9, 16]
            .iter()
            .map(|i| Value::Integer(*i))
            .collect(),
    );
    addn(
        &mut v,
        "number-up-layout-supported",
        tags::KEYWORD,
        [
            "btlr", "btrl", "lrbt", "lrtb", "rlbt", "rltb", "tblr", "tbrl",
        ]
        .iter()
        .map(|s| kw(s))
        .collect(),
    );
    addn(
        &mut v,
        "operations-supported",
        tags::ENUM,
        ctx.operations_supported
            .iter()
            .map(|o| Value::Enum(*o))
            .collect(),
    );
    addn(
        &mut v,
        "orientation-requested-supported",
        tags::ENUM,
        [3, 4, 5, 6].iter().map(|i| Value::Enum(*i)).collect(),
    );
    addn(
        &mut v,
        "page-delivery-supported",
        tags::KEYWORD,
        ["reverse-order", "same-order"]
            .iter()
            .map(|s| kw(s))
            .collect(),
    );
    add1(
        &mut v,
        "page-ranges-supported",
        tags::BOOLEAN,
        Value::Boolean(true),
    );
    add1(
        &mut v,
        "pdf-k-octets-supported",
        tags::RANGE,
        Value::Range {
            low: 0,
            high: K_SUPPORTED,
        },
    );
    addn(
        &mut v,
        "pdf-versions-supported",
        tags::KEYWORD,
        [
            "adobe-1.2",
            "adobe-1.3",
            "adobe-1.4",
            "adobe-1.5",
            "adobe-1.6",
            "adobe-1.7",
            "iso-19005-1_2005",
            "iso-32000-1_2008",
            "pwg-5102.3",
        ]
        .iter()
        .map(|s| kw(s))
        .collect(),
    );
    add1(
        &mut v,
        "pdl-override-supported",
        tags::KEYWORD,
        kw("attempted"),
    );
    add1(
        &mut v,
        "print-as-raster-supported",
        tags::BOOLEAN,
        Value::Boolean(true),
    );
    addn(
        &mut v,
        "print-scaling-supported",
        tags::KEYWORD,
        ["auto", "auto-fit", "fill", "fit", "none"]
            .iter()
            .map(|s| kw(s))
            .collect(),
    );
    add1(
        &mut v,
        "printer-get-attributes-supported",
        tags::KEYWORD,
        kw("document-format"),
    );
    if !ctx.policies.is_empty() {
        addn(
            &mut v,
            "printer-op-policy-supported",
            tags::NAME,
            ctx.policies
                .iter()
                .map(|p| Value::Name(p.as_str().into()))
                .collect(),
        );
    }
    addn(
        &mut v,
        "printer-settable-attributes-supported",
        tags::KEYWORD,
        [
            "printer-geo-location",
            "printer-info",
            "printer-location",
            "printer-organization",
            "printer-organizational-unit",
        ]
        .iter()
        .map(|s| kw(s))
        .collect(),
    );
    add1(
        &mut v,
        "printer-strings-languages-supported",
        tags::LANGUAGE,
        Value::NaturalLanguage(ctx.default_language.as_str().into()),
    );
    add1(
        &mut v,
        "server-is-sharing-printers",
        tags::BOOLEAN,
        Value::Boolean(ctx.sharing),
    );
    addn(
        &mut v,
        "which-jobs-supported",
        tags::KEYWORD,
        [
            "completed",
            "not-completed",
            "aborted",
            "all",
            "canceled",
            "pending",
            "pending-held",
            "processing",
            "processing-stopped",
            "proof-print",
            "fetchable",
        ]
        .iter()
        .map(|s| kw(s))
        .collect(),
    );
    v
}
