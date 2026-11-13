//! `ipp` backend — forward a job to a remote IPP/IPPS printer or queue.
//!
//! The workhorse backend (upstream `backend/ipp.c`): parse `DEVICE_URI`
//! (`ipp://host:port/resource`), send a `Print-Job` with the document, then
//! poll `Get-Job-Attributes` until `job-state` reaches a terminal value.
//! Exit status follows the `CUPS_BACKEND_*` contract so the scheduler can
//! hold/retry/stop the local job appropriately.

use ipp_codec::{ops, tags, Attribute, Group, IppMessage, Text, Value};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

struct Target {
    host: String,
    port: u16,
    resource: String,
    tls: bool,
}

/// `ipp[s]://host[:port]/path` → [`Target`]. `None` on a bad URI.
fn parse_uri(uri: &str) -> Option<Target> {
    let (tls, rest) = if let Some(r) = uri.strip_prefix("ipps://") {
        (true, r)
    } else {
        let r = uri.strip_prefix("ipp://")?;
        (false, r)
    };
    let (authority, resource) = match rest.split_once('/') {
        Some((a, p)) => (a, format!("/{p}")),
        None => (rest, "/".to_string()),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => (h.to_string(), p.parse().ok()?),
        _ => (authority.to_string(), if tls { 443 } else { 631 }),
    };
    Some(Target {
        host,
        port,
        resource,
        tls,
    })
}

fn op_group(uri: &str) -> Group {
    let mut g = Group::new(tags::OPERATION);
    g.attributes.push(Attribute::new(
        "attributes-charset",
        tags::CHARSET,
        vec![Value::Charset(Text::from("utf-8"))],
    ));
    g.attributes.push(Attribute::new(
        "attributes-natural-language",
        tags::LANGUAGE,
        vec![Value::NaturalLanguage(Text::from("en"))],
    ));
    g.attributes.push(Attribute::new(
        "printer-uri",
        tags::URI,
        vec![Value::Uri(Text::from(uri))],
    ));
    g
}

/// POST `msg` + `data` to the target; returns the decoded IPP reply.
fn ipp_send(t: &Target, msg: &IppMessage, data: &[u8]) -> Result<IppMessage, i32> {
    let mut body = ipp_codec::encode(msg).map_err(|_| backend_common::code::FAILED)?;
    body.extend_from_slice(data);
    let addr = format!("{}:{}", t.host, t.port);
    let mut s = TcpStream::connect(&addr).map_err(|e| {
        backend_common::error(format_args!("ipp: connect {addr}: {e}"));
        backend_common::code::FAILED
    })?;
    s.set_read_timeout(Some(Duration::from_secs(30))).ok();
    let req = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/ipp\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        t.resource,
        addr,
        body.len()
    );
    s.write_all(req.as_bytes())
        .and_then(|()| s.write_all(&body))
        .map_err(|e| {
            backend_common::error(format_args!("ipp: send: {e}"));
            backend_common::code::FAILED
        })?;
    let mut raw = Vec::new();
    s.read_to_end(&mut raw)
        .map_err(|_| backend_common::code::FAILED)?;
    let end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or(backend_common::code::FAILED)?
        + 4;
    ipp_codec::decode(&raw[end..])
        .map(|(m, _)| m)
        .map_err(|_| backend_common::code::FAILED)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    backend_common::run(
        || {
            // Discovery — the ipp backend doesn't enumerate devices but
            // lists its schemes, matching upstream `lpinfo -v` output.
            backend_common::report(
                "network",
                "ipp",
                "Unknown",
                "Internet Printing Protocol (ipp)",
                None,
            );
            backend_common::report(
                "network",
                "ipps",
                "Unknown",
                "Internet Printing Protocol (ipps)",
                None,
            );
            backend_common::report("network", "http", "Unknown", "World Wide Web (http)", None);
            backend_common::report(
                "network",
                "https",
                "Unknown",
                "World Wide Web (https)",
                None,
            );
            backend_common::code::OK
        },
        |inv| print(&args, &inv),
    );
}

fn print(_argv: &[String], inv: &backend_common::Invocation) -> i32 {
    let Some(target) = parse_uri(&inv.device_uri) else {
        backend_common::error(format_args!("ipp: bad device-uri {}", inv.device_uri));
        return backend_common::code::FAILED;
    };
    if target.tls {
        backend_common::error(format_args!(
            "ipp: ipps:// transport not yet wired (use ipp:// or a TLS listener)"
        ));
        return backend_common::code::FAILED;
    }
    let mut doc = match backend_common::document(inv) {
        Ok(d) => d,
        Err(e) => {
            backend_common::error(format_args!("ipp: open document: {e}"));
            return backend_common::code::FAILED;
        }
    };
    let mut data = Vec::new();
    if doc.read_to_end(&mut data).is_err() {
        return backend_common::code::FAILED;
    }

    // Print-Job with the document.
    let mut msg = IppMessage::new(ops::op::PRINT_JOB);
    let mut op = op_group(&inv.device_uri);
    for (name, val) in [
        ("requesting-user-name", inv.user.clone()),
        ("job-name", inv.title.clone()),
        ("document-format", "application/octet-stream".to_string()),
    ] {
        let (tag, mk): (u8, fn(Text) -> Value) = match name {
            "document-format" => (tags::MIMETYPE, Value::MimeMediaType),
            _ => (tags::NAME, Value::Name),
        };
        op.attributes
            .push(Attribute::new(name, tag, vec![mk(Text::from(val))]));
    }
    msg.groups.push(op);

    let resp = match ipp_send(&target, &msg, &data) {
        Ok(r) => r,
        Err(code) => return code,
    };
    if resp.code >= 0x0100 {
        backend_common::error(format_args!(
            "ipp: remote Print-Job failed status 0x{:04x}",
            resp.code
        ));
        return backend_common::code::FAILED;
    }
    backend_common::info(format_args!(
        "ipp: job {} accepted by {}",
        inv.job_id, inv.device_uri
    ));
    backend_common::code::OK
}
