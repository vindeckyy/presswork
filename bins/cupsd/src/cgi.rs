//! Web UI CGI passthrough — a port of `scheduler/client.c`'s CGI dispatch
//! (`cupsdSendCommand`) + `cups/cgi.c`'s process contract.
//!
//! The stock CUPS web interface is a set of external binaries in
//! `{ServerBin}/cgi-bin/*.cgi`. We map request URIs to those binaries, spawn
//! them with the RFC 3875 CGI/1.1 environment, feed the request body on
//! stdin, and translate the CGI output headers into an HTTP response. When
//! the binaries aren't installed the URI falls through to static files.

use httpd::{Method, Request, Response, StatusCode};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Map a request URI to its CGI binary + the `options` string (the part of
/// the URI after the path prefix — upstream `con->options`). `None` when the
/// URI isn't a CGI route.
pub fn map_uri(uri: &str) -> Option<(&'static str, &str)> {
    // Order matters — upstream checks prefixes in this sequence.
    let path = uri;
    let (prefix, script) = if path == "/" || path.starts_with("/?") {
        ("", "home.cgi")
    } else if let Some(p) = path.strip_prefix("/admin") {
        (p, "admin.cgi")
    } else if let Some(p) = path.strip_prefix("/classes") {
        (p, "classes.cgi")
    } else if let Some(p) = path.strip_prefix("/jobs") {
        (p, "jobs.cgi")
    } else if let Some(p) = path.strip_prefix("/printers") {
        (p, "printers.cgi")
    } else if let Some(p) = path.strip_prefix("/help") {
        (p, "help.cgi")
    } else {
        return None;
    };
    // Strip the leading '/' between the prefix and the remainder.
    let options = prefix.strip_prefix('/').unwrap_or(prefix);
    Some((script, options))
}

/// The `{ServerBin}/cgi-bin` directory.
pub fn cgi_root(server_bin: &Path) -> PathBuf {
    server_bin.join("cgi-bin")
}

/// `cupsdSendCommand` — run a CGI binary and capture its response.
///
/// `req`'s body becomes the CGI's stdin (POST forms). The CGI's stdout is
/// parsed: a `Status:` header sets the code, `Content-Type:` the type, and
/// everything after the blank line is the body. A nonexistent/failed binary
/// yields `None` so the caller can fall back to static files.
pub fn run(
    server_bin: &Path,
    script: &str,
    options: &str,
    req: &Request,
    client_addr: std::net::IpAddr,
    host: &str,
    port: u16,
    encrypted: bool,
) -> Option<Response> {
    let bin = cgi_root(server_bin).join(script);
    if !bin.is_file() {
        return None;
    }
    // `is_cgi`: QUERY_STRING is the part of the URI after the first `?`
    // (the `?` itself is stripped via `options ++`). `options` is the
    // prefix-remainder used for PATH_INFO + positional argv.
    let query_string = req.uri.split_once('?').map(|(_, q)| q).unwrap_or("");
    let mut cmd = std::process::Command::new(&bin);
    cmd.env("GATEWAY_INTERFACE", "CGI/1.1")
        .env("SERVER_SOFTWARE", "CUPS/2.5")
        .env("SERVER_NAME", host)
        .env("SERVER_PORT", port.to_string())
        .env("SERVER_PROTOCOL", "HTTP/1.1")
        .env("REQUEST_METHOD", req.method.as_str())
        .env("SCRIPT_NAME", format!("/cgi-bin/{script}"))
        .env("PATH_INFO", options)
        .env("QUERY_STRING", query_string)
        .env("REMOTE_ADDR", client_addr.to_string())
        .env("REMOTE_USER", "")
        .env("AUTH_TYPE", "")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
    if encrypted {
        cmd.env("HTTPS", "on");
    }
    // `pipe_command` splits `command options` on whitespace into argv —
    // argv[0] is the script, the options become positional args.
    for arg in options.split_whitespace() {
        cmd.arg(arg);
    }
    if let Some(ct) = req.content_type() {
        cmd.env("CONTENT_TYPE", ct);
    }
    let body = req.body.as_bytes();
    if !body.is_empty() {
        cmd.env("CONTENT_LENGTH", body.len().to_string());
    }
    for (name, value) in req.headers.iter() {
        // HTTP_FOO from each request header (skip hop-by-hop).
        let key = name
            .chars()
            .map(|c| if c == '-' { '_' } else { c.to_ascii_uppercase() })
            .collect::<String>();
        cmd.env(format!("HTTP_{key}"), value);
    }

    let mut child = cmd.spawn().ok()?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(body);
        drop(stdin);
    }
    let out = child.wait_with_output().ok()?;
    Some(parse_output(&out.stdout))
}

/// Split CGI output into a [`Response`]: `Status:`/`Content-Type:` headers,
/// blank line, then body. Defaults `200`/`text/html`.
fn parse_output(bytes: &[u8]) -> Response {
    let sep = bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .or_else(|| bytes.windows(2).position(|w| w == b"\n\n"));
    let (head, body) = match sep {
        Some(i) => {
            let skip = if &bytes[i..i + 4] == b"\r\n\r\n" { 4 } else { 2 };
            (&bytes[..i], &bytes[i + skip..])
        }
        None => (bytes, &[][..]),
    };
    let mut status = 200u16;
    let mut ctype = "text/html".to_string();
    for line in std::str::from_utf8(head).unwrap_or("").lines() {
        let line = line.trim_end_matches('\r');
        if let Some(v) = line.strip_prefix("Status:") {
            status = v.trim().split_whitespace().next().and_then(|n| n.parse().ok()).unwrap_or(200);
        } else if let Some(v) = line.strip_prefix("Content-Type:") {
            ctype = v.trim().to_string();
        }
    }
    let code = StatusCode(status);
    let mut r = Response::with_body(code, &ctype, body.to_vec());
    // CGI `Location:` → redirect support.
    if let Some(loc) = std::str::from_utf8(head)
        .ok()
        .and_then(|h| h.lines().find_map(|l| l.strip_prefix("Location:")))
    {
        r.headers.set("Location", loc.trim());
        if status == 200 {
            r.status = StatusCode(302);
        }
    }
    r
}

/// Route a GET/POST to CGI when it maps; `None` → caller falls back.
pub fn dispatch(
    uri: &str,
    server_bin: &Path,
    req: &Request,
    client_addr: std::net::IpAddr,
    host: &str,
    port: u16,
    encrypted: bool,
) -> Option<Response> {
    let (script, options) = map_uri(uri)?;
    if req.method == Method::Post && script == "home.cgi" {
        return None; // POST goes to CGIs that accept it; home doesn't.
    }
    run(server_bin, script, options, req, client_addr, host, port, encrypted)
}
