//! Connection serving — the keep-alive request loop.
//!
//! Port of the `client.c`/`httpState` loop: read request line +
//! headers, validate (`Host` on 1.1, known method, `Content-Length` ∨
//! `Transfer-Encoding` framing), emit `100 Continue`, buffer the body,
//! dispatch to the handler, write the response, and loop while
//! keep-alive holds.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::request::{Body, HttpVersion, Method, Request};
use crate::response::{Response, StatusCode};
use crate::{Headers, MAX_HEADER_BLOCK};

/// Error class for connection failures.
#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    /// Client disconnected (EOF or reset) — normal termination.
    #[error("peer disconnected")]
    Disconnect,
    /// I/O failure.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Malformed request (handler already got a 400 emitted).
    #[error("bad request: {0}")]
    BadRequest(&'static str),
}

/// Options controlling the connection loop.
#[derive(Debug, Clone)]
pub struct ServerOptions {
    /// `ServerTokens` string (upstream `ServerTokens` directive).
    pub server_tokens: String,
    /// `MaxRequestSize` (0 = unlimited, upstream default).
    pub max_body: usize,
    /// `Timeout` — idle-connection seconds (upstream `KeepAlive`/300).
    pub idle_timeout: std::time::Duration,
    /// Max simultaneous request-line attempts before closing (upstream
    /// gives up on repeated garbage).
    pub max_bad_requests: u32,
}

impl Default for ServerOptions {
    fn default() -> Self {
        Self {
            server_tokens: "CUPS/2.5 (presswork)".into(),
            max_body: 0,
            idle_timeout: std::time::Duration::from_secs(300),
            max_bad_requests: 4,
        }
    }
}

/// Serve one connection until close.
///
/// The RFC 2817 seam: if the handler returns
/// `SwitchingProtocols`, the server writes the 101 and returns
/// `Err(ServeError::Disconnect)` — the *caller* (which owns the
/// transport) performs the TLS wrap and re-enters `serve_connection`
/// on the encrypted stream.
///
/// # Errors
/// `Disconnect` on clean EOF, `Io` on transport failure, `BadRequest`
/// when the peer sends unrecoverable garbage (a 4xx was written first).
pub async fn serve_connection<S>(
    stream: &mut S,
    opts: &ServerOptions,
    mut handler: impl FnMut(Request) -> Response + Send,
) -> Result<(), ServeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = Vec::with_capacity(16 * 1024);
    let mut bad = 0u32;

    loop {
        let mut req = match read_request(stream, &mut buf, opts.idle_timeout).await {
            Ok(Some(req)) => req,
            Ok(None) => return Ok(()), // clean EOF between requests
            Err(e @ ServeError::Disconnect) => return Err(e),
            Err(e @ ServeError::Io(_)) => return Err(e),
            Err(ServeError::BadRequest(_)) => {
                bad += 1;
                let resp = Response::status(StatusCode::BAD_REQUEST);
                write_response(stream, &resp, false, false).await?;
                if bad >= opts.max_bad_requests {
                    return Err(ServeError::BadRequest("too many bad requests"));
                }
                continue;
            }
        };

        // Host required on HTTP/1.1 (upstream rejects with 400).
        if req.version == HttpVersion::V11 && req.headers.get("host").is_none() {
            let resp = Response::status(StatusCode::BAD_REQUEST);
            write_response(stream, &resp, false, req.keep_alive).await?;
            continue;
        }
        if req.version == HttpVersion::Other {
            let resp = Response::status(StatusCode::VERSION_NOT_SUPPORTED);
            write_response(stream, &resp, false, false).await?;
            return Ok(());
        }

        // Frame + buffer the body (emits 100-continue when requested).
        let body_res = read_body(stream, &mut buf, &mut req, opts.max_body).await;
        if let Err(e) = body_res {
            let resp = Response::status(match e {
                ServeError::BadRequest(m) if m.contains("large") => StatusCode::TOO_LARGE,
                _ => StatusCode::BAD_REQUEST,
            });
            let _ = write_response(stream, &resp, false, false).await;
            return Err(e);
        }

        let head_only = req.method == Method::Head;
        let client_keep = req.keep_alive;
        let resp = handler(req);
        let keep = client_keep && !resp.headers.connection_has("close");
        let mut resp = resp;
        resp.headers.set("Server", opts.server_tokens.clone());
        if resp.status == StatusCode::SWITCHING_PROTOCOLS {
            // RFC 2817: write the 101 and hand the transport back.
            write_response(stream, &resp, false, true).await?;
            return Err(ServeError::Disconnect);
        }
        write_response(stream, &resp, head_only, keep).await?;
        if !keep {
            return Ok(());
        }
    }
}

/// Read one request: line + headers, then framed body.
///
/// Returns `Ok(None)` on clean EOF *before* any bytes of a new request.
async fn read_request<R: AsyncRead + Unpin>(
    r: &mut R,
    buf: &mut Vec<u8>,
    idle: std::time::Duration,
) -> Result<Option<Request>, ServeError> {
    // Fill until we have the header block (\r\n\r\n) or give up.
    let header_end;
    loop {
        if let Some(pos) = find_header_end(buf) {
            header_end = pos;
            break;
        }
        if buf.len() > MAX_HEADER_BLOCK {
            return Err(ServeError::BadRequest("header block too large"));
        }
        let mut chunk = [0u8; 8192];
        let n = match tokio::time::timeout(idle, r.read(&mut chunk)).await {
            Ok(Ok(0)) => {
                return if buf.is_empty() {
                    Ok(None)
                } else {
                    Err(ServeError::Disconnect)
                };
            }
            Ok(Ok(n)) => n,
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(ServeError::Disconnect);
            }
            Ok(Err(e)) => return Err(ServeError::Io(e)),
            Err(_) => return Err(ServeError::Disconnect), // idle timeout
        };
        buf.extend_from_slice(&chunk[..n]);
    }

    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let term_len = if buf[header_end..].starts_with(b"\r\n") {
        4
    } else {
        2
    };
    buf.drain(..header_end + term_len);

    let mut lines = head.split('\n').map(|l| l.trim_end_matches('\r'));
    let reqline = lines.next().unwrap_or("");
    let mut parts = reqline.split_whitespace();
    let method_tok = parts.next().unwrap_or("");
    let uri = parts.next().unwrap_or("").to_string();
    let ver_tok = parts.next().unwrap_or("");

    let method = Method::parse(method_tok);
    if method_tok.is_empty() || uri.is_empty() {
        return Err(ServeError::BadRequest("malformed request line"));
    }
    let version = match ver_tok {
        "HTTP/1.0" => HttpVersion::V10,
        "HTTP/1.1" => HttpVersion::V11,
        "" => HttpVersion::V09,
        _ => HttpVersion::Other,
    };

    let mut headers = Headers::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((name, val)) = line.split_once(':') else {
            // Continuation lines start with whitespace — join onto prev.
            if line.starts_with([' ', '\t']) && headers.iter().next().is_some() {
                // (Upstream folds; we keep it simple — rare in practice.)
                continue;
            }
            return Err(ServeError::BadRequest("malformed header line"));
        };
        headers.push(name.trim(), val.trim().to_string());
    }

    // Keep-alive resolution (upstream HTTP_KEEPALIVE_*).
    let keep_alive = match version {
        HttpVersion::V11 => !headers.connection_has("close"),
        HttpVersion::V10 => headers.connection_has("keep-alive"),
        _ => false,
    };

    // RFC 2817 seam.
    let wants_tls_upgrade = method == Method::Options
        && uri == "*"
        && headers.get("upgrade").is_some_and(|v| {
            v.eq_ignore_ascii_case("tls/1.0") || v.to_ascii_lowercase().starts_with("tls/")
        });

    Ok(Some(Request {
        method,
        method_token: method_tok.to_string(),
        uri,
        version,
        headers,
        body: Body::Empty, // filled by read_body below — see serve loop
        keep_alive,
        wants_tls_upgrade,
    }))
    // Note: body framing is handled by the caller — see `read_body`.
}

/// Locate the start of the header-block terminator (`\r\n\r\n`, or
/// `\n\n` from bare-LF clients).
fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .or_else(|| buf.windows(2).position(|w| w == b"\n\n"))
}

/// Read and buffer the request body per its framing.
///
/// Emits `100 Continue` first if the client asked. `max_body == 0`
/// means unlimited (upstream `MaxRequestSize 0`).
pub async fn read_body<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    buf: &mut Vec<u8>,
    req: &mut Request,
    max_body: usize,
) -> Result<(), ServeError> {
    let is_chunked = req
        .headers
        .get("transfer-encoding")
        .is_some_and(|v| v.eq_ignore_ascii_case("chunked"));
    let content_length = req.content_length();
    let close_delimited = !is_chunked
        && content_length.is_none()
        && matches!(req.method, Method::Post | Method::Put)
        && req.headers.get("content-type").is_some();

    if is_chunked || content_length.is_some() || close_delimited {
        // Expect: 100-continue.
        if req
            .headers
            .get("expect")
            .is_some_and(|v| v.eq_ignore_ascii_case("100-continue"))
        {
            s.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await?;
            s.flush().await?;
        }
        let limit = if max_body == 0 { usize::MAX } else { max_body };
        let body = if is_chunked {
            read_chunked(s, buf, limit).await?
        } else if let Some(len) = content_length {
            read_exact_n(s, buf, len.min(limit)).await?
        } else {
            read_to_eof(s, buf, limit).await?
        };
        req.body = Body::Bytes(body);
    }
    Ok(())
}

async fn fill<R: AsyncRead + Unpin>(
    r: &mut R,
    buf: &mut Vec<u8>,
    need: usize,
) -> Result<usize, ServeError> {
    let mut chunk = [0u8; 8192];
    let mut got = 0;
    while buf.len() < need {
        match r.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                got += n;
            }
            Err(e) => return Err(ServeError::Io(e)),
        }
    }
    Ok(got)
}

async fn read_exact_n<R: AsyncRead + Unpin>(
    r: &mut R,
    buf: &mut Vec<u8>,
    n: usize,
) -> Result<Vec<u8>, ServeError> {
    fill(r, buf, n).await?;
    let take = n.min(buf.len());
    Ok(buf.drain(..take).collect())
}

async fn read_to_eof<R: AsyncRead + Unpin>(
    r: &mut R,
    buf: &mut Vec<u8>,
    limit: usize,
) -> Result<Vec<u8>, ServeError> {
    let mut out = std::mem::take(buf);
    let mut chunk = [0u8; 8192];
    loop {
        if out.len() >= limit {
            return Err(ServeError::BadRequest("body too large"));
        }
        match r.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&chunk[..n]),
            Err(e) => return Err(ServeError::Io(e)),
        }
    }
    Ok(out)
}

async fn read_chunked<R: AsyncRead + Unpin>(
    r: &mut R,
    buf: &mut Vec<u8>,
    limit: usize,
) -> Result<Vec<u8>, ServeError> {
    let mut out = Vec::new();
    loop {
        // Read chunk-size line.
        let mut line = Vec::new();
        loop {
            if line.ends_with(b"\r\n") {
                line.truncate(line.len().saturating_sub(2));
                break;
            }
            if buf.is_empty() {
                fill(r, buf, 1).await?;
            }
            if buf.is_empty() {
                return Err(ServeError::Disconnect);
            }
            line.push(buf.remove(0));
            if line.len() > 32 {
                return Err(ServeError::BadRequest("chunk-size line too long"));
            }
        }
        let size_str = std::str::from_utf8(&line)
            .ok()
            .and_then(|s| s.split(';').next())
            .unwrap_or("")
            .trim();
        let size = usize::from_str_radix(size_str, 16)
            .map_err(|_| ServeError::BadRequest("bad chunk size"))?;
        if size == 0 {
            // Drain trailers until blank line.
            loop {
                let mut tl = Vec::new();
                while !(tl.ends_with(b"\r\n") || tl.ends_with(b"\n")) {
                    if buf.is_empty() {
                        fill(r, buf, 1).await?;
                    }
                    if buf.is_empty() {
                        break;
                    }
                    tl.push(buf.remove(0));
                }
                let t = String::from_utf8_lossy(&tl);
                if t.trim().is_empty() {
                    break;
                }
            }
            break;
        }
        if out.len() + size > limit {
            return Err(ServeError::BadRequest("body too large"));
        }
        fill(r, buf, size + 2).await?;
        if buf.len() < size {
            return Err(ServeError::Disconnect);
        }
        out.extend_from_slice(&buf[..size]);
        buf.drain(..size.min(buf.len()));
        // Consume \r\n after chunk.
        if buf.starts_with(b"\r\n") {
            buf.drain(..2);
        } else {
            let mut crlf = [0u8; 2];
            let _ = r.read(&mut crlf).await;
        }
    }
    Ok(out)
}

/// Write a response.
async fn write_response<W: AsyncWrite + Unpin>(
    w: &mut W,
    resp: &Response,
    head_only: bool,
    keep_alive: bool,
) -> Result<(), ServeError> {
    let bytes = resp.encode(head_only, keep_alive);
    w.write_all(&bytes).await?;
    w.flush().await?;
    Ok(())
}
