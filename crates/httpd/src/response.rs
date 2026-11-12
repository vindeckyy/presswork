//! HTTP response emission — status line, headers, body.

use crate::Headers;

/// Status codes cupsd actually emits (upstream `HTTP_STATUS_*`);
/// `as_u16` covers the wire value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusCode(pub u16);

impl StatusCode {
    /// `100 Continue`.
    pub const CONTINUE: Self = Self(100);
    /// `101 Switching Protocols` — RFC 2817 TLS upgrade ack.
    pub const SWITCHING_PROTOCOLS: Self = Self(101);
    /// `200 OK`.
    pub const OK: Self = Self(200);
    /// `201 Created`.
    pub const CREATED: Self = Self(201);
    /// `204 No Content`.
    pub const NO_CONTENT: Self = Self(204);
    /// `206 Partial Content` — `Range:` on static files.
    pub const PARTIAL_CONTENT: Self = Self(206);
    /// `304 Not Modified`.
    pub const NOT_MODIFIED: Self = Self(304);
    /// `400 Bad Request`.
    pub const BAD_REQUEST: Self = Self(400);
    /// `401 Unauthorized` — HTTP-level auth challenge.
    pub const UNAUTHORIZED: Self = Self(401);
    /// `403 Forbidden`.
    pub const FORBIDDEN: Self = Self(403);
    /// `404 Not Found`.
    pub const NOT_FOUND: Self = Self(404);
    /// `405 Method Not Allowed`.
    pub const METHOD_NOT_ALLOWED: Self = Self(405);
    /// `413 Content Too Large` (upstream `HTTP_STATUS_REQUEST_TOO_LARGE`).
    pub const TOO_LARGE: Self = Self(413);
    /// `417 Expectation Failed`.
    pub const EXPECTATION_FAILED: Self = Self(417);
    /// `426 Upgrade Required`.
    pub const UPGRADE_REQUIRED: Self = Self(426);
    /// `500 Internal Server Error`.
    pub const INTERNAL: Self = Self(500);
    /// `501 Not Implemented`.
    pub const NOT_IMPLEMENTED: Self = Self(501);
    /// `505 HTTP Version Not Supported`.
    pub const VERSION_NOT_SUPPORTED: Self = Self(505);
}

/// Reason phrase — upstream `httpStatus()` table, the subset cupsd
/// emits (plus generic "code NNN" fallback which upstream does too).
#[must_use]
pub fn reason_phrase(code: u16) -> String {
    match code {
        100 => "Continue",
        101 => "Switching Protocols",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        411 => "Length Required",
        413 => "Request Entity Too Large",
        414 => "URI Too Long",
        417 => "Expectation Failed",
        426 => "Upgrade Required",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        505 => "HTTP Version Not Supported",
        n => return format!("Status {n}"),
    }
    .to_string()
}

/// An HTTP response: status + headers + optional body.
#[derive(Debug)]
pub struct Response {
    /// Status code.
    pub status: StatusCode,
    /// Response headers (`Content-Length`/`Transfer-Encoding` computed
    /// at emission if not set).
    pub headers: Headers,
    /// Body bytes (empty for HEAD/304).
    pub body: Vec<u8>,
}

impl Response {
    /// Bare status response (no body).
    #[must_use]
    pub fn status(status: StatusCode) -> Self {
        Self {
            status,
            headers: Headers::new(),
            body: Vec::new(),
        }
    }

    /// Body-carrying response.
    #[must_use]
    pub fn with_body(status: StatusCode, content_type: &str, body: Vec<u8>) -> Self {
        let mut r = Self::status(status);
        r.headers.set("Content-Type", content_type);
        r.body = body;
        r
    }

    /// IPP response — `application/ipp`.
    #[must_use]
    pub fn ipp(status: StatusCode, body: Vec<u8>) -> Self {
        Self::with_body(status, "application/ipp", body)
    }

    /// Serialize onto the wire. `keep_alive` determines `Connection:`
    /// emission (upstream only sends `Connection: close` when closing
    /// — HTTP/1.1 clients assume persistence).
    #[must_use]
    pub fn encode(&self, head_only: bool, keep_alive: bool) -> Vec<u8> {
        let mut out = Vec::with_capacity(256 + self.body.len());
        out.extend_from_slice(
            format!(
                "HTTP/1.1 {} {}\r\n",
                self.status.0,
                reason_phrase(self.status.0)
            )
            .as_bytes(),
        );
        let mut saw_len = false;
        let mut saw_conn = false;
        for (n, v) in self.headers.iter() {
            if n.eq_ignore_ascii_case("content-length") {
                saw_len = true;
            }
            if n.eq_ignore_ascii_case("connection") {
                saw_conn = true;
            }
            out.extend_from_slice(format!("{n}: {v}\r\n").as_bytes());
        }
        if !saw_len {
            out.extend_from_slice(format!("Content-Length: {}\r\n", self.body.len()).as_bytes());
        }
        if !saw_conn && !keep_alive {
            out.extend_from_slice(b"Connection: close\r\n");
        }
        out.extend_from_slice(b"\r\n");
        if !head_only {
            out.extend_from_slice(&self.body);
        }
        out
    }
}
