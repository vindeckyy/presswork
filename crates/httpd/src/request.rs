//! Parsed HTTP request line + headers + body framing.

use crate::Headers;

/// HTTP version on the request line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpVersion {
    /// `HTTP/0.9` — no version token (upstream still tolerates this).
    V09,
    /// `HTTP/1.0` — close-by-default.
    V10,
    /// `HTTP/1.1` — keep-alive by default, `Host` required.
    V11,
    /// Anything else — cupsd answers `505 Not Supported`.
    Other,
}

/// Request method. Unknown methods parse as `Unknown` and the handler
/// decides (upstream maps unknown → `HTTP_STATUS_ERROR` → 400/501).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// `OPTIONS` — used by RFC 2817 TLS upgrade (`OPTIONS *`).
    Options,
    /// `GET` — static files, CGIs, IPP-over-GET isn't a thing upstream.
    Get,
    /// `HEAD` — like GET, headers only.
    Head,
    /// `POST` — all IPP traffic.
    Post,
    /// `PUT` — document uploads (`Send-Document` uses POST upstream;
    /// PUT is used by `cupsPutFile`-style admin).
    Put,
    /// `DELETE` — admin file ops.
    Delete,
    /// `TRACE` — upstream rejects.
    Trace,
    /// `CONNECT` — upstream rejects.
    Connect,
    /// Anything else.
    Unknown,
}

impl Method {
    /// Parse a method token (case-sensitive, uppercase per RFC 7230;
    /// upstream `httpUpdate()` compares exactly).
    #[must_use]
    pub fn parse(s: &str) -> Self {
        match s {
            "OPTIONS" => Self::Options,
            "GET" => Self::Get,
            "HEAD" => Self::Head,
            "POST" => Self::Post,
            "PUT" => Self::Put,
            "DELETE" => Self::Delete,
            "TRACE" => Self::Trace,
            "CONNECT" => Self::Connect,
            _ => Self::Unknown,
        }
    }

    /// Token used on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Options => "OPTIONS",
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
            Self::Trace => "TRACE",
            Self::Connect => "CONNECT",
            Self::Unknown => "",
        }
    }
}

/// Request body — already buffered (cupsd spools bodies it needs; for
/// IPP the body is decoded in place by `ipp-codec`).
#[derive(Debug)]
pub enum Body {
    /// No body.
    Empty,
    /// Buffered body (`Content-Length` or chunked-decoded).
    Bytes(Vec<u8>),
    /// Body extends to EOF — `Connection: close` semantics. Buffered
    /// here; callers wanting streaming go through the server directly.
    UntilEof(Vec<u8>),
}

impl Body {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        matches!(self, Self::Empty) || self.as_bytes().is_empty()
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Empty => &[],
            Self::Bytes(b) | Self::UntilEof(b) => b,
        }
    }
}

/// A fully-parsed request (headers + body).
#[derive(Debug)]
pub struct Request {
    /// Method.
    pub method: Method,
    /// Raw method token as received (for `Unknown`).
    pub method_token: String,
    /// Request URI — absolute path or absolute URI; also `*` for
    /// `OPTIONS *` (TLS upgrade request).
    pub uri: String,
    /// HTTP version from the request line.
    pub version: HttpVersion,
    /// Header collection.
    pub headers: Headers,
    /// Buffered body.
    pub body: Body,
    /// Whether the client asked for the connection to stay open,
    /// resolved against version + `Connection:` (upstream
    /// `HTTP_KEEPALIVE_*` state).
    pub keep_alive: bool,
    /// Whether the request demands a TLS upgrade (`OPTIONS *` +
    /// `Upgrade: TLS/1.x`, or a resource whose `<Location>` requires
    /// encryption — resolved by the daemon, not the server core).
    pub wants_tls_upgrade: bool,
}

impl Request {
    /// Content type, trimmed (for `application/ipp` dispatch).
    #[must_use]
    pub fn content_type(&self) -> Option<&str> {
        self.headers.get("content-type")
    }

    /// `Content-Length` if present and valid.
    #[must_use]
    pub fn content_length(&self) -> Option<usize> {
        self.headers
            .get("content-length")
            .and_then(|v| v.parse().ok())
    }
}
