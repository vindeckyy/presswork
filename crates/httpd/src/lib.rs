//! `httpd` — the HTTP/1.1 server core shared by `cupsd`.
//!
//! Mirrors the client-connection semantics of upstream
//! `scheduler/client.c`: request-line + header parsing,
//! `Transfer-Encoding: chunked` and `Content-Length` request bodies,
//! `Expect: 100-continue`, persistent connections (HTTP/1.1 default,
//! HTTP/1.0 with `Connection: keep-alive`), `Host` enforcement on 1.1,
//! and an RFC 2817 `Upgrade: TLS/1.x` seam (the daemon wraps the
//! transport when the config demands encryption).
//!
//! Transport-agnostic: works over any `AsyncRead + AsyncWrite`, so the
//! same code serves plain TCP, unix sockets, and (later) rustls
//! streams.

#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]

mod headers;
mod request;
mod response;
mod server;

pub use headers::Headers;
pub use request::{Body, HttpVersion, Method, Request};
pub use response::{Response, StatusCode};
pub use server::{serve_connection, ServeError, ServerOptions};

/// Maximum request line + header block size (cupsd uses `HTTP_MAX_VALUE`
/// 256 per line; total header block is bounded at 32 KiB here — the
/// practical limit upstream applies via `MaxRequestSize` is on the body).
pub const MAX_HEADER_BLOCK: usize = 32 * 1024;

/// Maximum body we will spool when `MaxRequestSize` is not configured
/// (upstream default 0 = unlimited; we retain that).
pub const DEFAULT_MAX_BODY: usize = 0;
