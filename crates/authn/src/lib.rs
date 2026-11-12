//! Authentication — HTTP `Authorization` parsing + credential verification
//! (`scheduler/auth.c`'s Basic layer; Kerberos/OAuth are feature-gated).
//!
//! Basic auth decodes `Authorization: Basic base64(user:pass)` and verifies
//! against the local password database via `sys::check_password` (shadow
//! `crypt`), matching cupsd's PAM-backed `BasicAuth` semantics.

use base64::Engine;
use std::fmt::Write as _;

/// Decoded `Authorization` credentials.
#[derive(Debug, Clone)]
pub struct Credentials {
    /// `Basic`, `Bearer`, `Negotiate`…
    pub scheme: String,
    /// Username (Basic) or token (Bearer).
    pub user: String,
    /// Password/secret (Basic) — kept out of `Debug` output.
    pub secret: String,
}

/// Parse an `Authorization` header value.
#[must_use]
pub fn parse(header: &str) -> Option<Credentials> {
    let (scheme, rest) = header.split_once(' ')?;
    if scheme.eq_ignore_ascii_case("basic") {
        let dec = base64::engine::general_purpose::STANDARD
            .decode(rest.trim())
            .ok()?;
        let s = String::from_utf8(dec).ok()?;
        let (u, p) = s.split_once(':')?;
        Some(Credentials {
            scheme: "Basic".into(),
            user: u.to_string(),
            secret: p.to_string(),
        })
    } else {
        // Bearer/Negotiate: token only, no local password.
        Some(Credentials {
            scheme: scheme.to_string(),
            user: String::new(),
            secret: rest.trim().to_string(),
        })
    }
}

/// Verify credentials and return the authenticated username + groups.
/// `Basic` → `sys::check_password`; other schemes → `None` (P4 = Basic only).
#[must_use]
pub fn authenticate(creds: &Credentials) -> Option<(String, Vec<String>)> {
    if !creds.scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    if !sys::check_password(&creds.user, &creds.secret) {
        return None;
    }
    Some((creds.user.clone(), sys::groups_of(&creds.user)))
}

/// `Basic realm="…"` challenge for a 401 response.
#[must_use]
pub fn basic_challenge(realm: &str) -> String {
    let mut s = String::new();
    let _ = write!(s, "Basic realm=\"{realm}\"");
    s
}
