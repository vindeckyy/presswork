//! sys — the only workspace crate permitted to contain `unsafe` code:
//! NSS lookups, privilege drop, fd plumbing, rlimits, exec, syslog.
//!
//! Everything else in the workspace is `#![forbid(unsafe_code)]`.
//! Keep this crate small and audit-friendly.

#![deny(clippy::undocumented_unsafe_blocks)]

use std::ffi::CString;

/// Look up a group id by name (`getgrnam`).
///
/// Returns `None` if the group does not exist or lookup fails.
#[cfg(unix)]
#[must_use]
pub fn gid_of(name: &str) -> Option<u32> {
    let c = CString::new(name).ok()?;
    // SAFETY: `getgrnam` returns a pointer to static storage or NULL.
    // We only read `gr_gid` and copy it out; NSS modules may not be
    // thread-safe in exotic configurations, which matches cupsd's own
    // usage (it calls getgrnam during config load).
    unsafe {
        let g = libc::getgrnam(c.as_ptr());
        if g.is_null() {
            None
        } else {
            Some((*g).gr_gid)
        }
    }
}

/// Look up a user id by name (`getpwnam`).
///
/// Returns `None` if the user does not exist or lookup fails.
#[cfg(unix)]
#[must_use]
pub fn uid_of(name: &str) -> Option<u32> {
    let c = CString::new(name).ok()?;
    // SAFETY: see `gid_of` — static storage, read `pw_uid` only.
    unsafe {
        let p = libc::getpwnam(c.as_ptr());
        if p.is_null() {
            None
        } else {
            Some((*p).pw_uid)
        }
    }
}

/// Look up a user name by id (`getpwuid`).
#[cfg(unix)]
#[must_use]
pub fn name_of_uid(uid: u32) -> Option<String> {
    // SAFETY: see `gid_of` — copies the name out of static storage.
    unsafe {
        let p = libc::getpwuid(uid);
        if p.is_null() {
            None
        } else {
            Some(
                std::ffi::CStr::from_ptr((*p).pw_name)
                    .to_string_lossy()
                    .into_owned(),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_lookup() {
        assert_eq!(uid_of("root"), Some(0));
        assert_eq!(gid_of("root"), Some(0));
        assert_eq!(name_of_uid(0).as_deref(), Some("root"));
    }

    #[test]
    fn missing_lookup() {
        assert_eq!(uid_of("definitely-not-a-user-xyz"), None);
    }
}
