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

/// Group names a user belongs to (`getgrouplist` + `getgrgid`).
pub fn groups_of(user: &str) -> Vec<String> {
    use std::ffi::CString;
    let Some(c) = CString::new(user).ok() else {
        return Vec::new();
    };
    unsafe {
        let pw = libc::getpwnam(c.as_ptr());
        if pw.is_null() {
            return Vec::new();
        }
        let mut n: libc::c_int = 0;
        // size probe
        libc::getgrouplist(c.as_ptr(), (*pw).pw_gid, std::ptr::null_mut(), &mut n);
        if n <= 0 {
            n = 16;
        }
        let mut gids = vec![0u32; n as usize];
        let mut got = n;
        if libc::getgrouplist(c.as_ptr(), (*pw).pw_gid, gids.as_mut_ptr(), &mut got) < 0 {
            return Vec::new();
        }
        gids.truncate(got.max(0) as usize);
        gids.iter()
            .filter_map(|&gid| {
                let g = libc::getgrgid(gid);
                if g.is_null() {
                    None
                } else {
                    Some(
                        std::ffi::CStr::from_ptr((*g).gr_name)
                            .to_string_lossy()
                            .into_owned(),
                    )
                }
            })
            .collect()
    }
}

/// Verify a local password against the shadow entry (`getspnam`+`crypt`).
/// Returns `false` for unknown users or when shadow is unreadable (non-root).
pub fn check_password(user: &str, pass: &str) -> bool {
    use std::ffi::CString;
    let (Some(cu), Some(cp)) = (CString::new(user).ok(), CString::new(pass).ok()) else {
        return false;
    };
    unsafe {
        let sp = libc::getspnam(cu.as_ptr());
        if sp.is_null() {
            return false;
        }
        #[link(name = ":libcrypt.so.1")]
        extern "C" {
            fn crypt(key: *const libc::c_char, salt: *const libc::c_char) -> *mut libc::c_char;
        }
        let hashed = crypt(cp.as_ptr(), (*sp).sp_pwdp);
        if hashed.is_null() {
            return false;
        }
        let got = std::ffi::CStr::from_ptr(hashed);
        let want = std::ffi::CStr::from_ptr((*sp).sp_pwdp);
        // constant-time compare
        let (a, b) = (got.to_bytes(), want.to_bytes());
        a.len() == b.len() && a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
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

/// systemd socket activation (`sd_listen_fds(3)`): when `LISTEN_PID`
/// equals our pid and `LISTEN_FDS` is set, systemd has passed pre-bound
/// listener sockets on fds 3..=3+N-1. Return them as owned fds so the
/// daemon can adopt them instead of binding its own. Empty when the
/// daemon was started directly (no activation).
///
/// # Safety
/// This takes ownership of the inherited descriptors exactly once —
/// callers must not use the raw fd numbers again after this call.
#[cfg(unix)]
#[must_use]
pub fn sd_listen_fds() -> Vec<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;
    let pid_ok = std::env::var("LISTEN_PID")
        .ok()
        .and_then(|p| p.parse::<u32>().ok())
        .is_some_and(|p| p == std::process::id());
    if !pid_ok {
        return Vec::new();
    }
    let n: i32 = std::env::var("LISTEN_FDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
        .max(0);
    let mut out = Vec::with_capacity(n as usize);
    for i in 0..n {
        let fd = 3 + i;
        // SAFETY: systemd guarantees fds 3..3+n are open, valid listening
        // sockets belonging to this process. Taking ownership once is the
        // documented activation contract; we never touch the numbers after.
        let owned = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
        out.push(owned);
    }
    out
}

/// `getsockname(2)` `sa_family` for an fd — `AF_UNIX` vs `AF_INET`/`INET6`.
/// Returns the family constant, or `-1` on error.
#[cfg(unix)]
#[must_use]
pub fn socket_family(fd: std::os::fd::RawFd) -> i32 {
    let mut ss: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    // SAFETY: `ss`/`len` are valid out-params; `fd` is an open socket.
    let rc = unsafe {
        libc::getsockname(fd, &mut ss as *mut _ as *mut libc::sockaddr, &mut len)
    };
    if rc == 0 {
        i32::from(ss.ss_family)
    } else {
        -1
    }
}
