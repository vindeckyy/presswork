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
#[must_use]
pub fn groups_of(user: &str) -> Vec<String> {
    use std::ffi::CString;
    let Some(c) = CString::new(user).ok() else {
        return Vec::new();
    };
    // SAFETY: `c` is a valid NUL-terminated CString; the returned `pw` is a
    // static getpwnam buffer read before any subsequent libc call that could
    // clobber it; `gids` is a live buffer of `n` elements for getgrouplist.
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
        let mut gids = vec![0u32; usize::try_from(n).unwrap_or(0)];
        let mut got = n;
        if libc::getgrouplist(c.as_ptr(), (*pw).pw_gid, gids.as_mut_ptr(), &mut got) < 0 {
            return Vec::new();
        }
        gids.truncate(usize::try_from(got.max(0)).unwrap_or(0));
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
#[must_use]
pub fn check_password(user: &str, pass: &str) -> bool {
    use std::ffi::CString;
    let (Some(cu), Some(cp)) = (CString::new(user).ok(), CString::new(pass).ok()) else {
        return false;
    };
    // SAFETY: `cu`/`cp` are valid NUL-terminated CStrings; `sp`/`hashed` are
    // static libc buffers read before the next clobbering call; `crypt` is the
    // real libcrypt symbol linked by soname.
    unsafe {
        #[link(name = ":libcrypt.so.1")]
        extern "C" {
            fn crypt(key: *const libc::c_char, salt: *const libc::c_char) -> *mut libc::c_char;
        }
        let sp = libc::getspnam(cu.as_ptr());
        if sp.is_null() {
            return false;
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
    let mut out = Vec::with_capacity(usize::try_from(n).unwrap_or(0));
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

/// `SO_PEERCRED` on an `AF_UNIX` stream socket — the `(pid, uid, gid)` of
/// the connected peer, the `cupsdAuthorize`/`PeerCred` path that lets local
/// clients authenticate as their real user without a password.
/// Returns `None` when the socket is not `AF_UNIX` or the getsockopt fails.
#[cfg(unix)]
#[must_use]
pub fn peer_cred(fd: std::os::fd::RawFd) -> Option<(i32, u32, u32)> {
    // SAFETY: `ucred` is a plain POD; all-zero is a valid bit pattern.
    let mut uc: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = libc::socklen_t::try_from(std::mem::size_of::<libc::ucred>())
        .unwrap_or(libc::socklen_t::MAX);
    // SAFETY: `uc`/`len` are valid out-params; `fd` is an open socket.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::addr_of_mut!(uc).cast::<libc::c_void>(),
            &mut len,
        )
    };
    if rc == 0 {
        Some((uc.pid, uc.uid, uc.gid))
    } else {
        None
    }
}

/// `getsockname(2)` `sa_family` for an fd — `AF_UNIX` vs `AF_INET`/`INET6`.
/// Returns the family constant, or `-1` on error.
#[cfg(unix)]
#[must_use]
pub fn socket_family(fd: std::os::fd::RawFd) -> i32 {
    // SAFETY: `sockaddr_storage` is a plain POD; all-zero is a valid pattern.
    let mut ss: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = libc::socklen_t::try_from(std::mem::size_of::<libc::sockaddr_storage>())
        .unwrap_or(libc::socklen_t::MAX);
    // SAFETY: `ss`/`len` are valid out-params; `fd` is an open socket.
    let rc = unsafe {
        libc::getsockname(
            fd,
            std::ptr::addr_of_mut!(ss).cast::<libc::sockaddr>(),
            &mut len,
        )
    };
    if rc == 0 {
        i32::from(ss.ss_family)
    } else {
        -1
    }
}

/// Terminal line settings for serial ports (`tcgetattr`/`tcsetattr`) —
/// owned copy of `libc::termios` with named setters so callers stay
/// `unsafe`-free.
#[cfg(unix)]
#[derive(Clone)]
pub struct Termios(libc::termios);

#[cfg(unix)]
impl Termios {
    /// `tcgetattr(fd)` → the current settings, `None` on error.
    #[must_use]
    pub fn get(fd: std::os::fd::RawFd) -> Option<Self> {
        // SAFETY: `termios` is a POD; all-zero is valid before tcgetattr fills it.
        let mut t: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: `t` is a valid out-param; `fd` may be any fd (fails harmlessly).
        if unsafe { libc::tcgetattr(fd, &mut t) } == 0 {
            Some(Self(t))
        } else {
            None
        }
    }

    /// `tcdrain` + `tcsetattr(fd, TCSADRAIN, self)` — apply after draining.
    #[must_use]
    pub fn set(&self, fd: std::os::fd::RawFd) -> bool {
        // SAFETY: `&self.0` is a valid in-param; `fd` may be any fd.
        unsafe { libc::tcdrain(fd) == 0 && libc::tcsetattr(fd, libc::TCSADRAIN, &self.0) == 0 }
    }

    /// Map a numeric baud rate to a `B*` constant; `None` if unsupported.
    #[must_use]
    pub fn baud(rate: u32) -> Option<libc::speed_t> {
        Some(match rate {
            50 => libc::B50,
            75 => libc::B75,
            110 => libc::B110,
            134 => libc::B134,
            150 => libc::B150,
            200 => libc::B200,
            300 => libc::B300,
            600 => libc::B600,
            1200 => libc::B1200,
            1800 => libc::B1800,
            2400 => libc::B2400,
            4800 => libc::B4800,
            9600 => libc::B9600,
            19200 => libc::B19200,
            38400 => libc::B38400,
            57600 => libc::B57600,
            115200 => libc::B115200,
            230400 => libc::B230400,
            _ => return None,
        })
    }

    /// `cfsetispeed`/`cfsetospeed` for a `B*` constant.
    pub fn set_baud(&mut self, speed: libc::speed_t) {
        // SAFETY: `&mut self.0` is a valid termios to update.
        unsafe {
            libc::cfsetispeed(&mut self.0, speed);
            libc::cfsetospeed(&mut self.0, speed);
        }
    }

    /// Parity: `none`/`odd`/`even`/`space`/`mark`.
    pub fn set_parity(&mut self, parity: &str) {
        self.0.c_iflag &= !(libc::ISTRIP | libc::IGNPAR | libc::INPCK | libc::PARMRK);
        self.0.c_cflag &= !libc::CMSPAR;
        match parity {
            "odd" => self.0.c_cflag |= libc::PARENB | libc::PARODD,
            "even" => self.0.c_cflag = (self.0.c_cflag | libc::PARENB) & !libc::PARODD,
            "space" => {
                self.0.c_cflag |= libc::PARENB | libc::CMSPAR;
                self.0.c_cflag &= !libc::PARODD;
            }
            "mark" => self.0.c_cflag |= libc::PARENB | libc::CMSPAR | libc::PARODD,
            _ => self.0.c_cflag &= !libc::PARENB,
        }
    }

    /// Character size 5–8 bits (`CS5`…`CS8`); other values are ignored.
    pub fn set_bits(&mut self, bits: &str) {
        self.0.c_cflag &= !libc::CSIZE;
        self.0.c_cflag |= match bits {
            "5" => libc::CS5,
            "6" => libc::CS6,
            "7" => libc::CS7,
            _ => libc::CS8,
        };
    }

    /// Flow control: `none`/`soft`(xon/xoff)/`hard`(rtscts)/`dtrdsr`.
    pub fn set_flow(&mut self, flow: &str) {
        match flow {
            "soft" | "xon" => {
                self.0.c_iflag |= libc::IXON | libc::IXOFF;
                self.0.c_cflag &= !libc::CRTSCTS;
            }
            "hard" | "rtscts" => {
                self.0.c_iflag &= !(libc::IXON | libc::IXOFF);
                self.0.c_cflag |= libc::CRTSCTS;
            }
            _ => {
                self.0.c_iflag &= !(libc::IXON | libc::IXOFF);
                self.0.c_cflag &= !libc::CRTSCTS;
            }
        }
    }

    /// `tcdrain(fd)` — wait for pending output to flush.
    pub fn drain(fd: std::os::fd::RawFd) {
        // SAFETY: `fd` may be any fd; tcdrain is side-effect safe.
        unsafe {
            libc::tcdrain(fd);
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
