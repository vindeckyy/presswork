//! `serial` backend — RS-232 printers (`backend/serial.c`).
//!
//! `serial:///dev/ttySN[?baud=9600+parity=none+flow=none+bits=8]` opens the
//! port, applies the termios line settings from the URI params (upstream
//! supports `baud`, `parity` (`none`/`odd`/`even`/`space`/`mark`), `flow`
//! (`none`/`soft`/`hard`/`dtrdsr`), `bits`), streams the doc, then restores
//! the saved termios.

use backend_common as bc;
use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;

/// `(path, params)` from `serial:///dev/ttySN?k=v&k=v`.
fn parse_uri(uri: &str) -> Option<(String, Vec<(String, String)>)> {
    let rest = uri.strip_prefix("serial://")?;
    let (path, query) = rest.split_once('?').map_or((rest, ""), |(p, q)| (p, q));
    let params = query
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    Some((path.to_string(), params))
}

fn apply_params(fd: i32, params: &[(String, String)]) -> Result<sys::Termios, String> {
    let mut tio = sys::Termios::get(fd).ok_or("tcgetattr failed")?;
    for (k, v) in params {
        match k.as_str() {
            "baud" => {
                let b: u32 = v.parse().map_err(|_| format!("bad baud {v}"))?;
                let c = sys::Termios::baud(b).ok_or_else(|| format!("unsupported baud {v}"))?;
                tio.set_baud(c);
            }
            "parity" => match v.as_str() {
                "none" | "odd" | "even" | "space" | "mark" => tio.set_parity(v),
                _ => return Err(format!("bad parity {v}")),
            },
            "bits" => {
                if !matches!(v.as_str(), "5" | "6" | "7" | "8") {
                    return Err(format!("bad bits {v}"));
                }
                tio.set_bits(v);
            }
            "flow" => match v.as_str() {
                "none" | "soft" | "xon" | "hard" | "rtscts" | "dtrdsr" => tio.set_flow(v),
                _ => return Err(format!("bad flow {v}")),
            },
            _ => {}
        }
    }
    if !tio.set(fd) {
        return Err("tcsetattr failed".into());
    }
    Ok(tio)
}

fn main() {
    bc::run(
        || {
            // Discovery lists available ports (upstream lists /dev/ttyS* +
            // /dev/ttyUSB* when writable).
            if let Ok(rd) = std::fs::read_dir("/dev") {
                let mut names: Vec<String> = rd
                    .flatten()
                    .filter_map(|e| {
                        let n = e.file_name().to_string_lossy().into_owned();
                        (n.starts_with("ttyS")
                            || n.starts_with("ttyUSB")
                            || n.starts_with("ttyACM"))
                        .then_some(n)
                    })
                    .collect();
                names.sort();
                for n in names {
                    let node = format!("/dev/{n}");
                    if std::fs::OpenOptions::new()
                        .read(true)
                        .write(true)
                        .open(&node)
                        .is_ok()
                    {
                        bc::report(
                            "direct",
                            &format!("serial://{node}?baud=9600"),
                            "Unknown",
                            &format!("Serial Port ({node})"),
                            Some(""),
                        );
                    }
                }
            }
            bc::code::OK
        },
        |inv| {
            let uri = &inv.device_uri;
            let Some((path, params)) = parse_uri(uri) else {
                bc::error(format_args!("serial: bad device-uri {uri}"));
                return bc::code::FAILED;
            };
            let mut dev = match std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
            {
                Ok(f) => f,
                Err(e) => {
                    bc::error(format_args!("serial: cannot open {path}: {e}"));
                    return bc::code::FAILED;
                }
            };
            let fd = dev.as_raw_fd();
            // Save termios to restore on exit (upstream restores on exit).
            let saved = sys::Termios::get(fd);
            if let Err(e) = apply_params(fd, &params) {
                bc::error(format_args!("serial: {e}"));
                return bc::code::FAILED;
            }
            let mut doc = match bc::document(&inv) {
                Ok(d) => d,
                Err(e) => {
                    bc::error(format_args!("serial: open document: {e}"));
                    return bc::code::FAILED;
                }
            };
            let mut rc = bc::code::OK;
            let mut buf = [0u8; 8192];
            loop {
                match doc.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if let Err(e) = dev.write_all(&buf[..n]) {
                            bc::error(format_args!("serial: write failed: {e}"));
                            rc = bc::code::RETRY;
                            break;
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => {
                        rc = bc::code::FAILED;
                        break;
                    }
                }
            }
            // Wait for the FIFO to drain, then restore line settings.
            sys::Termios::drain(fd);
            if let Some(saved) = saved {
                let _ = saved.set(fd);
            }
            rc
        },
    );
}
