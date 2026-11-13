//! `parallel` backend — IEEE-1284 parallel port (`backend/parallel.c`).
//!
//! `parallel:///dev/lpN` streams the document to the port. Discovery lists
//! `/dev/lp*` nodes with the port's 1284 id when the kernel exposes it
//! (`/sys/class/parport/parportN/devices/lpN` or procfs).

use backend_common as bc;
use std::io::{Read, Write};

fn enumerate() -> Vec<(String, String)> {
    let mut out = Vec::new();
    for dir in ["/dev", "/dev/parport"] {
        let Ok(rd) = std::fs::read_dir(dir) else {
            continue;
        };
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let ok = if dir == "/dev" {
                name.starts_with("lp") && name[2..].chars().all(|c| c.is_ascii_digit())
            } else {
                true
            };
            if !ok {
                continue;
            }
            let node = e.path().to_string_lossy().into_owned();
            // 1284 id via /proc/sys/dev/parport/parportN/devices or sysfs.
            let devid = [
                format!("/sys/class/parport/{name}/device/ieee1284_id"),
                format!(
                    "/sys/class/parport/parport{}/devices/{}/ieee1284_id",
                    &name[2..],
                    name
                ),
            ]
            .iter()
            .find_map(|c| std::fs::read_to_string(c).ok())
            .map_or_else(String::new, |v| v.trim().to_string());
            out.push((node, devid));
        }
    }
    out
}

fn main() {
    bc::run(
        || {
            for (node, devid) in enumerate() {
                bc::report(
                    "direct",
                    &format!("parallel://{node}"),
                    "Unknown",
                    &format!("Parallel Port ({node})"),
                    if devid.is_empty() {
                        Some("")
                    } else {
                        Some(&devid)
                    },
                );
            }
            bc::code::OK
        },
        |inv| {
            let uri = &inv.device_uri;
            let Some(path) = uri.strip_prefix("parallel://") else {
                bc::error(format_args!("parallel: bad device-uri {uri}"));
                return bc::code::FAILED;
            };
            let mut dev = match std::fs::OpenOptions::new().write(true).open(path) {
                Ok(f) => f,
                Err(e) => {
                    bc::error(format_args!("parallel: cannot open {path}: {e}"));
                    return bc::code::FAILED;
                }
            };
            let mut doc = match bc::document(&inv) {
                Ok(d) => d,
                Err(e) => {
                    bc::error(format_args!("parallel: open document: {e}"));
                    return bc::code::FAILED;
                }
            };
            let mut buf = [0u8; 8192];
            loop {
                match doc.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if let Err(e) = dev.write_all(&buf[..n]) {
                            bc::error(format_args!("parallel: write failed: {e}"));
                            return bc::code::RETRY;
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(_) => return bc::code::FAILED,
                }
            }
            bc::code::OK
        },
    );
}
