//! `usb` backend — USB printer transport (`backend/usb.c`-equivalent).
//!
//! `usb://<make>/<model>?serial=<ser>` selects a `/dev/usb/lp*` node whose
//! IEEE-1284 device-id (`/sys/class/usbmisc/lpN/device/ieee1284_id` or the
//! interface's sysfs attributes) matches; `usb:///dev/usb/lpN` addresses a
//! node directly. Discovery lists each lp node with its 1284 id so
//! `lpinfo -v` shows `direct usb://make/model?serial=…` lines like
//! upstream.

use backend_common as bc;
use std::io::{Read, Write};
use std::path::Path;

/// One discovered lp node with its IEEE-1284 id fields.
struct UsbDev {
    node: String,  // /dev/usb/lpN
    devid: String, // MFG:..;MDL:..;...
    uri: String,   // usb://mfg/mdl?serial=s
    make_model: String,
    info: String,
}

/// Parse `MFG:x;MDL:y;SER:z;` device-id strings.
fn id_field<'a>(id: &'a str, key: &str) -> Option<&'a str> {
    id.split(';')
        .find(|f| {
            f.to_ascii_uppercase()
                .starts_with(&key.to_ascii_uppercase())
        })
        .and_then(|f| f.split_once(':'))
        .map(|(_, v)| v.trim())
        .filter(|v| !v.is_empty())
}

fn pct_encode(s: &str) -> String {
    s.bytes()
        .map(|c| {
            if c.is_ascii_alphanumeric() || b"-_.".contains(&c) {
                (c as char).to_string()
            } else {
                format!("%{c:02X}")
            }
        })
        .collect()
}

fn enumerate() -> Vec<UsbDev> {
    let mut out = Vec::new();
    for dir in ["/dev/usb", "/dev"] {
        let Ok(rd) = std::fs::read_dir(dir) else {
            continue;
        };
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let is_lp = if dir == "/dev/usb" {
                name.starts_with("lp")
            } else {
                name.starts_with("usblp")
            };
            if !is_lp {
                continue;
            }
            let node = e.path().to_string_lossy().into_owned();
            // IEEE-1284 id via sysfs: usbmisc/lpN or usb/lpN class entries.
            let mut devid = String::new();
            for cand in [
                format!("/sys/class/usbmisc/{name}/device/ieee1284_id"),
                format!("/sys/class/usb/{name}/device/ieee1284_id"),
            ] {
                if let Ok(v) = std::fs::read_to_string(&cand) {
                    devid = v.trim().to_string();
                    break;
                }
            }
            let mfg = id_field(&devid, "MFG")
                .or_else(|| id_field(&devid, "MANUFACTURER"))
                .unwrap_or("Unknown");
            let mdl = id_field(&devid, "MDL")
                .or_else(|| id_field(&devid, "MODEL"))
                .unwrap_or("Unknown");
            let ser = id_field(&devid, "SER")
                .or_else(|| id_field(&devid, "SERN"))
                .unwrap_or("");
            let make_model = format!("{mfg} {mdl}");
            let uri = if ser.is_empty() {
                format!("usb://{}/{}", pct_encode(mfg), pct_encode(mdl))
            } else {
                format!(
                    "usb://{}/{}?serial={}",
                    pct_encode(mfg),
                    pct_encode(mdl),
                    pct_encode(ser)
                )
            };
            out.push(UsbDev {
                node,
                devid,
                uri,
                make_model: make_model.clone(),
                info: format!("{make_model} ({name})"),
            });
        }
    }
    out
}

/// Find the node for a `usb://` URI: direct `/dev` path wins, else match
/// make/model(/serial) from the 1284 id.
fn find_node(uri: &str) -> Option<String> {
    let rest = uri.strip_prefix("usb://")?;
    if let Some(p) = rest.strip_prefix('/').map(|s| format!("/{s}")) {
        // usb:///dev/usb/lpN
        if Path::new(&p).exists() {
            return Some(p);
        }
    }
    let path = rest.split('?').next()?;
    let mut seg = path.split('/');
    let mfg = seg.next().unwrap_or_default();
    let mdl = seg.next().unwrap_or_default();
    let want_serial = rest
        .split('?')
        .nth(1)
        .and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("serial=")));
    let dec = |s: &str| {
        let mut o = String::new();
        let mut b = s.bytes();
        while let Some(c) = b.next() {
            if c == b'%' {
                if let (Some(a), Some(x)) = (b.next(), b.next()) {
                    if let Ok(v) = u8::from_str_radix(&format!("{}{}", a as char, x as char), 16) {
                        o.push(v as char);
                        continue;
                    }
                }
                o.push('%');
            } else {
                o.push(c as char);
            }
        }
        o
    };
    let (mfg, mdl, want_serial) = (dec(mfg), dec(mdl), want_serial.map(dec));
    for d in enumerate() {
        let dmfg = id_field(&d.devid, "MFG").unwrap_or_default();
        let dmdl = id_field(&d.devid, "MDL").unwrap_or_default();
        let dser = id_field(&d.devid, "SER").unwrap_or_default();
        if !dmfg.eq_ignore_ascii_case(&mfg) && !mfg.is_empty() {
            continue;
        }
        if !dmdl.eq_ignore_ascii_case(&mdl) && !mdl.is_empty() {
            continue;
        }
        if let Some(s) = &want_serial {
            if !dser.eq_ignore_ascii_case(s) {
                continue;
            }
        }
        return Some(d.node);
    }
    None
}

fn main() {
    bc::run(
        || {
            for d in enumerate() {
                bc::report(
                    "direct",
                    &d.uri,
                    &d.make_model,
                    &d.info,
                    if d.devid.is_empty() {
                        Some("")
                    } else {
                        Some(&d.devid)
                    },
                );
            }
            bc::code::OK
        },
        |inv| {
            let uri = &inv.device_uri;
            let Some(node) = find_node(uri) else {
                bc::error(format_args!("usb: cannot resolve {uri} to a device node"));
                return bc::code::FAILED;
            };
            bc::info(format_args!("Opening {node}"));
            let mut dev = match std::fs::OpenOptions::new().write(true).open(&node) {
                Ok(f) => f,
                Err(e) => {
                    bc::error(format_args!("usb: cannot open {node}: {e}"));
                    return bc::code::FAILED;
                }
            };
            let mut doc = match bc::document(&inv) {
                Ok(d) => d,
                Err(e) => {
                    bc::error(format_args!("usb: open document: {e}"));
                    return bc::code::FAILED;
                }
            };
            let mut buf = [0u8; 8192];
            loop {
                match doc.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if let Err(e) = dev.write_all(&buf[..n]) {
                            bc::error(format_args!("usb: write failed: {e}"));
                            return bc::code::RETRY;
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => return bc::code::FAILED,
                }
            }
            bc::code::OK
        },
    );
}
