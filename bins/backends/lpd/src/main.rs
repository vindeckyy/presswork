//! `lpd` backend — forward a job to a remote RFC 1179 LPD print server.
//!
//! Complements `cups-lpd` (the server side). `DEVICE_URI` is
//! `lpd://host/queue`; the backend connects to `host:515` and drives the
//! receive-job protocol: `02 queue\n`, then a control file (`02`) and a
//! data file (`03`), waiting for a `0` ack at each step.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

fn parse_uri(uri: &str) -> Option<(String, u16, String)> {
    let rest = uri.strip_prefix("lpd://")?;
    let (authority, queue) = rest.split_once('/')?;
    let queue = queue.split(['?', '#']).next().unwrap_or(queue);
    let (host, port) = match authority.split_once(':') {
        Some((h, p)) => (h, p.parse().ok()?),
        None => (authority, 515),
    };
    if host.is_empty() || queue.is_empty() {
        return None;
    }
    Some((host.to_string(), port, queue.to_string()))
}

/// Read exactly one status byte; LPD `0` means OK.
fn read_ack(s: &mut TcpStream) -> std::io::Result<()> {
    let mut b = [0u8; 1];
    s.read_exact(&mut b)?;
    if b[0] == 0 {
        Ok(())
    } else {
        Err(std::io::Error::other(format!("lpd: ack byte {}", b[0])))
    }
}

fn main() {
    backend_common::run(
        || {
            // Discovery — lpd doesn't enumerate remote queues.
            backend_common::code::OK
        },
        |inv| {
            let (host, port, queue) = match parse_uri(&inv.device_uri) {
                Some(t) => t,
                None => {
                    backend_common::error(format_args!("lpd: bad device-uri {}", inv.device_uri));
                    return backend_common::code::FAILED;
                }
            };
            let mut doc = match backend_common::document(&inv) {
                Ok(d) => d,
                Err(e) => {
                    backend_common::error(format_args!("lpd: open document: {e}"));
                    return backend_common::code::FAILED;
                }
            };
            let mut data = Vec::new();
            if doc.read_to_end(&mut data).is_err() {
                return backend_common::code::FAILED;
            }
            match send(&host, port, &queue, &inv, &data) {
                Ok(()) => backend_common::code::OK,
                Err(e) => {
                    backend_common::error(format_args!("lpd: {e}"));
                    backend_common::code::FAILED
                }
            }
        },
    );
}

fn send(
    host: &str,
    port: u16,
    queue: &str,
    inv: &backend_common::Invocation,
    data: &[u8],
) -> std::io::Result<()> {
    let mut s = TcpStream::connect(format!("{host}:{port}"))?;
    s.set_read_timeout(Some(Duration::from_secs(30))).ok();

    // 02 <queue>\n — receive a printer job.
    s.write_all(&[0x02])?;
    s.write_all(queue.as_bytes())?;
    s.write_all(b"\n")?;
    read_ack(&mut s)?;

    // Control file (dfA###host): minimal job metadata.
    let ctrl = format!(
        "H{host}\nP{user}\nJ{title}\nfdfA###{host}\nUdfA###{host}\nN{title}\n",
        user = inv.user,
        title = inv.title
    );
    let cname = format!("dfA{:03}{}", inv.job_id % 1000, host);
    s.write_all(&[0x02])?;
    s.write_all(format!("{} {}\n", ctrl.len(), cname).as_bytes())?;
    read_ack(&mut s)?;
    s.write_all(ctrl.as_bytes())?;
    s.write_all(&[0])?;
    read_ack(&mut s)?;

    // Data file.
    let dname = format!("dfB{:03}{}", inv.job_id % 1000, host);
    s.write_all(&[0x03])?;
    s.write_all(format!("{} {}\n", data.len(), dname).as_bytes())?;
    read_ack(&mut s)?;
    s.write_all(data)?;
    s.write_all(&[0])?;
    read_ack(&mut s)?;

    backend_common::info(format_args!(
        "lpd: job {} sent to {host}/{queue}",
        inv.job_id
    ));
    Ok(())
}
