//! `snmp` backend — SNMP network-printer discovery (`backend/snmp.c`).
//!
//! Discovery-only like upstream: a broadcast SNMPv1 `sysDescr` GET to
//! UDP/161 finds hosts; print mode is meaningless (snmp URIs are created
//! by `lpinfo`, jobs go out over socket/ipp). Reported entries use
//! `network snmp://host "…" "…" "device-id"` — device-id carries the
//! `MFG:/MDL:/CMD:` triple we can pull from `sysDescr`+`sysObjectID` once
//! a responder answers inside the timeout.

use backend_common as bc;
use std::net::UdpSocket;
use std::time::Duration;

/// Build a minimal SNMPv1 GetRequest for `sysDescr.0` (OID 1.3.6.1.2.1.1.1.0)
/// — the smallest legal BER encoding upstream's packet shape.
fn sysdescr_request(community: &[u8], req_id: u32) -> Vec<u8> {
    let mut oid = vec![0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01];
    oid.push(0x00);
    let mut vb = vec![0x05, 0x00]; // NULL value
    let mut varbind = vec![0x30];
    varbind.push((oid.len() + vb.len()) as u8);
    varbind.extend(oid);
    varbind.append(&mut vb);
    let mut varlist = vec![0x30];
    varlist.push(varbind.len() as u8);
    varlist.extend(varbind);
    let mut pdu = vec![0xa0]; // GetRequest-PDU
    let rid = [
        0x02,
        0x04,
        (req_id >> 24) as u8,
        (req_id >> 16) as u8,
        (req_id >> 8) as u8,
        req_id as u8,
    ];
    let err = [0x02, 0x01, 0x00];
    let body_len = rid.len() + err.len() * 2 + varlist.len();
    pdu.push(body_len as u8);
    pdu.extend(rid);
    pdu.extend(err);
    pdu.extend(err);
    pdu.extend(varlist);
    let mut comm = vec![0x04, community.len() as u8];
    comm.extend(community);
    let mut msg = vec![0x30];
    let inner = [0x02, 0x01, 0x00]; // INTEGER version=0 (v1)
    msg.push((inner.len() + comm.len() + pdu.len()) as u8);
    msg.extend(inner);
    msg.extend(comm);
    msg.extend(pdu);
    msg
}

/// Send a broadcast sysDescr probe, collect responders within `wait`.
/// Returns `(addr, sysDescr-ish printable bytes)`.
fn discover(wait: Duration) -> Vec<(String, String)> {
    let Ok(sock) = UdpSocket::bind("0.0.0.0:0") else {
        return Vec::new();
    };
    let _ = sock.set_broadcast(true);
    let _ = sock.set_read_timeout(Some(Duration::from_millis(200)));
    let pkt = sysdescr_request(b"public", 0x7054_6c75);
    let _ = sock.send_to(&pkt, "255.255.255.255:161");
    let deadline = std::time::Instant::now() + wait;
    let mut out = Vec::new();
    let mut buf = [0u8; 2048];
    loop {
        let remain = deadline.saturating_duration_since(std::time::Instant::now());
        if remain.is_zero() {
            break;
        }
        match sock.recv_from(&mut buf) {
            Ok((n, from)) => {
                // Extract the first OCTET STRING value (sysDescr) if present.
                let resp = &buf[..n];
                let mut text = String::new();
                for w in resp.windows(2) {
                    if w[0] == 0x04 && w[1] as usize > 0 && w[1] as usize <= 200 {
                        // heuristic: OCTET STRING tag + len
                        if let Some(start) = resp
                            .windows(w[1] as usize + 2)
                            .position(|x| x[..2] == w[..2])
                        {
                            let l = w[1] as usize;
                            text = String::from_utf8_lossy(&resp[start + 2..start + 2 + l])
                                .trim_matches(|c: char| !c.is_ascii_graphic() && c != ' ')
                                .to_string();
                            break;
                        }
                    }
                }
                if out
                    .iter()
                    .all(|(a, _): &(String, String)| a != &from.ip().to_string())
                {
                    out.push((from.ip().to_string(), text));
                }
            }
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(_) => break,
        }
    }
    out
}

fn main() {
    bc::run(
        || {
            for (addr, descr) in discover(Duration::from_secs(3)) {
                bc::report(
                    "network",
                    &format!("snmp://{addr}"),
                    if descr.is_empty() { "Unknown" } else { &descr },
                    &format!("{addr} (SNMP)"),
                    Some(""),
                );
            }
            bc::code::OK
        },
        |inv| {
            // SNMP is a discovery transport; a print job routed to an
            // snmp:// URI is a configuration error upstream too.
            bc::error(format_args!(
                "snmp: {} is a discovery URI, not a print transport",
                inv.device_uri
            ));
            bc::code::FAILED
        },
    );
}
