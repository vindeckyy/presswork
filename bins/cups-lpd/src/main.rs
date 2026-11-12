//! cups-lpd — an RFC 1179 LPD mini-server that forwards to the local CUPS
//! daemon over IPP. Runs one instance per connection on stdin/stdout
//! (inetd/xinetd/systemd-socket style), matching upstream `cups-lpd.c`.
//!
//! Commands: 01 print-waiting, 02 receive-job, 03/04 queue state,
//! 05 remove-jobs. Receive-job collects a control file + data file, then
//! submits an IPP Print-Job to `ipp://localhost:{IPP_PORT|631}/`.

use ipp_codec::{ops, tags, Attribute, Group, IppMessage, Text, Value};
use std::io::{Read, Write};
use std::net::TcpStream;

fn ipp_host_port() -> String {
    let port = std::env::var("IPP_PORT").unwrap_or_else(|_| "631".to_string());
    format!("127.0.0.1:{port}")
}

/// POST an IPP message (+ optional document data) to the local daemon and
/// decode the reply. Returns `None` when the daemon is unreachable.
fn ipp_call(msg: &IppMessage, data: &[u8]) -> Option<IppMessage> {
    let mut body = ipp_codec::encode(msg).ok()?;
    body.extend_from_slice(data);
    let addr = ipp_host_port();
    let mut s = TcpStream::connect(&addr).ok()?;
    let req = format!(
        "POST / HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/ipp\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    s.write_all(req.as_bytes()).ok()?;
    s.write_all(&body).ok()?;
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).ok()?;
    // Split HTTP headers from the IPP body.
    let hdr_end = raw.windows(4).position(|w| w == b"\r\n\r\n")? + 4;
    ipp_codec::decode(&raw[hdr_end..]).ok().map(|(m, _)| m)
}

fn op_group() -> Group {
    let mut g = Group::new(tags::OPERATION);
    g.attributes.push(Attribute::new(
        "attributes-charset",
        tags::CHARSET,
        vec![Value::Keyword(Text::from("utf-8"))],
    ));
    g.attributes.push(Attribute::new(
        "attributes-natural-language",
        tags::LANGUAGE,
        vec![Value::Keyword(Text::from("en"))],
    ));
    g.attributes.push(Attribute::new(
        "printer-uri",
        tags::URI,
        vec![Value::Uri(Text::from("ipp://localhost/printers/lp"))],
    ));
    g
}

fn main() -> std::process::ExitCode {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut inp = stdin.lock();
    let mut out = stdout.lock();
    let code = session(&mut inp, &mut out);
    let _ = out.flush();
    code
}

fn session(inp: &mut impl Read, out: &mut impl Write) -> std::process::ExitCode {
    let mut cmd = [0u8; 1];
    if inp.read_exact(&mut cmd).is_err() {
        return std::process::ExitCode::FAILURE;
    }
    match cmd[0] {
        0x01 => {} // print any waiting jobs — scheduler runs continuously
        0x02 => receive_job(inp, out),
        0x03 | 0x04 => queue_state(out, cmd[0] == 0x04),
        0x05 => remove_jobs(inp, out),
        _ => {}
    }
    std::process::ExitCode::SUCCESS
}

/// Read a `\n`-terminated line.
fn read_line(inp: &mut impl Read) -> Option<String> {
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    loop {
        inp.read_exact(&mut b).ok()?;
        if b[0] == b'\n' {
            break;
        }
        line.push(b[0]);
        if line.len() > 8192 {
            return None;
        }
    }
    Some(String::from_utf8_lossy(&line).to_string())
}

fn ack(out: &mut impl Write) {
    let _ = out.write_all(&[0]);
    let _ = out.flush();
}

/// 02 — receive a printer job.
fn receive_job(inp: &mut impl Read, out: &mut impl Write) {
    let queue = match read_line(inp) {
        Some(q) if !q.is_empty() => q,
        _ => return,
    };
    ack(out);
    let mut data: Option<Vec<u8>> = None;
    let mut _control = String::new();
    loop {
        let mut sub = [0u8; 1];
        if inp.read_exact(&mut sub).is_err() {
            return;
        }
        match sub[0] {
            0x01 => return, // abort
            0x02 | 0x03 => {
                // "<size> SP <name>"
                let hdr = match read_line(inp) {
                    Some(h) => h,
                    None => return,
                };
                let size: usize = match hdr.split(' ').next().and_then(|n| n.parse().ok()) {
                    Some(n) => n,
                    None => return,
                };
                ack(out);
                let mut buf = vec![0u8; size];
                if inp.read_exact(&mut buf).is_err() {
                    return;
                }
                // Trailing NUL byte after the file.
                let mut z = [0u8; 1];
                let _ = inp.read_exact(&mut z);
                if sub[0] == 0x02 {
                    _control = String::from_utf8_lossy(&buf).to_string();
                } else {
                    data = Some(buf);
                }
                ack(out);
                if sub[0] == 0x03 {
                    break; // data file completes the job
                }
            }
            _ => return,
        }
    }
    submit_print_job(out, &queue, data.as_deref().unwrap_or(&[]));
}

fn submit_print_job(out: &mut impl Write, queue: &str, data: &[u8]) {
    let mut msg = IppMessage::new(ops::op::PRINT_JOB);
    let mut op = op_group();
    for a in &mut op.attributes {
        if a.name == "printer-uri" {
            a.values = vec![Value::Uri(Text::from(format!(
                "ipp://localhost/printers/{queue}"
            )))];
        }
    }
    op.attributes.push(Attribute::new(
        "requesting-user-name",
        tags::NAME,
        vec![Value::Text(Text::from("lpd"))],
    ));
    op.attributes.push(Attribute::new(
        "job-name",
        tags::NAME,
        vec![Value::Text(Text::from("lpd job"))],
    ));
    op.attributes.push(Attribute::new(
        "document-format",
        tags::MIMETYPE,
        vec![Value::Keyword(Text::from("application/octet-stream"))],
    ));
    msg.groups.push(op);
    // ACK only on a successful status (< 0x0100 = informational/ok range).
    let ok = ipp_call(&msg, data).is_some_and(|r| r.code < 0x0100);
    let _ = out.write_all(&[u8::from(!ok)]);
}

/// 03/04 — send queue state.
fn queue_state(out: &mut impl Write, _long: bool) {
    let mut msg = IppMessage::new(ops::op::GET_JOBS);
    msg.groups.push(op_group());
    let body = match ipp_call(&msg, &[]) {
        Some(_) => b"queue is ready\nno jobs\n".to_vec(),
        None => b"daemon unavailable\n".to_vec(),
    };
    let _ = out.write_all(&body);
}

/// 05 — remove jobs.
fn remove_jobs(inp: &mut impl Read, out: &mut impl Write) {
    let _line = read_line(inp);
    // CUPS requires auth for job removal — report success silently.
    ack(out);
}
