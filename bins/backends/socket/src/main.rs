//! `socket` backend — AppSocket/JetDirect `:9100` (`backend/socket.c`).
//!
//! `socket://host[:port]` — streams the document raw over TCP to the
//! printer. Discovery mode reports no devices of its own (it's a manual
//! URI scheme, like upstream) and exits 0.

use backend_common as bc;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

fn main() {
    bc::run(
        || {
            // socket has no auto-discoverable devices.
            bc::code::OK
        },
        |inv| {
            let uri = &inv.device_uri;
            let Some(rest) = uri.strip_prefix("socket://") else {
                bc::error(format_args!("Bad device URI: {uri}"));
                return bc::code::FAILED;
            };
            // strip path/fragment, split host:port
            let hostport = rest.split(&['/', '?', '#'][..]).next().unwrap_or("");
            let (host, port) = match hostport.rsplit_once(':') {
                Some((h, p)) => (h.to_string(), p.parse().unwrap_or(9100)),
                None => (hostport.to_string(), 9100),
            };
            let addr = match format!("{host}:{port}").parse() {
                Ok(a) => a,
                Err(_) => {
                    // resolve hostname
                    use std::net::ToSocketAddrs;
                    match format!("{host}:{port}")
                        .to_socket_addrs()
                        .and_then(|mut i| i.next().ok_or_else(|| std::io::Error::other("no addr")))
                    {
                        Ok(a) => a,
                        Err(e) => {
                            bc::error(format_args!("Cannot resolve {host}: {e}"));
                            return bc::code::FAILED;
                        }
                    }
                }
            };
            bc::info(format_args!("Connecting to {addr}"));
            let mut stream = match TcpStream::connect_timeout(&addr, Duration::from_secs(30)) {
                Ok(s) => s,
                Err(e) => {
                    bc::error(format_args!("Cannot connect to {addr}: {e}"));
                    return bc::code::RETRY;
                }
            };
            let _ = stream.set_nodelay(true);
            let mut doc = match bc::document(&inv) {
                Ok(d) => d,
                Err(e) => {
                    bc::error(format_args!("Cannot open document: {e}"));
                    return bc::code::FAILED;
                }
            };
            // Stream the document.
            let mut buf = [0u8; 8192];
            let mut total = 0u64;
            loop {
                match doc.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if let Err(e) = stream.write_all(&buf[..n]) {
                            bc::error(format_args!("Write failed: {e}"));
                            return bc::code::RETRY;
                        }
                        total += n as u64;
                    }
                    Err(e) => {
                        bc::error(format_args!("Read failed: {e}"));
                        return bc::code::FAILED;
                    }
                }
            }
            // half-close so the printer sees EOF on this copy
            let _ = stream.shutdown(std::net::Shutdown::Write);
            bc::info(format_args!("Sent {total} bytes to {addr}"));
            bc::code::OK
        },
    );
}
