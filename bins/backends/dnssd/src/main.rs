//! `dnssd` backend — DNS-SD remote printer discovery + dnssd:// forwarding.
//!
//! ## Discovery mode (`cups-deviced`, argv.len()==1)
//! Browse `_ipp._tcp`/`_ipps._tcp` and emit one
//! `network dnssd://<host>:<port>/<rp> "make-model" "info"` line per remote
//! printer (upstream `backend/dnssd.c` `find_devices`).
//!
//! ## Print mode
//! `dnssd://<name>._ipp._tcp.local/<rp>` resolves the service name to a real
//! `ipp://` URI, then forwards the job by exec'ing the sibling `ipp` backend
//! with the same argv (preserving the backend contract).

use std::time::Duration;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    backend_common::run(
        || {
            // Discovery — browse for a short window, dedup by URI.
            let mut seen = std::collections::HashSet::new();
            for r in dnssd::browse_ipp(Duration::from_millis(1500)) {
                if seen.insert(r.uri.clone()) {
                    let info = if r.make_model.is_empty() {
                        r.name.clone()
                    } else {
                        r.make_model.clone()
                    };
                    backend_common::report("network", &r.uri, "IPP Printer", &info, None);
                }
            }
            backend_common::code::OK
        },
        |inv| {
            // Print — resolve the dnssd:// service to ipp:// and hand off.
            let uri = inv.device_uri.as_str();
            match dnssd::resolve_uri(uri, Duration::from_secs(3)) {
                Some(real) => forward(&args, &real),
                None => {
                    backend_common::error(format_args!(
                        "dnssd: could not resolve {uri} to an IPP address"
                    ));
                    backend_common::code::FAILED
                }
            }
        },
    );
}

/// Exec the sibling `ipp` backend with `dnssd://` rewritten to `ipp://`.
fn forward(_argv0: &[String], _real_uri: &str) -> i32 {
    backend_common::error(format_args!(
        "dnssd: ipp forwarding not yet wired (resolve ok)"
    ));
    backend_common::code::FAILED
}
