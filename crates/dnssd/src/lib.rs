//! DNS-SD (mDNS/Bonjour) printer advertisement + discovery — a port of
//! `scheduler/dirsvc.c`'s `dnssdRegisterPrinter` + `cupsdStartBrowsing`.
//!
//! Uses the pure-Rust `mdns-sd` responder (no Avahi/D-Bus runtime dep) so
//! yindle can advertise and discover printers self-contained on Linux.
//!
//! ## Advertisement (`cupsdRegisterPrinter`)
//! For each shared printer we register, per upstream:
//!  * `_printer._tcp` — the LPD reservation record (empty TXT, port 0),
//!  * `_ipp._tcp`   — IPP service with the full TXT record,
//!  * `_ipps._tcp`  — IPPS service when TLS is enabled,
//!  * `_fax-ipp._tcp` — when the queue is a fax,
//!  * `_http._tcp`   — the web interface (`CUPS @ <computer>`).
//!
//! The service instance name is `"<printer-info> @ <computer-name>"`.
//!
//! ## Discovery (`dnssd` backend)
//! [`browse_ipp`] resolves remote `_ipp._tcp`/`_ipps._tcp` services into
//! `(uri, name, info)` triples for the `cups-deviced` device list.

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use std::collections::HashMap;
use std::time::Duration;

/// Per-printer data needed to build the service TXT record — mirrors the
/// fields `dnssdBuildTxtRecord` reads off `cupsd_printer_t`.
#[derive(Clone, Debug, Default)]
pub struct SharedPrinter {
    pub name: String,
    /// `printer-info` — used in the instance name when set.
    pub info: String,
    /// `make_model` for `ty=` (falls back to "Unknown").
    pub make_model: String,
    /// `printer-location` for `note=`.
    pub location: String,
    /// `pdl` (default `application/postscript`).
    pub pdl: String,
    /// `printer-type` bitmask (`CUPS_PTYPE`_*).
    pub printer_type: u32,
    /// `printer-state` (idle=3, processing=4, stopped=5).
    pub printer_state: i32,
    /// `printer-uuid` tail (after "urn:uuid:").
    pub uuid: String,
    /// Class (not printer) — flips `rp`/`adminurl` to `/classes/`.
    pub is_class: bool,
    /// Fax queue — registers `_fax-ipp._tcp`.
    pub is_fax: bool,
}

/// A discovered remote IPP printer (for the `dnssd` backend).
#[derive(Clone, Debug)]
pub struct RemotePrinter {
    /// `ipp{s}://host:port/<rp>` device URI.
    pub uri: String,
    /// Instance name (`<info> @ <computer>`).
    pub name: String,
    /// `ty=` make/model for the device `info` field.
    pub make_model: String,
}

/// The mDNS advertiser (`DNSSDContext` + per-printer `dnssd` services).
pub struct Advertiser {
    daemon: ServiceDaemon,
    /// `DNSSDHostName` — `host.local` the services resolve to.
    host: String,
    /// `DNSSDComputerName` — the `@ <name>` instance suffix.
    computer: String,
    port: u16,
    /// Register `_ipps._tcp` + emit `TLS=` TXT when true.
    tls: bool,
    /// printer name → its registered service full-names (for unregister).
    registered: HashMap<String, Vec<String>>,
    /// The `_http._tcp` web interface service full-name.
    webif: Option<String>,
}

impl Advertiser {
    /// Start the mDNS daemon + register the web interface.
    ///
    /// `host` is the mDNS hostname (`<host>.local`), `computer` the
    /// human-readable machine name, `port` the IPP listen port, `tls`
    /// whether `_ipps._tcp`/`TLS=` is advertised.
    pub fn start(host: &str, computer: &str, port: u16, tls: bool) -> std::io::Result<Self> {
        let daemon =
            ServiceDaemon::new().map_err(|e| std::io::Error::other(format!("mdns-sd: {e}")))?;
        let mut adv = Self {
            daemon,
            host: normalize_local(host),
            computer: computer.to_string(),
            port,
            tls,
            registered: HashMap::new(),
            webif: None,
        };
        adv.publish_webif()?;
        Ok(adv)
    }

    /// `dnssdBuildTxtRecord` — the TXT key/value pairs for a shared printer.
    fn txt_record(&self, p: &SharedPrinter, secure: bool) -> HashMap<String, String> {
        let mut t = HashMap::new();
        t.insert("txtvers".into(), "1".into());
        t.insert("qtotal".into(), "1".into());
        t.insert(
            "rp".into(),
            format!(
                "{}/{}",
                if p.is_class { "classes" } else { "printers" },
                p.name
            ),
        );
        t.insert(
            "ty".into(),
            if p.make_model.is_empty() {
                "Unknown".into()
            } else {
                p.make_model.clone()
            },
        );
        t.insert("adminurl".into(), self.adminurl(p));
        if !p.location.is_empty() {
            t.insert("note".into(), p.location.clone());
        }
        t.insert("priority".into(), "0".into());
        t.insert(
            "pdl".into(),
            if p.pdl.is_empty() {
                "application/postscript".into()
            } else {
                p.pdl.clone()
            },
        );
        if !p.uuid.is_empty() {
            t.insert("UUID".into(), p.uuid.trim_start_matches("urn:uuid:").into());
        }
        if secure {
            t.insert("TLS".into(), "1.3".into());
        }
        // Capability flags from printer-type.
        let cap = |bit| if p.printer_type & bit != 0 { "T" } else { "F" };
        t.insert("Color".into(), cap(0x0004).into());
        t.insert("Duplex".into(), cap(0x0010).into());
        t.insert("Staple".into(), cap(0x0040).into());
        t.insert("Copies".into(), cap(0x0080).into());
        t.insert("Collate".into(), cap(0x0100).into());
        t.insert("Punch".into(), cap(0x0200).into());
        t.insert("Bind".into(), cap(0x0400).into());
        t.insert("Sort".into(), cap(0x0800).into());
        if p.printer_type & 0x20000 != 0 {
            t.insert("Scan".into(), "T".into());
        }
        if p.is_fax {
            t.insert("Fax".into(), "T".into());
            t.insert(
                "rfo".into(),
                format!(
                    "{}/{}",
                    if p.is_class { "classes" } else { "printers" },
                    p.name
                ),
            );
        }
        t.insert("printer-type".into(), format!("{:#010x}", p.printer_type));
        t.insert("printer-state".into(), p.printer_state.to_string());
        t.insert("mopria-certified".into(), "1.3".into());
        t
    }

    /// `adminurl` — `http{s}://<host>:<port>/<printers|classes>/<name>`.
    fn adminurl(&self, p: &SharedPrinter) -> String {
        format!(
            "{scheme}://{host}:{port}/{sub}/{name}",
            scheme = if self.tls { "https" } else { "http" },
            host = self.host,
            port = self.port,
            sub = if p.is_class { "classes" } else { "printers" },
            name = p.name,
        )
    }

    /// Instance name `"<info|name> @ <computer>"`.
    fn instance(&self, p: &SharedPrinter) -> String {
        let base = if p.info.is_empty() { &p.name } else { &p.info };
        if self.computer.is_empty() {
            base.clone()
        } else {
            format!("{base} @ {}", self.computer)
        }
    }

    /// `cupsdRegisterPrinter` — register a shared printer's services.
    /// Unregisters any prior registration for the same name first.
    pub fn publish(&mut self, p: &SharedPrinter) -> std::io::Result<()> {
        self.unpublish(&p.name);
        let instance = self.instance(p);
        let mut names = Vec::new();

        // 1. `_printer._tcp` reservation (empty TXT, port 0).
        names.push(self.register(&instance, "_printer._tcp.local.", 0, HashMap::new())?);

        // 2. `_fax-ipp._tcp` for fax queues.
        if p.is_fax {
            names.push(self.register(
                &instance,
                "_fax-ipp._tcp.local.",
                self.port,
                self.txt_record(p, false),
            )?);
        }

        // 3. `_ipp._tcp` with the full TXT record.
        names.push(self.register(
            &instance,
            "_ipp._tcp.local.",
            self.port,
            self.txt_record(p, false),
        )?);

        // 4. `_ipps._tcp` when TLS is enabled (`TLS=` in TXT).
        if self.tls {
            names.push(self.register(
                &instance,
                "_ipps._tcp.local.",
                self.port,
                self.txt_record(p, true),
            )?);
        }

        self.registered.insert(p.name.clone(), names);
        Ok(())
    }

    /// `cupsdDeregisterPrinter` — stop advertising a printer.
    pub fn unpublish(&mut self, name: &str) {
        if let Some(services) = self.registered.remove(name) {
            for full in services {
                let _ = self.daemon.unregister(&full);
            }
        }
    }

    /// `cupsdUpdateDNSSDName` — register the `_http._tcp` web UI.
    pub fn publish_webif(&mut self) -> std::io::Result<()> {
        let name = if self.computer.is_empty() {
            "CUPS".to_string()
        } else {
            format!("CUPS @ {}", self.computer)
        };
        let full = self.register(&name, "_http._tcp.local.", self.port, HashMap::new())?;
        self.webif = Some(full);
        Ok(())
    }

    /// Number of printers currently advertised.
    #[must_use]
    pub fn count(&self) -> usize {
        self.registered.len()
    }

    /// Register one service; returns its full-name for unregister.
    fn register(
        &self,
        instance: &str,
        regtype: &str,
        port: u16,
        txt: HashMap<String, String>,
    ) -> std::io::Result<String> {
        let info = ServiceInfo::new(
            regtype, instance, &self.host,
            "", // no static ip — let mdns-sd pick the host addrs
            port, txt,
        )
        .map_err(|e| std::io::Error::other(format!("service info: {e}")))?;
        let full = info.get_fullname().to_string();
        self.daemon
            .register(info)
            .map_err(|e| std::io::Error::other(format!("register {regtype}: {e}")))?;
        Ok(full)
    }

    /// Shut down — unregister all services.
    pub fn shutdown(self) {
        let _ = self.daemon.shutdown();
    }
}

/// `cupsdStartBrowsing`-style discovery — resolve `_ipp._tcp` (+`_ipps._tcp`)
/// services on the local network for `timeout`, returning each as a
/// [`RemotePrinter`] for the `dnssd` backend's device list.
#[must_use]
pub fn browse_ipp(timeout: Duration) -> Vec<RemotePrinter> {
    let Ok(daemon) = ServiceDaemon::new() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for regtype in ["_ipp._tcp.local.", "_ipps._tcp.local."] {
        let Ok(receiver) = daemon.browse(regtype) else {
            continue;
        };
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            match receiver.recv_timeout(Duration::from_millis(120)) {
                Ok(ServiceEvent::ServiceResolved(info)) => {
                    if let Some(rp) = info.get_property_val_str("rp") {
                        let host = info.get_hostname().trim_end_matches('.').to_string();
                        let port = info.get_port();
                        let scheme = if regtype.starts_with("_ipps") {
                            "ipps"
                        } else {
                            "ipp"
                        };
                        out.push(RemotePrinter {
                            uri: format!("{scheme}://{host}:{port}/{rp}"),
                            name: info.get_fullname().to_string(),
                            make_model: info
                                .get_property_val_str("ty")
                                .unwrap_or_default()
                                .to_string(),
                        });
                    }
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
        let _ = daemon.stop_browse(regtype);
    }
    let _ = daemon.shutdown();
    out
}

/// `hostname.local.` — ensure the mDNS host has the `.local.` suffix.
fn normalize_local(host: &str) -> String {
    let h = host.trim_end_matches('.');
    if h.to_ascii_lowercase().ends_with(".local") {
        format!("{h}.")
    } else {
        format!("{h}.local.")
    }
}

/// Resolve a `dnssd://<instance>._ipp._tcp.local/<rp>` device URI to a real
/// `ipp{s}://host:port/<rp>` URI — the dnssd backend's print-path resolution
/// (upstream `backend/dnssd.c` `cupsBackendResolve`). Returns `None` when the
/// service isn't on the wire within `timeout`.
#[must_use]
pub fn resolve_uri(device_uri: &str, timeout: Duration) -> Option<String> {
    // dnssd://<instance>._ipp(s)._tcp[.local][/<rp>]
    let rest = device_uri.strip_prefix("dnssd://")?;
    let (authority, rp) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i + 1..]),
        None => (rest, "ipp/print"),
    };
    // Determine regtype from the instance suffix.
    let (regtype, secure) = if authority.contains("._ipps.") {
        ("_ipps._tcp.local.", true)
    } else {
        ("_ipp._tcp.local.", false)
    };
    let instance = authority.trim_end_matches(".local.").to_string();

    let daemon = ServiceDaemon::new().ok()?;
    let receiver = daemon.browse(regtype).ok()?;
    let deadline = std::time::Instant::now() + timeout;
    let mut found = None;
    while std::time::Instant::now() < deadline && found.is_none() {
        if let Ok(ServiceEvent::ServiceResolved(info)) =
            receiver.recv_timeout(Duration::from_millis(120))
        {
            // Match by instance full-name (the part before the regtype).
            if info.get_fullname().starts_with(&instance) {
                let scheme = if secure { "ipps" } else { "ipp" };
                let host = info.get_hostname().trim_end_matches('.').to_string();
                found = Some(format!("{scheme}://{}:{}/{rp}", host, info.get_port()));
            }
        }
    }
    let _ = daemon.shutdown();
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_host() {
        assert_eq!(normalize_local("server"), "server.local.");
        assert_eq!(normalize_local("server.local."), "server.local.");
        assert_eq!(normalize_local("server.local"), "server.local.");
    }

    #[test]
    fn txt_record_keys() {
        let a = Advertiser::start("testhost", "Test", 631, true).unwrap();
        let p = SharedPrinter {
            name: "office".into(),
            info: "Office HP".into(),
            make_model: "HP LaserJet".into(),
            pdl: "application/pdf".into(),
            printer_type: 0x14,
            uuid: "urn:uuid:abc123".into(),
            ..Default::default()
        };
        let t = a.txt_record(&p, true);
        assert_eq!(t["rp"], "printers/office");
        assert_eq!(t["ty"], "HP LaserJet");
        assert_eq!(t["TLS"], "1.3");
        assert_eq!(t["UUID"], "abc123");
        assert_eq!(t["Duplex"], "T");
        assert_eq!(t["Color"], "T");
        assert_eq!(t["pdl"], "application/pdf");
        let _ = a;
    }

    #[test]
    fn instance_name() {
        let a = Advertiser::start("h", "Workstation", 631, false).unwrap();
        let p = SharedPrinter {
            name: "q".into(),
            info: "My Printer".into(),
            ..Default::default()
        };
        assert_eq!(a.instance(&p), "My Printer @ Workstation");
        let p2 = SharedPrinter {
            name: "q".into(),
            ..Default::default()
        };
        assert_eq!(a.instance(&p2), "q @ Workstation");
    }
}
