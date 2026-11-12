//! TLS for cupsd — a port of `cups/tls.c` + `scheduler/client.c`'s
//! `HTTP_STATE_TLS_*` / `cupsdCreateCert` behavior.
//!
//! Two entry modes:
//!  * `SSLListen`/`SSLPort` — TLS from the first byte (`Encryption Always`).
//!  * RFC 2817 `OPTIONS *` + `Upgrade: TLS/1.x` — `101 Switching Protocols`,
//!    then TLS on the same connection (`Encryption IfRequested/Required`).
//!
//! On first use cupsd generates a self-signed server cert at
//! `{ServerRoot}/ssl/server.crt|key` (upstream `cupsdCreateCert`), so the
//! daemon is TLS-ready without a CA. `SSLOptions` can later pin
//! MinTLSVersion/ciphers.

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;

/// Certificate + key material for the TLS listener.
pub struct ServerIdentity {
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

impl ServerIdentity {
    /// Build a `rustls::ServerConfig` (no client auth — CUPS does IPP auth
    /// at the application layer).
    #[must_use]
    pub fn server_config(&self) -> Arc<rustls::ServerConfig> {
        let cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(self.certs.clone(), self.key.clone_key())
            .expect("cert/key mismatch");
        Arc::new(cfg)
    }

    /// A `tokio-rustls` acceptor for `SslListen`-style sockets.
    #[must_use]
    pub fn acceptor(&self) -> TlsAcceptor {
        TlsAcceptor::from(self.server_config())
    }
}

/// Load `{dir}/server.crt|key`, generating a self-signed pair if absent
/// (`cupsdCreateCert`). `cn` is the cert CN/SAN (server hostname).
pub fn load_or_create(dir: &Path, cn: &str) -> std::io::Result<ServerIdentity> {
    let crt = dir.join("server.crt");
    let key = dir.join("server.key");
    if crt.exists() && key.exists() {
        if let Ok(id) = load(dir) {
            return Ok(id);
        }
        // fall through to regenerate on parse failure
    }
    create(dir, cn)
}

/// Generate a self-signed cert + write it (mode 0600 key) to `dir`.
fn create(dir: &Path, cn: &str) -> std::io::Result<ServerIdentity> {
    std::fs::create_dir_all(dir)?;
    let mut params = rcgen::CertificateParams::new(vec![cn.to_string()]).map_err(to_io)?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn.to_string());
    let pair = rcgen::KeyPair::generate().map_err(to_io)?;
    let cert = params.self_signed(&pair).map_err(to_io)?;
    let crt_pem = cert.pem();
    let key_pem = pair.serialize_pem();
    let crt_path = dir.join("server.crt");
    let key_path = dir.join("server.key");
    std::fs::write(&crt_path, &crt_pem)?;
    write_key(&key_path, &key_pem)?;
    load(dir)
}

fn load(dir: &Path) -> std::io::Result<ServerIdentity> {
    let crt_pem = std::fs::read(dir.join("server.crt"))?;
    let key_pem = std::fs::read(dir.join("server.key"))?;
    use rustls::pki_types::pem::PemObject;
    let certs = CertificateDer::pem_slice_iter(&crt_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(to_io)?;
    let key = PrivateKeyDer::from_pem_slice(&key_pem)
        .map_err(|_| io_err("no private key in server.key"))?;
    Ok(ServerIdentity { certs, key })
}

#[cfg(unix)]
fn write_key(path: &Path, pem: &str) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?
        .write_all(pem.as_bytes())
}
#[cfg(not(unix))]
fn write_key(path: &Path, pem: &str) -> std::io::Result<()> {
    std::fs::write(path, pem)
}

/// `ssl_dir` — `{ServerRoot}/ssl`.
#[must_use]
pub fn ssl_dir(server_root: &Path) -> PathBuf {
    server_root.join("ssl")
}

fn io_err(m: impl Into<String>) -> std::io::Error {
    std::io::Error::other(m.into())
}
fn to_io(e: impl std::fmt::Display) -> std::io::Error {
    io_err(e.to_string())
}
use std::io::Write;
