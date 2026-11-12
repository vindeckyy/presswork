//! `cupsd` — the print scheduler daemon.
//!
//! P0 milestone: boots, parses `cupsd.conf`/`cups-files.conf`, binds
//! every `Listen`/`SSLListen` address (TCP + unix socket), serves
//! static `GET`/`HEAD` from `DocumentRoot`, decodes `application/ipp`
//! POSTs, and answers unimplemented operations with an in-band IPP
//! `server-error-internal-error`. Real operation dispatch lands in P1
//! (`crates/ops`).

#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::io::{split, AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, UnixListener};

use cups_config::{Config, Diagnostic, ListenAddr, Paths, Severity};
use httpd::{Method, Request, Response, StatusCode};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn usage() -> &'static str {
    "Usage: cupsd [options]\n\
     Options:\n\
     \x20 -c config-file       Load the specified configuration file instead of\n\
     \x20                       the default cupsd.conf.\n\
     \x20 -s files-config       Load the specified cups-files.conf.\n\
     \x20 -t                    Test configuration, print result, and exit.\n\
     \x20 -f                    Stay in the foreground.\n\
     \x20 -l                    On-demand mode (socket activation).\n\
     \x20 -h                    Show this help.\n\
     \x20 -v                    Show version and exit.\n"
}

#[derive(Debug, Default, Clone)]
struct Args {
    server_root: Option<PathBuf>,
    test_config: bool,
    foreground: bool,
    on_demand: bool,
}

fn parse_args() -> Result<Option<Args>, i32> {
    let mut a = Args::default();
    let mut it = std::env::args_os().skip(1);
    while let Some(arg) = it.next() {
        let s = arg.to_string_lossy();
        match s.as_ref() {
            "-c" => {
                let p = it.next().map(PathBuf::from);
                a.server_root = p.as_ref().and_then(|p| p.parent().map(Path::to_path_buf));
            }
            "-s" => {
                // cups-files.conf override — resolve() handles same-dir
                // layouts; store root for now.
                let p = it.next().map(PathBuf::from);
                if let Some(par) = p.as_ref().and_then(|p| p.parent()) {
                    a.server_root.get_or_insert_with(|| par.to_path_buf());
                }
            }
            "-t" | "-C" => a.test_config = true,
            "-f" | "-F" => a.foreground = true,
            "-l" => a.on_demand = true,
            "-h" | "--help" => {
                print!("{}", usage());
                return Ok(None);
            }
            "-v" | "--version" => {
                println!("cupsd {VERSION} (presswork)");
                return Ok(None);
            }
            _ => {
                eprintln!("cupsd: bad option/argument '{s}'");
                return Err(1);
            }
        }
    }
    Ok(Some(a))
}

fn main() -> std::process::ExitCode {
    let args = match parse_args() {
        Ok(Some(a)) => a,
        Ok(None) => return std::process::ExitCode::SUCCESS,
        Err(c) => return std::process::ExitCode::from(c as u8),
    };

    let paths = Paths::resolve(args.server_root.as_deref());
    let outcome = cups_config::load(&paths);
    emit_diagnostics(&outcome.diagnostics);

    if args.test_config {
        return if outcome.ok {
            println!("{} is OK", paths.cupsd_conf.display());
            std::process::ExitCode::SUCCESS
        } else {
            eprintln!("{} contains errors", paths.cupsd_conf.display());
            std::process::ExitCode::from(1)
        };
    }
    if !outcome.ok {
        eprintln!("cupsd: unable to read configuration, exiting");
        return std::process::ExitCode::from(1);
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    rt.block_on(run(outcome.config, args))
}

fn emit_diagnostics(ds: &[Diagnostic]) {
    for e in ds {
        let lvl = match e.severity {
            Severity::Info => "I",
            Severity::Warn => "W",
            Severity::Error => "E",
        };
        eprintln!("{lvl} [{:>16}:{}] {}", e.file, e.line, e.message);
    }
}

async fn run(cfg: Config, _args: Args) -> std::process::ExitCode {
    let opts = Arc::new(httpd::ServerOptions {
        server_tokens: cfg.cupsd.server_header.clone(),
        max_body: usize::try_from(cfg.cupsd.max_request_size).unwrap_or(usize::MAX),
        idle_timeout: std::time::Duration::from_secs(u64::from(
            cfg.cupsd.timeout.clamp(0, 3600) as u32
        )),
        max_bad_requests: 4,
    });
    let doc_root = PathBuf::from(
        cfg.files
            .document_root
            .as_deref()
            .unwrap_or("/usr/share/cups/doc-root"),
    );

    // Bind all listeners.
    let mut join = tokio::task::JoinSet::new();
    let mut bound = 0usize;
    for ln in &cfg.cupsd.listeners {
        match &ln.addr {
            ListenAddr::Tcp(addr) => match TcpListener::bind(addr).await {
                Ok(l) => {
                    bound += 1;
                    eprintln!(
                        "cupsd: listening on {addr}{}",
                        if ln.ssl { " (TLS)" } else { "" }
                    );
                    join.spawn(accept_tcp(l, ln.ssl, opts.clone(), doc_root.clone()));
                }
                Err(e) => eprintln!("cupsd: cannot bind {addr}: {e}"),
            },
            ListenAddr::Unix(path) => match bind_unix(path) {
                Ok(l) => {
                    bound += 1;
                    eprintln!("cupsd: listening on {}", path.display());
                    join.spawn(accept_unix(l, opts.clone(), doc_root.clone()));
                }
                Err(e) => eprintln!("cupsd: cannot bind {}: {e}", path.display()),
            },
        }
    }
    if bound == 0 {
        eprintln!("cupsd: no listeners bound, exiting");
        return std::process::ExitCode::from(1);
    }
    eprintln!("cupsd {VERSION}: ready on {bound} listener(s)");

    let mut sigint =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()).expect("signal");
    let mut sigterm =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("signal");
    tokio::select! {
        _ = sigint.recv() => {}
        _ = sigterm.recv() => {}
        _ = join.join_next() => {}
    }
    join.abort_all();
    eprintln!("cupsd: shutdown");
    std::process::ExitCode::SUCCESS
}

fn bind_unix(p: &Path) -> std::io::Result<UnixListener> {
    if p.exists() {
        std::fs::remove_file(p)?;
    }
    if let Some(dir) = p.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let l = UnixListener::bind(p)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o777))?;
    Ok(l)
}

async fn accept_tcp(
    listener: TcpListener,
    ssl: bool,
    opts: Arc<httpd::ServerOptions>,
    doc_root: PathBuf,
) {
    let _ = ssl; // TLS acceptor lands with cups-tls (P5)
    loop {
        match listener.accept().await {
            Ok((stream, _peer)) => {
                let opts = opts.clone();
                let doc_root = doc_root.clone();
                tokio::spawn(async move { serve_one(stream, opts, doc_root).await });
            }
            Err(e) => {
                eprintln!("cupsd: accept: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
}

async fn accept_unix(listener: UnixListener, opts: Arc<httpd::ServerOptions>, doc_root: PathBuf) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let opts = opts.clone();
                let doc_root = doc_root.clone();
                tokio::spawn(async move { serve_one(stream, opts, doc_root).await });
            }
            Err(e) => {
                eprintln!("cupsd: unix accept: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
}

async fn serve_one<S>(stream: S, opts: Arc<httpd::ServerOptions>, doc_root: PathBuf)
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let (mut rd, mut wr) = split(stream);
    let _ = httpd::serve_connection(&mut rd, &mut wr, &opts, move |req| {
        dispatch(&req, &doc_root)
    })
    .await;
}

/// P0 request dispatch.
fn dispatch(req: &Request, doc_root: &Path) -> Response {
    match req.method {
        Method::Get | Method::Head => static_get(&req.uri, doc_root),
        Method::Post
            if req.content_type().is_some_and(|c| {
                c.split(';')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .eq_ignore_ascii_case("application/ipp")
            }) =>
        {
            ipp_stub(req)
        }
        Method::Options if req.wants_tls_upgrade => Response::status(StatusCode::UPGRADE_REQUIRED),
        Method::Options => Response::status(StatusCode::OK),
        _ => Response::status(StatusCode::NOT_IMPLEMENTED),
    }
}

fn static_get(uri: &str, doc_root: &Path) -> Response {
    let path_part = uri.split(['?', '#']).next().unwrap_or("/");
    if path_part.contains("..") {
        return Response::status(StatusCode::FORBIDDEN);
    }
    let rel = path_part.trim_start_matches('/');
    let file = doc_root.join(if rel.is_empty() { "index.html" } else { rel });
    match std::fs::read(&file) {
        Ok(bytes) => Response::with_body(StatusCode::OK, mime_guess(&file), bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Response::status(StatusCode::NOT_FOUND)
        }
        Err(_) => Response::status(StatusCode::FORBIDDEN),
    }
}

fn mime_guess(p: &Path) -> &'static str {
    match p.extension().and_then(|e| e.to_str()).unwrap_or("") {
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "png" => "image/png",
        "gif" => "image/gif",
        "ico" => "image/vnd.microsoft.icon",
        "jpg" | "jpeg" => "image/jpeg",
        "txt" => "text/plain",
        _ => "application/octet-stream",
    }
}

/// Decode the IPP request and answer in-band: same version + request-id,
/// `server-error-internal-error` — the shape a client sees from real
/// cupsd for an op it can't service, so `ipptool` framing tests pass.
fn ipp_stub(req: &Request) -> Response {
    match ipp_codec::decode(req.body.as_bytes()) {
        Ok((msg, _consumed)) => {
            let mut out = ipp_codec::IppMessage::new(ipp_codec::ops::status::ERROR_INTERNAL);
            out.request_id = msg.request_id;
            out.version = msg.version;
            match ipp_codec::encode(&out) {
                Ok(b) => Response::ipp(StatusCode::OK, b),
                Err(_) => Response::status(StatusCode::INTERNAL),
            }
        }
        Err(_) => Response::status(StatusCode::BAD_REQUEST),
    }
}
