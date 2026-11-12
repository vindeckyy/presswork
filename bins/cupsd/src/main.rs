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

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, UnixListener};

use cups_config::{Config, Diagnostic, ListenAddr, Paths, Severity};
use httpd::{Method, Request, Response, StatusCode};
mod cgi;
use printer::Registry;

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
        Err(c) => return std::process::ExitCode::from(u8::try_from(c).unwrap_or(1)),
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
    rt.block_on(run(outcome.config, args, paths))
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

#[allow(clippy::too_many_lines)] // daemon bootstraps every subsystem inline
async fn run(cfg: Config, _args: Args, paths: Paths) -> std::process::ExitCode {
    let cfg = Arc::new(cfg);
    let opts = Arc::new(httpd::ServerOptions {
        server_tokens: cfg.cupsd.server_header.clone(),
        max_body: usize::try_from(cfg.cupsd.max_request_size).unwrap_or(usize::MAX),
        idle_timeout: std::time::Duration::from_secs(u64::from(
            u32::try_from(cfg.cupsd.timeout.clamp(0, 3600)).unwrap_or(3600),
        )),
        max_bad_requests: 4,
    });
    let doc_root = PathBuf::from(
        cfg.files
            .document_root
            .as_deref()
            .unwrap_or("/usr/share/cups/doc-root"),
    );

    // Registry: load printers.conf (+ classes.conf uses same parser).
    let mut registry = Registry {
        next_printer_id: 1,
        next_job_id: 1,
        ..Registry::default()
    };
    let proot = PathBuf::from(
        cfg.files
            .request_root
            .as_deref()
            .unwrap_or("/var/spool/cups"),
    );
    let proot = proot.parent().unwrap_or(&proot).to_path_buf();
    for f in ["printers.conf", "classes.conf"] {
        let p = paths.server_root.join(f);
        match registry.load_printers_file(&p) {
            Ok(errs) => {
                for e in errs {
                    eprintln!("cupsd: {e}");
                }
            }
            Err(e) => eprintln!("cupsd: cannot read {}: {e}", p.display()),
        }
    }
    let _ = proot;
    let registry = std::sync::Arc::new(std::sync::RwLock::new(registry));

    // Job table (RequestRoot) + MIME database (ServerRoot or DataDir).
    let request_root = cfg
        .files
        .request_root
        .clone()
        .unwrap_or_else(|| "/var/spool/cups".into());
    let subs = Arc::new(std::sync::RwLock::new(events::Subscriptions::new()));
    let dnssd_state = Arc::new(std::sync::RwLock::new(None::<dnssd::Advertiser>));
    let jobs = Arc::new(std::sync::RwLock::new(job::Jobs::load_all(
        std::path::Path::new(&request_root),
    )));
    let mime_dir = cfg
        .files
        .data_dir
        .clone()
        .unwrap_or_else(|| "/usr/share/cups".into());
    let mime = Arc::new(mime_db::MimeDb::load(std::path::Path::new(&mime_dir)).unwrap_or_default());
    let server_root = Arc::new(paths.server_root.clone());

    // Log sinks — error_log always (foreground → stderr), access_log
    // when configured.
    let log = Arc::new(Logs {
        error: cfg
            .files
            .error_log
            .as_deref()
            .map_or_else(cups_log::Sink::stderr, cups_log::Sink::file),
        access: cfg
            .files
            .access_log
            .as_deref()
            .map_or_else(cups_log::Sink::stderr, cups_log::Sink::file),
        time_fmt: match cfg.cupsd.log_time_format {
            cups_config::LogTimeFormat::Usecs => cups_log::TimeFormat::Usecs,
            cups_config::LogTimeFormat::Standard => cups_log::TimeFormat::Standard,
        },
    });

    // TLS identity — load {ServerRoot}/ssl/server.crt|key, generating a
    // self-signed pair on first boot (upstream `cupsdCreateCert`). Built
    // unconditionally so it can serve both `SSLListen` first-byte sockets and
    // the RFC 2817 upgrade on plain listeners.
    let tls = match cups_tls::load_or_create(&cups_tls::ssl_dir(&server_root), &hostname())
        .map(|id| id.acceptor())
    {
        Ok(acc) => {
            log.err(
                cups_log::Level::Info,
                format!(
                    "Using self-signed TLS certificate in {}",
                    cups_tls::ssl_dir(&server_root).display()
                ),
            );
            Some(Arc::new(acc))
        }
        Err(e) => {
            log.err(
                cups_log::Level::Warn,
                format!("Unable to set up TLS ({e}); encryption disabled"),
            );
            None
        }
    };

    // DNS-SD (`cupsdStartBrowsing`/`dnssdRegisterPrinter`) — advertise shared
    // printers when `Browsing` + `BrowseLocalProtocols dnssd` are enabled.
    {
        let port = cfg
            .cupsd
            .listeners
            .iter()
            .find_map(|l| match &l.addr {
                ListenAddr::Tcp(a) => Some(a.port()),
                ListenAddr::Unix(_) => None,
            })
            .unwrap_or(631);
        let dnssd_on = cfg.cupsd.browsing
            && cfg.cupsd.browse_local_protocols.0 & cups_config::BrowseProtocols::DNSSD.0 != 0;
        if dnssd_on {
            let host = cfg.cupsd.dnssd_host_name.clone().unwrap_or_else(hostname);
            let computer = cfg
                .cupsd
                .dnssd_computer_name
                .clone()
                .unwrap_or_else(hostname);
            match dnssd::Advertiser::start(&host, &computer, port, tls.is_some()) {
                Ok(mut adv) => {
                    // Publish every currently-shared queue.
                    let reg = registry
                        .read()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    let mut n = 0;
                    for p in reg.printers.values() {
                        if p.shared {
                            let _ = adv.publish(&dnssd::SharedPrinter {
                                name: p.name.clone(),
                                info: p.info.clone().unwrap_or_default(),
                                make_model: p.make_model.clone().unwrap_or_default(),
                                location: p.location.clone().unwrap_or_default(),
                                pdl: String::new(),
                                printer_type: u32::try_from(p.ptype).unwrap_or_default(),
                                printer_state: p.state,
                                uuid: p.uuid.clone(),
                                is_class: p.ptype & printer::ptype::CLASS != 0,
                                is_fax: p.ptype & printer::ptype::FAX != 0,
                            });
                            n += 1;
                        }
                    }
                    drop(reg);
                    log.err(
                        cups_log::Level::Info,
                        format!("DNS-SD advertising {n} shared printer(s) on {host}"),
                    );
                    *dnssd_state
                        .write()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(adv);
                }
                Err(e) => log.err(
                    cups_log::Level::Warn,
                    format!("DNS-SD unavailable ({e}); sharing disabled"),
                ),
            }
        }
    }

    // systemd socket activation — `cups.socket` hands us pre-bound
    // listeners on fds 3+N (`sd_listen_fds`). When present they take
    // precedence over `Listen` directives.
    let activated = sys::sd_listen_fds();
    let mut join = tokio::task::JoinSet::new();
    let mut bound = 0usize;
    for fd in activated {
        use std::os::fd::{AsRawFd, IntoRawFd};
        match sys::socket_family(fd.as_raw_fd()) {
            f if f == libc::AF_UNIX => {
                let std_l = std::os::unix::net::UnixListener::from(fd);
                std_l.set_nonblocking(true).ok();
                match UnixListener::from_std(std_l) {
                    Ok(l) => {
                        bound += 1;
                        log.err(cups_log::Level::Info, "Listening on activated unix socket.");
                        join.spawn(accept_unix(
                            l,
                            tls.clone(),
                            opts.clone(),
                            doc_root.clone(),
                            registry.clone(),
                            cfg.clone(),
                            log.clone(),
                            jobs.clone(),
                            mime.clone(),
                            subs.clone(),
                            dnssd_state.clone(),
                            server_root.clone(),
                        ));
                    }
                    Err(e) => log.err(
                        cups_log::Level::Error,
                        format!("activated unix socket: {e}"),
                    ),
                }
            }
            f if f == libc::AF_INET || f == libc::AF_INET6 => {
                let std_l = std::net::TcpListener::from(fd);
                std_l.set_nonblocking(true).ok();
                match TcpListener::from_std(std_l) {
                    Ok(l) => {
                        bound += 1;
                        log.err(cups_log::Level::Info, "Listening on activated TCP socket.");
                        join.spawn(accept_tcp(
                            l,
                            false,
                            tls.clone(),
                            opts.clone(),
                            doc_root.clone(),
                            registry.clone(),
                            cfg.clone(),
                            log.clone(),
                            jobs.clone(),
                            mime.clone(),
                            subs.clone(),
                            dnssd_state.clone(),
                            server_root.clone(),
                        ));
                    }
                    Err(e) => log.err(cups_log::Level::Error, format!("activated socket: {e}")),
                }
            }
            _ => {
                let _ = fd.into_raw_fd(); // unknown family — leak rather than close wrongly
            }
        }
    }

    // Bind configured listeners (skipped under socket activation).
    for ln in if bound == 0 {
        &cfg.cupsd.listeners[..]
    } else {
        &[][..]
    } {
        match &ln.addr {
            ListenAddr::Tcp(addr) => match TcpListener::bind(addr).await {
                Ok(l) => {
                    bound += 1;
                    log.err(
                        cups_log::Level::Info,
                        format!(
                            "Listening for client connections on {addr}{}",
                            if ln.ssl { " (TLS)" } else { "" }
                        ),
                    );
                    join.spawn(accept_tcp(
                        l,
                        ln.ssl,
                        tls.clone(),
                        opts.clone(),
                        doc_root.clone(),
                        registry.clone(),
                        cfg.clone(),
                        log.clone(),
                        jobs.clone(),
                        mime.clone(),
                        subs.clone(),
                        dnssd_state.clone(),
                        server_root.clone(),
                    ));
                }
                Err(e) => log.err(
                    cups_log::Level::Error,
                    format!("Unable to open listen socket for address {addr} - {e}"),
                ),
            },
            ListenAddr::Unix(path) => match bind_unix(path) {
                Ok(l) => {
                    bound += 1;
                    log.err(
                        cups_log::Level::Info,
                        format!("Listening for client connections on {}.", path.display()),
                    );
                    join.spawn(accept_unix(
                        l,
                        tls.clone(),
                        opts.clone(),
                        doc_root.clone(),
                        registry.clone(),
                        cfg.clone(),
                        log.clone(),
                        jobs.clone(),
                        mime.clone(),
                        subs.clone(),
                        dnssd_state.clone(),
                        server_root.clone(),
                    ));
                }
                Err(e) => log.err(
                    cups_log::Level::Error,
                    format!(
                        "Unable to open listen socket for address {} - {e}",
                        path.display()
                    ),
                ),
            },
        }
    }
    if bound == 0 {
        log.err(cups_log::Level::Error, "No listeners bound, exiting.");
        return std::process::ExitCode::from(1);
    }
    log.err(
        cups_log::Level::Info,
        format!("cupsd {VERSION} ready on {bound} listener(s)"),
    );

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
    log.err(cups_log::Level::Info, "Scheduler shutting down.");
    std::process::ExitCode::SUCCESS
}

fn bind_unix(p: &Path) -> std::io::Result<UnixListener> {
    use std::os::unix::fs::PermissionsExt;
    if p.exists() {
        std::fs::remove_file(p)?;
    }
    if let Some(dir) = p.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let l = UnixListener::bind(p)?;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o777))?;
    Ok(l)
}

#[allow(clippy::too_many_arguments)] // threads daemon ctx through the accept loop
async fn accept_tcp(
    listener: TcpListener,
    ssl_first_byte: bool,
    tls: Option<Arc<tokio_rustls::TlsAcceptor>>,
    opts: Arc<httpd::ServerOptions>,
    doc_root: PathBuf,
    registry: Arc<std::sync::RwLock<Registry>>,
    cfg: Arc<Config>,
    log: Arc<Logs>,
    jobs: Arc<std::sync::RwLock<job::Jobs>>,
    mime: Arc<mime_db::MimeDb>,
    subs: Arc<std::sync::RwLock<events::Subscriptions>>,
    dnssd_state: Arc<std::sync::RwLock<Option<dnssd::Advertiser>>>,
    server_root: Arc<PathBuf>,
) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let opts = opts.clone();
                let doc_root = doc_root.clone();
                let registry = registry.clone();
                let cfg = cfg.clone();
                let local = peer.ip().is_loopback();
                let port = stream.local_addr().map_or(631, |a| a.port());
                let host = peer.ip().to_string();
                let log = log.clone();
                let jobs = jobs.clone();
                let mime = mime.clone();
                let subs = subs.clone();
                let dnssd_state = dnssd_state.clone();
                let server_root = server_root.clone();
                let client_addr = peer.ip();
                let tls = tls.clone();
                tokio::spawn(async move {
                    serve_one(
                        stream,
                        opts,
                        doc_root,
                        registry,
                        cfg,
                        port,
                        local,
                        log,
                        host,
                        jobs,
                        mime,
                        subs,
                        dnssd_state,
                        server_root,
                        client_addr,
                        tls,
                        ssl_first_byte,
                        None,
                    )
                    .await;
                });
            }
            Err(e) => {
                eprintln!("cupsd: accept: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn accept_unix(
    listener: UnixListener,
    tls: Option<Arc<tokio_rustls::TlsAcceptor>>,
    opts: Arc<httpd::ServerOptions>,
    doc_root: PathBuf,
    registry: Arc<std::sync::RwLock<Registry>>,
    cfg: Arc<Config>,
    log: Arc<Logs>,
    jobs: Arc<std::sync::RwLock<job::Jobs>>,
    mime: Arc<mime_db::MimeDb>,
    subs: Arc<std::sync::RwLock<events::Subscriptions>>,
    dnssd_state: Arc<std::sync::RwLock<Option<dnssd::Advertiser>>>,
    server_root: Arc<PathBuf>,
) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                // `SO_PEERCRED` (upstream `cupsdAuthorize` PeerCred path) —
                // the kernel-verified uid gives the connecting user's real
                // name + groups, so local clients authenticate without a
                // password (and cannot claim a different user).
                use std::os::fd::AsRawFd;
                let peer_auth = sys::peer_cred(stream.as_raw_fd()).and_then(|(_, uid, _)| {
                    sys::name_of_uid(uid).map(|u| (u.clone(), sys::groups_of(&u)))
                });
                let opts = opts.clone();
                let doc_root = doc_root.clone();
                let registry = registry.clone();
                let cfg = cfg.clone();
                let log = log.clone();
                let jobs = jobs.clone();
                let mime = mime.clone();
                let subs = subs.clone();
                let dnssd_state = dnssd_state.clone();
                let server_root = server_root.clone();
                let tls = tls.clone();
                tokio::spawn(async move {
                    serve_one(
                        stream,
                        opts,
                        doc_root,
                        registry,
                        cfg,
                        631,
                        true,
                        log,
                        "localhost".to_string(),
                        jobs,
                        mime,
                        subs,
                        dnssd_state,
                        server_root,
                        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                        tls,
                        false,
                        peer_auth,
                    )
                    .await;
                });
            }
            Err(e) => {
                eprintln!("cupsd: unix accept: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn serve_one<S>(
    stream: S,
    opts: Arc<httpd::ServerOptions>,
    doc_root: PathBuf,
    registry: Arc<std::sync::RwLock<Registry>>,
    cfg: Arc<Config>,
    port: u16,
    local: bool,
    log: Arc<Logs>,
    host: String,
    jobs: Arc<std::sync::RwLock<job::Jobs>>,
    mime: Arc<mime_db::MimeDb>,
    subs: Arc<std::sync::RwLock<events::Subscriptions>>,
    dnssd_state: Arc<std::sync::RwLock<Option<dnssd::Advertiser>>>,
    server_root: Arc<PathBuf>,
    client_addr: std::net::IpAddr,
    tls: Option<Arc<tokio_rustls::TlsAcceptor>>,
    ssl_first_byte: bool,
    peer_auth: Option<(String, Vec<String>)>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut stream = stream;

    // `SSLListen` — TLS from the first byte.
    if ssl_first_byte {
        if let Some(acc) = &tls {
            if let Ok(mut ts) = acc.accept(stream).await {
                serve_conn(
                    &mut ts,
                    &opts,
                    true,
                    ConnArgs {
                        doc_root: doc_root.as_path(),
                        registry: registry.as_ref(),
                        cfg: cfg.as_ref(),
                        port,
                        local,
                        log: &log,
                        host: &host,
                        jobs: &jobs,
                        mime: &mime,
                        subs: &subs,
                        dnssd_state: &dnssd_state,
                        server_root: server_root.as_path(),
                        client_addr,
                        peer: &peer_auth,
                    },
                )
                .await;
            }
        }
        return;
    }

    // Plain connection. `OPTIONS *`+`Upgrade: TLS/1.x` -> 101 -> wrap+reserve.
    let upgraded = std::sync::atomic::AtomicBool::new(false);
    {
        let handler = |req: Request| {
            let mut r = dispatch_req(
                &req,
                &doc_root,
                &registry,
                &cfg,
                port,
                local,
                &log,
                &host,
                &jobs,
                &mime,
                &subs,
                &dnssd_state,
                &server_root,
                client_addr,
                false,
                &peer_auth,
            );
            if req.wants_tls_upgrade && tls.is_some() {
                upgraded.store(true, std::sync::atomic::Ordering::SeqCst);
                r.status = StatusCode::SWITCHING_PROTOCOLS;
            }
            r
        };
        let _ = httpd::serve_connection(&mut stream, &opts, handler).await;
    }
    if upgraded.load(std::sync::atomic::Ordering::SeqCst) {
        if let Some(acc) = &tls {
            if let Ok(mut ts) = acc.accept(stream).await {
                serve_conn(
                    &mut ts,
                    &opts,
                    true,
                    ConnArgs {
                        doc_root: doc_root.as_path(),
                        registry: registry.as_ref(),
                        cfg: cfg.as_ref(),
                        port,
                        local,
                        log: &log,
                        host: &host,
                        jobs: &jobs,
                        mime: &mime,
                        subs: &subs,
                        dnssd_state: &dnssd_state,
                        server_root: server_root.as_path(),
                        client_addr,
                        peer: &peer_auth,
                    },
                )
                .await;
            }
        }
    }
}

/// Shared connection args for `serve_conn`.
struct ConnArgs<'a> {
    doc_root: &'a Path,
    registry: &'a std::sync::RwLock<Registry>,
    cfg: &'a Config,
    port: u16,
    local: bool,
    log: &'a Arc<Logs>,
    host: &'a str,
    jobs: &'a Arc<std::sync::RwLock<job::Jobs>>,
    mime: &'a Arc<mime_db::MimeDb>,
    subs: &'a Arc<std::sync::RwLock<events::Subscriptions>>,
    dnssd_state: &'a Arc<std::sync::RwLock<Option<dnssd::Advertiser>>>,
    server_root: &'a Path,
    client_addr: std::net::IpAddr,
    peer: &'a Option<(String, Vec<String>)>,
}

/// `serve_connection` bound to a `dispatch_req` closure.
async fn serve_conn<S>(
    stream: &mut S,
    opts: &httpd::ServerOptions,
    encrypted: bool,
    a: ConnArgs<'_>,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let _ = httpd::serve_connection(stream, opts, |req| {
        dispatch_req(
            &req,
            a.doc_root,
            a.registry,
            a.cfg,
            a.port,
            a.local,
            a.log,
            a.host,
            a.jobs,
            a.mime,
            a.subs,
            a.dnssd_state,
            a.server_root,
            a.client_addr,
            encrypted,
            a.peer,
        )
    })
    .await;
}

/// Error + access log sinks shared per-request.
struct Logs {
    error: cups_log::Sink,
    access: cups_log::Sink,
    time_fmt: cups_log::TimeFormat,
}

impl Logs {
    /// `cupsdWriteErrorLog()` — `error_log` line (mirrors `E [time] msg`),
    /// echoed to stderr like upstream's foreground mode.
    fn err(&self, level: cups_log::Level, msg: impl AsRef<str>) {
        let line = cups_log::error_line(level, self.time_fmt, msg.as_ref());
        self.error.write(&line);
        eprintln!("cupsd: {}", msg.as_ref());
    }
}

/// Request dispatch: static files, IPP ops, misc.
#[allow(clippy::too_many_arguments, clippy::ref_option)]
fn dispatch_req(
    req: &Request,
    doc_root: &Path,
    registry: &std::sync::RwLock<Registry>,
    cfg: &Config,
    port: u16,
    local: bool,
    log: &Arc<Logs>,
    host: &str,
    jobs: &Arc<std::sync::RwLock<job::Jobs>>,
    mime: &Arc<mime_db::MimeDb>,
    subs: &Arc<std::sync::RwLock<events::Subscriptions>>,
    dnssd_state: &Arc<std::sync::RwLock<Option<dnssd::Advertiser>>>,
    server_root: &std::path::Path,
    client_addr: std::net::IpAddr,
    encrypted: bool,
    peer: &Option<(String, Vec<String>)>,
) -> Response {
    let server_bin =
        std::path::Path::new(cfg.files.server_bin.as_deref().unwrap_or("/usr/lib/cups"));
    match req.method {
        Method::Get | Method::Head => cgi::dispatch(
            &req.uri,
            server_bin,
            req,
            client_addr,
            host,
            port,
            encrypted,
        )
        .unwrap_or_else(|| static_get(&req.uri, doc_root)),
        Method::Post
            if req.content_type().is_some_and(|c| {
                c.split(';')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .eq_ignore_ascii_case("application/ipp")
            }) =>
        {
            ipp_dispatch(
                req,
                registry,
                cfg,
                port,
                local,
                log,
                host,
                jobs,
                mime,
                subs,
                dnssd_state,
                server_root,
                client_addr,
                encrypted,
                peer,
            )
        }
        Method::Options if req.wants_tls_upgrade => Response::status(StatusCode::UPGRADE_REQUIRED),
        Method::Options => {
            log_access(log, host, req, 200, 0, "-", "-");
            Response::status(StatusCode::OK)
        }
        Method::Post => cgi::dispatch(
            &req.uri,
            server_bin,
            req,
            client_addr,
            host,
            port,
            encrypted,
        )
        .unwrap_or_else(|| Response::status(StatusCode::NOT_IMPLEMENTED)),
        _ => {
            log_access(log, host, req, 501, 0, "-", "-");
            Response::status(StatusCode::NOT_IMPLEMENTED)
        }
    }
}

/// `cupsdLogRequest()` — `access_log` line after serving.
fn log_access(
    log: &Logs,
    host: &str,
    req: &Request,
    code: u16,
    bytes: u64,
    op_name: &str,
    status_name: &str,
) {
    let (maj, min) = match req.version {
        httpd::HttpVersion::V09 => (0, 9),
        httpd::HttpVersion::V10 => (1, 0),
        _ => (1, 1),
    };
    let line = cups_log::access_line(
        host,
        None,
        log.time_fmt,
        req.method.as_str(),
        &req.uri,
        (maj, min),
        code,
        bytes,
        op_name,
        status_name,
        None,
    );
    log.access.write(&line);
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

/// Decode the IPP request, run the op dispatcher, re-encode the
/// response — the `cupsdProcessIPPRequest` equivalent.
#[allow(clippy::too_many_arguments, clippy::ref_option)]
fn ipp_dispatch(
    req: &Request,
    registry: &std::sync::RwLock<Registry>,
    cfg: &Config,
    port: u16,
    local: bool,
    log: &Arc<Logs>,
    host: &str,
    jobs: &Arc<std::sync::RwLock<job::Jobs>>,
    mime: &Arc<mime_db::MimeDb>,
    subs: &Arc<std::sync::RwLock<events::Subscriptions>>,
    dnssd_state: &Arc<std::sync::RwLock<Option<dnssd::Advertiser>>>,
    server_root: &std::path::Path,
    client_addr: std::net::IpAddr,
    encrypted: bool,
    peer: &Option<(String, Vec<String>)>,
) -> Response {
    let Ok((msg, consumed)) = ipp_codec::decode(req.body.as_bytes()) else {
        log_access(log, host, req, 400, 0, "-", "-");
        return Response::status(StatusCode::BAD_REQUEST);
    };
    let document = &req.body.as_bytes()[consumed..];
    let mut ctx = ops::Ctx::new(
        registry,
        cfg,
        port,
        jobs.as_ref(),
        mime.as_ref(),
        subs.as_ref(),
        dnssd_state.as_ref(),
    );
    ctx.is_local = local;
    ctx.is_encrypted = encrypted;
    // httpGetHostname: prefer the request's Host header for generated URIs.
    if let Some(h) = req.headers.get("host") {
        ctx.hostname = h.split(':').next().unwrap_or(h).to_string();
    } else {
        ctx.hostname = hostname();
    }
    ctx.document = document;
    ctx.server_root = server_root.to_path_buf();
    ctx.client_addr = client_addr;
    // Basic auth: Authorization header -> authenticated user + groups.
    if let Some(h) = req.headers.get("authorization") {
        if let Some(creds) = authn::parse(h) {
            if let Some((user, groups)) = authn::authenticate(&creds) {
                ctx.user_groups = groups;
                ctx.username = Some(user);
            }
        }
    }
    // `SO_PEERCRED` fallback (unix socket only): when no credentials were
    // supplied, authenticate as the kernel-verified peer user — upstream
    // `cupsdAuthorize` PeerCred semantics for local clients.
    if ctx.username.is_none() {
        if let Some((user, groups)) = peer {
            ctx.user_groups.clone_from(groups);
            ctx.username = Some(user.clone());
        }
    }
    let resp = ops::dispatch(&msg, &ctx);
    // Scheduler tick: pick next pending job on an idle printer and spawn
    // its filter->backend pipeline (mirrors start_job being driven by the
    // scheduler's event loop).
    schedule_tick(jobs, subs, registry, mime, cfg, log);
    let op_name = ipp_codec::ops::op::name(msg.code);
    let status_name = ipp_codec::ops::status::name(resp.code);
    match ipp_codec::encode(&resp) {
        Ok(b) => {
            let n = b.len() as u64;
            log_access(log, host, req, 200, n, op_name, status_name);
            Response::ipp(StatusCode::OK, b)
        }
        Err(_) => Response::status(StatusCode::INTERNAL),
    }
}

/// Fetch a queue's PPD text via `cups-driverd cat <ppd-name>` — the stored
/// `Option ppd-name` (driver selection) wins, else the driverless `everywhere`
/// model. Returns `None` when the helper can't produce one.
fn printer_ppd(p: &printer::Printer, server_bin: &std::path::Path) -> Option<String> {
    let name = p
        .options
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("ppd-name"))
        .map_or_else(|| "everywhere".to_string(), |(_, v)| v.clone());
    let driverd = server_bin.join("daemon").join("cups-driverd");
    let base = server_bin.parent().map_or_else(
        || std::path::PathBuf::from("/usr/share"),
        std::path::Path::to_path_buf,
    );
    let out = std::process::Command::new(driverd)
        .args(["cat", &name])
        .env("PPDDIR", base.join("ppd"))
        .env("DRVROOT", base.join("drv"))
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Parse a PPD's `*cupsFilter` and `*cupsFilter2` lines into
/// `(final_mime, cost, program)` candidates — the device-consumable formats
/// and the final driver filter for each.
fn ppd_filters(ppd: &str) -> Vec<(String, u32, String)> {
    let mut out = Vec::new();
    for line in ppd.lines() {
        let Some(rest) = line
            .trim()
            .strip_prefix("*cupsFilter")
            .or_else(|| line.trim().strip_prefix("*cupsFilter2"))
        else {
            continue;
        };
        // `*cupsFilter: "mime cost prog"` / `*cupsFilter2: "dst src cost prog"`.
        let val = rest
            .split_once(':')
            .map_or("", |(_, v)| v.trim().trim_matches('"'));
        let parts: Vec<&str> = val.split_whitespace().collect();
        if line.contains("cupsFilter2") {
            if parts.len() >= 4 {
                out.push((
                    parts[0].into(),
                    parts[2].parse().unwrap_or(0),
                    parts[3].into(),
                ));
            }
        } else if parts.len() >= 3 {
            out.push((
                parts[0].into(),
                parts[1].parse().unwrap_or(0),
                parts[2].into(),
            ));
        }
    }
    out
}

/// Pick the device-consumable MIME a queue's PPD declares — the cheapest
/// `*cupsFilter`/`*cupsFilter2` target. `None` → caller uses the raw default.
fn ppd_final_type(p: &printer::Printer, server_bin: &std::path::Path) -> Option<String> {
    let ppd = printer_ppd(p, server_bin)?;
    let mut fs = ppd_filters(&ppd);
    if fs.is_empty() {
        return None;
    }
    fs.sort_by_key(|(_, cost, _)| *cost);
    Some(fs[0].0.clone())
}

/// The PPD's final driver filter for `dst` — `program != "-"` runs as the
/// last stage before the backend (e.g. `rastertofoo`).
fn ppd_final_filter(
    p: &printer::Printer,
    server_bin: &std::path::Path,
    dst: &str,
) -> Option<mime_db::Conv> {
    let ppd = printer_ppd(p, server_bin)?;
    ppd_filters(&ppd)
        .into_iter()
        .filter(|(_, _, prog)| prog != "-")
        .find(|(d, _, _)| d == dst)
        .map(|(d, cost, prog)| mime_db::Conv {
            src: d,
            dst: "application/vnd.cups-raw".into(),
            cost,
            program: prog,
        })
}

/// `start_job` scheduler tick — pick the first pending job whose printer is
/// idle + accepting, resolve its filter chain, and spawn the pipeline in a
/// watcher thread that marks the job completed/aborted on exit.
#[allow(clippy::too_many_lines)]
fn schedule_tick(
    jobs: &Arc<std::sync::RwLock<job::Jobs>>,
    subs: &Arc<std::sync::RwLock<events::Subscriptions>>,
    registry: &std::sync::RwLock<Registry>,
    mime: &mime_db::MimeDb,
    cfg: &Config,
    log: &Arc<Logs>,
) {
    let request_root = std::path::PathBuf::from(
        cfg.files
            .request_root
            .clone()
            .unwrap_or_else(|| "/var/spool/cups".into()),
    );
    let server_bin = std::path::PathBuf::from(
        cfg.files
            .server_bin
            .clone()
            .unwrap_or_else(|| "/usr/lib/cups".into()),
    );

    let found: Option<(i32, pipeline::JobSpec, String, String)> = {
        let jobs_r = jobs
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let reg = registry
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut out = None;
        for j in jobs_r.active() {
            if j.state != job::JobState::Pending || j.backend_pid.is_some() {
                continue;
            }
            let Some(p) = reg.find(&j.dest) else { continue };
            if !p.accepting {
                continue;
            }
            // Printer busy if it already has a processing job.
            if jobs_r
                .for_printer(&p.name)
                .any(|x| x.state == job::JobState::Processing)
            {
                continue;
            }
            let Some(file) = j.files.first() else {
                continue;
            };
            let data = job::Job::data_path(&request_root, j.id, file.num);
            // Target format: the queue's PPD `*cupsFilter`/`*cupsFilter2`
            // declarations pick the device-consumable MIME (P7); bare queues
            // take the raw passthrough.
            let dst = ppd_final_type(p, &server_bin)
                .unwrap_or_else(|| "application/vnd.cups-raw".to_string());
            let spec = pipeline::JobSpec {
                printer: p.name.clone(),
                job_id: j.id,
                username: j.username.clone(),
                title: j.title.clone(),
                copies: j.copies,
                options: String::new(),
                data_file: data,
                src_type: file.filetype.clone(),
                dst_type: dst.clone(),
                device_uri: p.device_uri.clone(),
                filter_dir: server_bin.join("filter"),
                backend_dir: server_bin.join("backend"),
                backend: pipeline::backend_for_uri(&p.device_uri),
                env: std::collections::HashMap::new(),
            };
            out = Some((j.id, spec, file.filetype.clone(), dst));
            break;
        }
        out
    };
    let Some((job_id, spec, src, dst)) = found else {
        return;
    };

    let chain = mime.filter_chain(&src, &dst, 0).unwrap_or_default();
    let mut chain: Vec<mime_db::Conv> = chain.into_iter().cloned().collect();
    // Append the queue's PPD final driver filter (`*cupsFilter` `program`) —
    // e.g. `rastertofoo` converts `cups-raster` to the device stream.
    if let Some(p) = registry
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .find(&spec.printer)
    {
        if let Some(ppf) = ppd_final_filter(p, &server_bin, &dst) {
            chain.push(ppf);
        }
    }

    match spec.spawn(&chain) {
        Ok(mut pipe) => {
            if let Some(j) = jobs
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get_mut(job_id)
            {
                j.state = job::JobState::Processing;
                j.processing_at = Some(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX)),
                );
                j.backend_pid = Some(i32::try_from(pipe.backend.id()).unwrap_or(-1));
                let _ = j.save(&request_root);
            }
            log.err(
                cups_log::Level::Info,
                format!("[Job {job_id}] Started backend (PID {})", pipe.backend.id()),
            );
            let jobs = jobs.clone();
            let subs = subs.clone();
            let log = log.clone();
            std::thread::spawn(move || {
                let status = pipe.backend.wait();
                for mut f in pipe.filters {
                    let _ = f.wait();
                }
                let ok = status.is_ok_and(|s| s.success());
                if let Some(j) = jobs
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .get_mut(job_id)
                {
                    j.state = if ok {
                        job::JobState::Completed
                    } else {
                        job::JobState::Aborted
                    };
                    j.reasons = vec![if ok {
                        "job-completed-successfully".into()
                    } else {
                        "job-aborted-by-system".into()
                    }];
                    j.backend_pid = None;
                    j.completed_at = Some(job::now());
                    let _ = j.save(&request_root);
                    let ev = if ok {
                        events::Event::JobCompleted
                    } else {
                        events::Event::JobStopped
                    };
                    let job_dest = j.dest.clone();
                    subs.write()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .push(
                            ev,
                            Some(&job_dest),
                            Some(job_id),
                            Some(match j.state {
                                job::JobState::Completed => 9,
                                job::JobState::Aborted => 7,
                                _ => 8,
                            }),
                            &format!("Job {job_id} {}.", if ok { "completed" } else { "aborted" }),
                        );
                }
                log.err(
                    if ok {
                        cups_log::Level::Info
                    } else {
                        cups_log::Level::Error
                    },
                    format!(
                        "[Job {job_id}] {}",
                        if ok {
                            "Job completed."
                        } else {
                            "Backend failed; job aborted."
                        }
                    ),
                );
            });
        }
        Err(e) => {
            if let Some(j) = jobs
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get_mut(job_id)
            {
                j.state = job::JobState::Aborted;
                j.reasons = vec!["job-aborted-by-system".into()];
                let _ = j.save(&request_root);
            }
            log.err(
                cups_log::Level::Error,
                format!("[Job {job_id}] Unable to start job: {e}"),
            );
        }
    }
}

/// Local host FQDN for cert CN / generated URIs when no Host header.
fn hostname() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "localhost".into())
}
