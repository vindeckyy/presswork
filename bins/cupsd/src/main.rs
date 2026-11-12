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

async fn run(cfg: Config, _args: Args, paths: Paths) -> std::process::ExitCode {
    let cfg = Arc::new(cfg);
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

    // Registry: load printers.conf (+ classes.conf uses same parser).
    let mut registry = Registry::default();
    registry.next_printer_id = 1;
    registry.next_job_id = 1;
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
    let jobs = Arc::new(std::sync::RwLock::new(job::Jobs::load_all(
        std::path::Path::new(&request_root),
    )));
    let mime_dir = cfg
        .files
        .data_dir
        .clone()
        .unwrap_or_else(|| "/usr/share/cups".into());
    let mime = Arc::new(mime_db::MimeDb::load(std::path::Path::new(&mime_dir)).unwrap_or_default());

    // Log sinks — error_log always (foreground → stderr), access_log
    // when configured.
    let log = Arc::new(Logs {
        error: cfg
            .files
            .error_log
            .as_deref()
            .map_or_else(|| cups_log::Sink::stderr(), cups_log::Sink::file),
        access: cfg
            .files
            .access_log
            .as_deref()
            .map_or_else(|| cups_log::Sink::stderr(), cups_log::Sink::file),
        time_fmt: match cfg.cupsd.log_time_format {
            cups_config::LogTimeFormat::Usecs => cups_log::TimeFormat::Usecs,
            _ => cups_log::TimeFormat::Standard,
        },
    });

    // Bind all listeners.
    let mut join = tokio::task::JoinSet::new();
    let mut bound = 0usize;
    for ln in &cfg.cupsd.listeners {
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
                        opts.clone(),
                        doc_root.clone(),
                        registry.clone(),
                        cfg.clone(),
                        log.clone(),
                        jobs.clone(),
                        mime.clone(),
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
                        opts.clone(),
                        doc_root.clone(),
                        registry.clone(),
                        cfg.clone(),
                        log.clone(),
                        jobs.clone(),
                        mime.clone(),
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
    registry: Arc<std::sync::RwLock<Registry>>,
    cfg: Arc<Config>,
    log: Arc<Logs>,
    jobs: Arc<std::sync::RwLock<job::Jobs>>,
    mime: Arc<mime_db::MimeDb>,
) {
    let _ = ssl; // TLS acceptor lands with cups-tls (P5)
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let opts = opts.clone();
                let doc_root = doc_root.clone();
                let registry = registry.clone();
                let cfg = cfg.clone();
                let local = peer.ip().is_loopback();
                let port = stream.local_addr().map(|a| a.port()).unwrap_or(631);
                let host = peer.ip().to_string();
                let log = log.clone();
                let jobs = jobs.clone();
                let mime = mime.clone();
                tokio::spawn(async move {
                    serve_one(
                        stream, opts, doc_root, registry, cfg, port, local, log, host, jobs, mime,
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

async fn accept_unix(
    listener: UnixListener,
    opts: Arc<httpd::ServerOptions>,
    doc_root: PathBuf,
    registry: Arc<std::sync::RwLock<Registry>>,
    cfg: Arc<Config>,
    log: Arc<Logs>,
    jobs: Arc<std::sync::RwLock<job::Jobs>>,
    mime: Arc<mime_db::MimeDb>,
) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let opts = opts.clone();
                let doc_root = doc_root.clone();
                let registry = registry.clone();
                let cfg = cfg.clone();
                let log = log.clone();
                let jobs = jobs.clone();
                let mime = mime.clone();
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
) where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let (mut rd, mut wr) = split(stream);
    let _ = httpd::serve_connection(&mut rd, &mut wr, &opts, move |req| {
        dispatch_req(
            &req, &doc_root, &registry, &cfg, port, local, &log, &host, &jobs, &mime,
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
    /// `cupsdWriteErrorLog()` — error_log line (mirrors `E [time] msg`),
    /// echoed to stderr like upstream's foreground mode.
    fn err(&self, level: cups_log::Level, msg: impl AsRef<str>) {
        let line = cups_log::error_line(level, self.time_fmt, msg.as_ref());
        self.error.write(&line);
        eprintln!("cupsd: {}", msg.as_ref());
    }
}

/// Request dispatch: static files, IPP ops, misc.
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
) -> Response {
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
            ipp_dispatch(req, registry, cfg, port, local, log, host, jobs, mime)
        }
        Method::Options if req.wants_tls_upgrade => Response::status(StatusCode::UPGRADE_REQUIRED),
        Method::Options => {
            log_access(&**log, host, req, 200, 0, "-", "-");
            Response::status(StatusCode::OK)
        }
        _ => {
            log_access(&**log, host, req, 501, 0, "-", "-");
            Response::status(StatusCode::NOT_IMPLEMENTED)
        }
    }
}

/// `cupsdLogRequest()` — access_log line after serving.
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
) -> Response {
    let Ok((msg, consumed)) = ipp_codec::decode(req.body.as_bytes()) else {
        log_access(&**log, host, req, 400, 0, "-", "-");
        return Response::status(StatusCode::BAD_REQUEST);
    };
    let document = &req.body.as_bytes()[consumed..];
    let reg = registry.read().unwrap_or_else(|e| e.into_inner());
    let mut ctx = ops::Ctx::new(&reg, cfg, port, jobs.as_ref(), mime.as_ref());
    ctx.is_local = local;
    ctx.document = document;
    let resp = ops::dispatch(&msg, &ctx);
    drop(reg);
    // Scheduler tick: pick next pending job on an idle printer and spawn
    // its filter->backend pipeline (mirrors start_job being driven by the
    // scheduler's event loop).
    schedule_tick(jobs, registry, mime, cfg, log);
    let op_name = ipp_codec::ops::op::name(msg.code);
    let status_name = ipp_codec::ops::status::name(resp.code);
    match ipp_codec::encode(&resp) {
        Ok(b) => {
            let n = b.len() as u64;
            log_access(&**log, host, req, 200, n, op_name, status_name);
            Response::ipp(StatusCode::OK, b)
        }
        Err(_) => Response::status(StatusCode::INTERNAL),
    }
}

/// `start_job` scheduler tick — pick the first pending job whose printer is
/// idle + accepting, resolve its filter chain, and spawn the pipeline in a
/// watcher thread that marks the job completed/aborted on exit.
fn schedule_tick(
    jobs: &Arc<std::sync::RwLock<job::Jobs>>,
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
        let jobs_r = jobs.read().unwrap_or_else(|e| e.into_inner());
        let reg = registry.read().unwrap_or_else(|e| e.into_inner());
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
            // Target format: raw passthrough for P2 (driverless PPD formats
            // land in P7). ipp/socket/file printers accept raw streams.
            let dst = "application/vnd.cups-raw".to_string();
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
    let chain: Vec<mime_db::Conv> = chain.into_iter().cloned().collect();

    match spec.spawn(&chain) {
        Ok(mut pipe) => {
            if let Some(j) = jobs
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .get_mut(job_id)
            {
                j.state = job::JobState::Processing;
                j.backend_pid = Some(pipe.backend.id() as i32);
                let _ = j.save(&request_root);
            }
            log.err(
                cups_log::Level::Info,
                format!("[Job {job_id}] Started backend (PID {})", pipe.backend.id()),
            );
            let jobs = jobs.clone();
            let log = log.clone();
            std::thread::spawn(move || {
                let status = pipe.backend.wait();
                for mut f in pipe.filters {
                    let _ = f.wait();
                }
                let ok = status.map(|s| s.success()).unwrap_or(false);
                if let Some(j) = jobs
                    .write()
                    .unwrap_or_else(|e| e.into_inner())
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
                .unwrap_or_else(|e| e.into_inner())
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
