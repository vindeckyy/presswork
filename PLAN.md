# Plan: A Rust rewrite of CUPS (cupsd + printing stack)

Build a drop-in, memory-safe replacement for `cupsd` and its companion daemons — the IPP scheduler, spooler, filter pipeline orchestrator, and device backends — as a Rust workspace, preserving wire, file-format, and process-contract compatibility with CUPS 2.x.

---

## 1. Executive summary

**What exists today (researched fact):**
- The Rust ecosystem has solid **client-side** and **device-side** IPP tooling:
  - `ipp` v8 (ancwrd1/ipp.rs) — full RFC 8010/8011 codec, all value types incl. collections, actively maintained (Oct 2026).
  - `ippper` — hyper 1.x IPP server library; already implements **RFC 2817 adaptive TLS upgrade**, the exact same-port HTTPS-upgrade trick cupsd uses. BSD-3.
  - `ipp-printer-app` v0.10 — pure-Rust IPP Everywhere *printer application* framework (the device side).
  - `ipp-server` 0.3, `ipp-proto` 0.3, `product-os-print-server` — stale or narrow server attempts.
  - `printers`, `ipp-util`, `ipp-client`/`ipp-async` — client crates.
  - `cups-sys` — stale FFI bindings to libcups2.
- **Nobody has built the scheduler**: the queue/job/state machine, filter-graph solver, backend process orchestration, policy/auth model, config compatibility, DNS-SD sharing, notifications, and admin ops that make cupsd the thing applications talk to. That is the gap this project fills.

**Reference implementation analyzed:** OpenPrinting/cups @ `d57fe3f` (CUPS 2.5 dev, cloned to `/tmp/cups-ref`). Scheduler ≈ 59k LOC C across 40 files; backends ≈ 8k; cups-lpd 1.7k; helpers (cups-deviced, cups-exec, cupsfilter) ≈ 4k. Relevant libcups surface (IPP codec, HTTP layer, options, PPD) ≈ 30–40k more. Estimated Rust port: **45–65k LOC**.

**Strategic context (important):** OpenPrinting's own CUPS 3.x splits the world into `cups-local` (per-user, temp queues) + `cups-sharing` (root, permanent queues), drops PPDs/drivers/raw queues/Kerberos. We are **not** copying that — we target **CUPS 2.x drop-in semantics** because that's what every distro, print dialog, and admin tool speaks today, while designing so the 3.x trajectory (driverless-first) is the fast path. PPD support is scoped as a later, separable layer.

**Key architectural choices:**
- **Keep the out-of-process filter/backend contract.** Filters (`pdftopdf`, `pdftoraster`, `foomatic-rip`…) and third-party backends (`beh`, `smbspool`, `hp`, `bjnp`) are external binaries with a stable argv/env/pipe/exit-code contract. We reimplement the *orchestrator*, not Ghostscript. We ship Rust rewrites of the *stock backends* (socket/ipp/ipps/lpd/snmp/usb/dnssd) as separate binaries speaking that contract.
- **tokio** for the event loop (replaces cupsd's single-threaded `select()` + `process_children` + timer-scanning), with jobs/queues as owned state behind locks — not async-infected data structures.
- **Own IPP codec crate** rather than forcing `ipp` v8, because cupsd needs exact libcups wire quirks (attribute-group ordering, out-of-band tags, dedup, charset/name-with-language rules, `memberAttrName`, the 11-byte date format, CUPS-private op IDs). Codec is ~3–4k LOC; full control is worth it. (`ipp` remains a fallback/reference; `ippper`'s RFC-2817 pattern is reused.)
- **hyper + tokio-rustls** for HTTP/1.1 incl. chunked, `Expect: 100-continue`, keep-alive, and RFC 2817 `Upgrade: TLS/1.x` — the same-port adaptive-encryption behavior `Encryption IfRequested/Required` depends on.
- **Pure-Rust deps where possible:** `mdns-sd` (not Avahi), `rustls`+`rcgen` (not OpenSSL), `zbus` (not libdbus), `rasn-snmp` (+thin client), `rusb`, `nonstick`/`pam-client2`, `libgssapi` (optional Negotiate), `nix`.

---

## 2. What cupsd actually does — component inventory

From source (`/tmp/cups-ref/scheduler/`):

| C file | LOC | Responsibility | Rust module |
|---|---|---|---|
| `main.c` | 2.1k | Daemon lifecycle, select loop, timers, signal handlers, `-c/-f/-F/-l/-s/-t` flags, idle-exit/on-demand | `cupsd` binary |
| `client.c` | 3.9k | Per-connection HTTP/1.1 state machine, IPP request intake, CGI dispatch, TLS upgrade, file serving | `http::conn` |
| `ipp.c` | 11.7k | The 50-op IPP dispatcher — the single biggest file | `ops::*` |
| `job.c` | 5.7k | Job lifecycle, filter-chain assembly, spool files `d%05d-%03d`, control files `c%05d`, job history, `start_job`/`stop_job` | `job::*` |
| `printers.c` | 5.5k | `cupsd_printer_t`, printers.conf r/w, per-printer attrs (`printer/image/pwg-raster` synth), implicit classes, temp queues | `printer::*` |
| `conf.c` | 4.7k | cupsd.conf + cups-files.conf parse; `<Location>/<Limit>/<Policy>` blocks; ~100 directives | `config::*` |
| `auth.c` | 2.6k | Basic/PAM/Negotiate/Bearer(OAuth)/local cert auth; Allow/Deny host rules; best-match Location | `auth::*` |
| `policy.c` | 0.5k | `<Policy>` op→ACL table, private attrs, `@OWNER`/`@SYSTEM` | `auth::policy` |
| `subscriptions.c` | 1.6k | Event subs, subscriptions.conf, notifier process mgmt, `notify-*` attrs | `events::*` |
| `colorman.c` | 1.5k | colord D-Bus device/profile registration | `colord` (opt) |
| `log.c` | 1.5k | error_log/access_log/page_log writers, syslog fallback, rotation | `log` |
| `type.c`/`mime.c`/`filter.c` | 2.5k | MIME types DB, magic rules, `mimeFilter2` least-cost graph search, convs | `mime::*` |
| `process.c`/`cups-exec.c` | 1.3k | posix_spawn w/ env, setuid/setgid/umask/rlimits, macOS sandbox profile | `pipeline::spawn` |
| `dirsvc.c` | 0.7k | DNS-SD registration (TXT build), Browsing/Browse* | `dnssd` |
| `cert.c` | 0.4k | TLS cert files, self-signed generation | `tls` |
| `statbuf.c`/`banners.c`/`quotas.c`/`classes.c`/`network.c`/`listen.c`/`sysman.c`/`env.c`/`util.c`/`select.c`/`file.c`/`network.c` | ~4k | Status-line parser, job-sheets, page quotas, classes, iface watch, listeners, systemd on-demand | misc |
| `cups-lpd.c` | 1.7k | RFC 1179 LPD→IPP shim daemon | `cups-lpd` bin |
| `cups-deviced.c` | 0.8k | Runs backends in "list" discovery mode, aggregates `scheme uri make-model info` | `cups-deviced` |
| `cups-driverd.cxx` | — | PPD driver enumeration (deprecated) | optional |
| `cupsfilter.c` | 1.6k | Standalone "run the filter chain" test tool | `cupsfilter` bin |

Backends (`/tmp/cups-ref/backend/`): `ipp.c` 3.7k (IPP client incl. auth, compression, status sync — the workhorse for remote/temp queues), `socket.c` 486, `lpd.c` 1.3k, `snmp.c` 1.4k (supplies/status), `usb.c`+variants (~1k, IEEE-1284 devid via libusb/kernel), `dnssd.c` 733 (resolve `dnssd://` → `ipp://`).

### The runtime shape
- Single-threaded `select()` over: listen fds → `cupsdReadClient` (HTTP/IPP state machine), CGI pipes, job status pipes (`statbuf`), backend back/side-channel pipes, notifier pipes; timer wheel via `select_timeout()` scanning jobs/clients for next deadline (job history purge, hold-until, kill delay, client timeouts, dirty-conf flush, IdleExitTimeout).
- `start_job()` builds **argv**: `printer job-id user title copies options [file]` and **env**: `CHARSET, LANG, PPD, CONTENT_TYPE, DEVICE_URI, PRINTER_INFO, PRINTER_LOCATION, PRINTER, PRINTER_STATE_REASONS, CUPS_FILETYPE, FINAL_CONTENT_TYPE, CLASSIFICATION, CLASS, AUTH_INFO_REQUIRED, AUTH_*` + base env (`cupsdLoadEnv`: ServerBin paths, datadir, TZ, etc.).
- Filter chain: `mimeFilter2` = least-cost path search over `mime.convs` edges from detected `filetype` → `printer/<name>` (or `image/urf`,`image/pwg-raster` for driverless). Chained via pipes: filter₁ → … → filterₙ → backend. Decompress (`gziptoany`), prefilters, port monitors inserted.
- Per-process plumbing: fd0=input, fd1=next-filter, fd2→status pipe (parsed `INFO:`/`STATE:`/`PAGE:`/`ATTR:`/`DEBUG:`/`NOTICE:` lines), fd3=backend backchannel, fd4=sidechannel (SNMP/1284 queries). Children run as `FilterUser/FilterGroup` (lp), `umask 077`, rlimits; `FilterLimit` cost accounting; `JobKillDelay` grace.
- Backend discovery: run `<ServerBin>/backend/*` with no args → stdout `scheme uri "make-model" "info" [device-id]`; `cups-deviced` multiplexes, incl. SNMP broadcast scan per snmp.conf.
- Persistence: `printers.conf`/`classes.conf` (XML-ish `<Printer>`/`<DefaultPrinter>`, attrs, quotas, state), `subscriptions.conf`, job `c%05d` files, `job.cache`, `NextJobId`; dirty-write with `DirtyCleanInterval` delay + atomic `.N` rename.
- Listeners: TCP/UDP on `Listen`/`Port`/`SSLListen`/domain socket `Listen /path` (mode/perms), plus inherited fds (systemd socket activation / `sd_listen_fds`), `IdleExitTimeout` on-demand exit.
- Sharing: `Browsing` + `BrowseLocalProtocols dnssd` registers `_ipp._tcp`, `_ipps._tcp`, `_printer._tcp` (+`_universal`/`_cups` subtypes); TXT: `txtvers,qtotal,rp,ty,adminurl,note,pdl,air,UUID,TLS,URF,mopria-certified,Color,Duplex,Staple,Copies,Collate,Punch,Bind,Sort,Scan,Fax,rfo,kind`.
- Notifications: `Create-*-Subscription` → event objects → push via `notify-*` (mailto/rss execs) + **D-Bus** `org.cups.cupsd.Notifier` signals (printer/job/server events) via external `notifier/dbus` program fed IPP event messages on stdin.
- Auth model: per-request `cupsdAuthorize` → best-match `<Location path>` → `<Limit ops>` → `AuthType {None,Basic,Negotiate,Bearer,Default}` + `Require {user,group,@OWNER,@SYSTEM,valid-user}` + `Order allow,deny|deny,allow` + `Allow/Deny host|IP|IFname|@LOCAL` + `Encryption` + `Satisfy`. Peer-cred on domain socket → uid/gid. Basic→PAM (`/etc/pam.d/cups`), also local-cert (macOS). 2.5 adds OAuth Bearer (`OAuthServer/OAuthScopes` + `OAuthGroup` files).
- Web UI: `WebInterface` GETs → static files from DocumentRoot or CGI exec (`cgi-bin/*.cgi` w/ templates); POST admin forms go through same auth pipeline.

### The 50 IPP operations (ipp.c dispatch table)
Standard: Print-Job, Print-URI, Validate-Job, Create-Job, Send-Document, Send-URI, Get-Job-Attributes, Get-Jobs, Get-Printer-Attributes, Get-Printer-Supported-Values, Pause/Resume-Printer, Purge-Jobs, Set-Printer-Attributes, Set-Job-Attributes, Enable/Disable-Printer, Hold/Release-Job, Restart-Job, Cancel-Job(s)/-My-Jobs/-Current-Job, Close-Job, Identify-Printer, Hold/Release-New-Jobs, Deactivate/Activate-Printer, Promote-Job, Schedule-Job-After, Reprocess-Job, Suspend/Resume-Current-Job, Create-{Job,Printer}-Subscriptions, Get/Renew/Cancel-Subscription, Get-Notifications.
CUPS-private: CUPS-Accept/Reject-Jobs, CUPS-Get-Default/-Set-Default, CUPS-Get-Printers/-Classes/-PPDs/-PPD/-Devices/-Document, CUPS-Add-Modify-Printer/-Class, CUPS-Delete-Printer/-Class, CUPS-Move-Job, CUPS-Authenticate-Job, CUPS-Create-Local-Printer.

---

## 3. The contract surface (what "drop-in" means)

| Surface | Must match | Notes |
|---|---|---|
| IPP wire | Byte-level RFC 8010/8011 + CUPS op IDs/status/attr sets | `ipptool` suite must pass |
| HTTP/1.1 | Keep-alive, chunked, `Expect: 100-continue`, `Upgrade: TLS/1.x` (RFC 2817), `Host` checks, `Server: CUPS/x.y IPP/2.1` | Same-port adaptive TLS is non-optional |
| Filter contract | argv0–6 + env list + fd0–4 + stderr status lines + exit codes | Frozen forever; third-party filters depend on it |
| Backend contract | Same argv/env + `device-uri` dispatch by scheme + discovery mode + `CUPS_BACKEND_*`/`CUPS_FILETYPE` semantics + `ATTR:`/`INFO:`/`STATE:`/`PAGE:` lines | Exit: 0 ok, 1 fail-retry, 2 abort, 3 auth, 4 stop-printer, 5 stop+hold, 100? |
| Sidechannel | `CUPS_SC_CMD_*` bidirectional fd4 protocol (SNMP/1284 passthrough to backend) | Needed by snmp-supplies etc. |
| Config files | `cupsd.conf`, `cups-files.conf`, `printers.conf`, `classes.conf`, `subscriptions.conf`, `mime.types`, `mime.convs`, `snmp.conf`, `passwd.md`, `oauth.conf`? | Read+write same formats in-place |
| Layout | `/etc/cups`, `/var/spool/cups` (d*/c*), `/var/cache/cups` (job.cache, .data certs), `/var/log/cups`, `/run/cups` (cups.sock, certs, printcap) | Root daemon, lp filter user |
| Logs | access_log CLF+IPP, error_log `X [date] [Client N] msg`, page_log `printer user job [date] total n - host` (+PageLogFormat vars) | Monitoring tools scrape these |
| DNS-SD | Service types + full TXT record above | AirPrint/Mopria clients match on URF/pdl/TLS |
| D-Bus | `org.cups.cupsd.Notifier` signal names+arg lists | GNOME/KDE print daemons consume |
| LPD | RFC 1179 sub-daemon (control/data files, `lpq`-style short/long reports) | Legacy clients |
| CLI | `cupsd -c file -f -F -h -l -s file -t` | `-t` config test used by init scripts |
| Signals | SIGHUP reload-conf, SIGTERM graceful, SIGCHLD reap, SIGUSR1? | |
| systemd | `Type=notify` READY, socket activation `LISTEN_FDS`, `IdleExitTimeout`, watchdog? | cups.service/.socket/.path |
| Env overrides | `CUPS_SERVERROOT`, `CUPS_STATEDIR`, `CUPS_CACHEDIR`, `CUPS_DATADIR`, `CUPS_SERVERBIN`, `TMPDIR`, `SOFTWARE` | |

**Explicit non-goals (v1):** PPD *driver* enumeration (`cups-driverd`), macOS sandbox profiles/xpc, Kerberos (CUPS 3 drops it; feature-flag Negotiate anyway), OpenDirectory, launchd. (Kerberos/Bearer kept behind cargo features.)

---

## 4. Rust architecture

```
CUPS/                             # workspace root (this repo)
├── Cargo.toml                    # workspace + release profile (lto, panic=unwind for pid safety)
├── crates/
│   ├── ipp-codec/                # IPP wire codec + model (own; modeled on libcups ipp.c semantics)
│   │                             #   IppMessage{version,op/status,request_id,groups}, Value enum incl.
│   │                             #   collections, RangeOfInt, Resolution, DateTime(11B), LangText,
│   │                             #   unknown/out-of-band tags; streaming reader; group-order preserve
│   ├── httpd/                    # HTTP/1.1 on hyper/hyper-util; conn state machine mirroring client.c
│   │                             #   chunked+Expect:100+keepalive+RFC2817 TLS upgrade+virtual-host check
│   │                             #   static-file GET + CGI exec plumbing
│   ├── cups-config/              # parsers: cupsd.conf, cups-files.conf, printers.conf, classes.conf,
│   │                             #   subscriptions.conf, snmp.conf, mime.types, mime.convs, passwd.md
│   │                             #   <Location>/<Limit>/<Policy>/<Printer> block model
│   ├── mime-db/                  # types+rules eval (contains/string/regex/short/int/char/ascii/printable/
│   │                             #   locale/priority), convs edges, mimeFilter2 least-cost solver
│   ├── authz/                    # AuthType/Require/Order/Allow-Deny evaluator, peer-cred, policy table
│   ├── authn/                    # Basic→PAM(nonstick|pam-client2), Negotiate→libgssapi(feat), 
│   │                             #   Bearer/JWT(oauth2+jsonwebtoken, feat), local-cert(feat,macOS)
│   ├── job/                      # Job state machine (pending→held→processing→stopped/completed/
│   │                             #   aborted/canceled), spool c/d files, history, quotas, banners
│   ├── printer/                  # Queue registry, per-printer synth attrs, classes/implicit-class,
│   │                             #   printer-state-reasons, temp/everywhere queues, printers.conf io
│   ├── pipeline/                 # Process supervisor: spawn filters/backends/port-monitors/notifiers,
│   │                             #   pipe chain, statbuf line parser, back/side-channel, privdrop,
│   │                             #   rlimits, FilterLimit accounting, kill/reap, exit-code semantics
│   ├── ops/                      # the 50-op dispatcher; per-op handlers, attr validators, policy hooks
│   ├── events/                   # subscriptions, event ring, notifier-proc feeder, Get-Notifications
│   ├── dnssd/                    # mdns-sd registration/TXT build/browse; BrowseLocal/RemoteProtocols
│   ├── tls/                      # rustls configs, rcgen self-signed mgmt, ServerKeychain files
│   ├── dbus/                     # zbus: org.cups.cupsd.Notifier emit + colord register (feature)
│   ├── log/                      # error/access/page writers, rotation, syslog/journald fallback
│   ├── backends/                 # binary crates: socket, ipp, ipps, lpd, snmp, usb, dnssd, parallel?,
│   │                             #   serial; shared `backend-common` (argv parse, backchannel, report)
│   ├── cups-lpd/                 # RFC1179 mini-daemon (xinetd/systemd-socket style entry per conn)
│   ├── cups-deviced/             # discovery multiplexer (runs backend list + snmp scan)
│   ├── cupsfilter/               # debug tool: run a doc through the chain, dump stages
│   └── cups-exec/                # setuid helper equivalent for sandboxed spawn (linux: clone+ns?)
└── cupsd/                        # the daemon: main loop, listeners, timers, signals, systemd glue
```

**Concurrency model:** tokio multi-thread; one accept loop per listener; per-connection task running the HTTP/IPP state machine; shared `Scheduler { printers, jobs, clients, subs, mime_db, config }` behind `RwLock`/`DashMap` where reads dominate. Filter/backend children via `tokio::process` + fd passing; status-line parsers as stream tasks. Timer wheel: a single `tokio::time` driver scanning the same deadline set `select_timeout()` computes (job-history, hold-until, kill-delay, client timeouts, dirty flush, IdleExit). SIGHUP→reload task; SIGCHLD implied by `Child::wait`.

**Why not single-threaded like cupsd:** we keep *deterministic single-writer* semantics for queue/job mutations (serialize all op handlers through one task or fine-grained per-printer locks) but get free parallelism for file I/O, CGI, DNS-SD, and TLS.

**FFI boundary:** only PAM (`nonstick`/`pam-client2`), optional GSSAPI (`libgssapi`), libusb (`rusb`), and `libc`/`nix` for privdrop/fd/socket ioctls. Everything else pure Rust. `#![forbid(unsafe_code)]` everywhere except a small `sys` crate housing the spawn/fd/privdrop/syslog glue.

**License:** Apache-2.0 OR MIT (matches ecosystem norms; CUPS is Apache-2.0+exceptions so derivative file-format parsers are fine).

---

## 5. Implementation phases (milestones)

> Each phase ends *runnable*, verified against `ipptool` + real clients.

### P0 — Skeleton & codec (foundation)
- Workspace, CI (clippy/fmt/audit/miri-lite, linux+macOS builds), license, tracing/log.
- `ipp-codec`: full wire read/write + model; round-trip fuzz vs libcups `ipp` decode of corpus (use CUPS `test/*.test` files + captured traffic); `#[no_std]`-ish core for reuse in backends.
- `httpd`: hyper-util HTTP/1.1 server w/ virtual-host check, chunked req bodies, Expect:100, keep-alive, CGI/static GET scaffold, TLS acceptor + **RFC 2817 upgrade** (reuse ippper pattern: peek first bytes → TLS or HTTP; on `OPTIONS *`+`Upgrade`→switch).
- `cups-config`: cupsd.conf/cups-files.conf parsers → typed `Config` incl. Location/Limit/Policy, all ~100 directives w/ defaults matching `conf.c`; `-t` config-test.
- **Deliverable:** `cupsd` boots, `Listen` binds, serves `GET /` static + parses config + no-op IPP 404s.

### P1 — Read-only IPP server
- `ops` dispatch skeleton + attr validation (`ippValidateAttributes`-equivalent; charset/naturalLanguage defaults, `printer-uri`/`job-uri` resolution incl. `ipp://localhost/...` normalization).
- Handlers: Get-Printer-Attributes, CUPS-Get-Printers/-Classes/-Default, Get-Jobs, Get-Job-Attributes, Get-Printer-Supported-Values, Validate-Job (attr-level), CUPS-Get-Document (spool read), Get-Notifications (empty).
- `printer` registry + `printers.conf`/`classes.conf` **load/save** (incl. `<DefaultPrinter>`, quotas, `State`, `Type`, `Attribute` blobs); synthesize `printer/<name>` mime types + `document-format-supported` etc.
- `log` writers (error/access formats byte-compat).
- **Gate:** `ipptool ipp://localhost/printers/q test/4.1-requests.test` passes for covered ops; `lpstat -p -l`, GNOME/KDE dialogs enumerate.

### P2 — Jobs & the pipeline (the spooler)
- `job`: c/d spool files, Create-Job+Send-Document, Print-Job (+Print-URI fetch), multi-doc, job-id alloc/`NextJobId`, `job.cache`, `PreserveJobHistory/Files`, state transitions + `time-at-*`, `job-*-attrs` sets, Cancel/Close/Restart/Hold/Release, `job-sheets` banners, quotas hooks.
- `mime-db`: mime.types magic eval (incl. `contains/locale/priority`), `filetype` sniff (gzip-aware), convs, `mimeFilter2` least-cost path.
- `pipeline`: filter-chain assembly (gziptoany/prefilter/port-monitor rules, `FINAL_CONTENT_TYPE`, `MAX_FILTERS`), spawn w/ `lp` privdrop+umask+rlimits (nix), pipes 0-4, statbuf parser→`printer-state-reasons`/`job-printer-state-message`/page_log, back/side-channel, `FilterLimit`, `JobKillDelay`, exit-code policy, `ErrorPolicy` (abort-job/retry/stop-printer), remote-vs-local job branching.
- Raw/`vnd.cups-raw` passthrough + `application/vnd.cups-command` handling.
- **Gate:** `lp -d realqueue file.pdf` prints on a real driverless printer via socket/ipp backend; `cupsfilter` tool reproduces chain; `test/4.3-job-ops.test` passes.

### P3 — Backends + device discovery
- `backend-common` crate: argv/env parse, `DEVICE_URI`, backchannel (`CUPS_BC_*`) + sidechannel (`CUPS_SC_*`) impls, supply-level/`ATTR:` reporting, exit codes, `-h` list mode.
- Binaries: `socket` (JetDirect 9100 + waiteof/bc), `ipp`/`ipps` (the 3.7k-line client: retries, auth URIs, `negotiate`, compression=identity/gzip, attr sync, `print-as-raster` URF/PWG-Raster selection, `create-job`/`send-document` forwarding, job monitor), `lpd`, `snmp` (+supplies scan per snmp.conf), `usb` (libusb/rusb + `/dev/usb/lp*`, IEEE-1284 devid, quirks table `org.cups.usb-quirks`), `dnssd` (mdns-sd resolve→ipp), `parallel`/`serial` (termios).
- `cups-deviced`: spawn all backends, aggregate discovery, SNMP community scan, `timeout`, `limit`, parallel spawn.
- **Gate:** `lpinfo -v` lists devices; jobs land on USB, JetDirect, IPP, and DNS-SD printers; supply levels report.

### P4 — Admin ops, auth, policies
- Ops: Add-Modify-Printer/-Class (incl. `ppd-name`, `device-uri`, `printer-is-accepting-jobs`, `printer-is-shared`, `printer-error-policy`, `printer-op-policy`, `-temporary`?), Delete-Printer/-Class, CUPS-Set-Default, Accept/Reject-Jobs, Pause/Resume/Enable/Disable (+`printer-state-message`/reasons), Hold/Release-New-Jobs, CUPS-Get-PPD(s), CUPS-Move-Job, CUPS-Authenticate-Job, `auth-info-required` flow.
- `authn`/`authz`: Location best-match, `<Limit>` op sets, `Order`/`Allow`/`Deny` (`@LOCAL` incl. if-subnet match), `Require user/group/@OWNER/@SYSTEM/valid-user`, `AuthType`, `Encryption` enforcement, `Satisfy`, domain-socket peer-cred, Basic→PAM, `SystemGroup`, `DefaultAuthType`; `passwd.md` for Basic admin if used.
- `policy` table incl. `JobPrivateAccess/Values`, `SubscriptionPrivateAccess/Values` redaction.
- **Gate:** `lpadmin -p … -E -v ipp://…` works; unauthorized ops → 401/403 exactly as cupsd (status + `WWW-Authenticate`); `test/4.2-cups-printer-ops.test` passes; `<Policy kerberos>` variant honored when feature on.

### P5 — Sharing, TLS, events, web
- `tls`: ServerKeychain cert load, rcgen self-signed on demand (`CreateSelfSignedCerts`), per-listener `Encryption` modes, cert rehash/rotate timer, `cups -E` semantics; TLS client-auth for local-cert auth where used.
- `dnssd`: register `_ipp._tcp`(+subtypes)/`_ipps._tcp`/`_printer._tcp` w/ full TXT; `Browsing`/`BrowseLocalProtocols`/`BrowseDNSSDSubTypes`/`BrowseWebIF`/host-name overrides; deregister on stop; `Browsing off` default honoring; interface-change reannounce.
- `events`: subscriptions.conf persistence, leases/renew/interval, `notify-sequence-number`, `Get-Notifications` pull, notifier-proc feeder (mailto/rss passthrough), `dbus` zbus emitter for all `CUPSD_EVENT_*` signals.
- Web: `WebInterface` static DocumentRoot serving + CGI exec (`REQUEST_METHOD`, env, auth passthrough) so the **stock** cups web UI works unmodified; keep `cgi.types`.
- `colord` device/profile registration (feature `colord`).
- **Gate:** printer appears in macOS/iOS/GNOME discovery (AirPrint TXT check), `cupsctl --share-printers` toggles, `dbus-monitor` sees `PrinterAdded`, admin.cgi fully browsable, `test/4.4-subscription-ops.test` passes.

### P6 — LPD, on-demand, polish
- `cups-lpd` binary (RFC 1179: commands 0x01/0x02/0x03/0x04/0x05, control-file directives `P/J/C/L/t/f/l/r`…, queue-name→printer map, `localhost`-only default, report formats).
- systemd: `sd_notify` READY/STATUS, `sd_listen_fds` socket activation, `IdleExitTimeout`/`OnDemand` exit, watchdog, `system-cups.slice`; ship `cups.service/.socket/.path` + sysusers/tmpfiles equivalents.
- `log` rotation/MaxLogSize/PageLogFormat vars/AccessLogLevel/`FatalErrors`; `cupsctl`-covered knobs.
- Kerberos `Negotiate` (feature `gssapi`), OAuth `Bearer`+`OAuthServer/OAuthScopes/OAuthGroup` (feature `oauth`; JWKS cache via reqwest/rustls + jsonwebtoken).
- **Gate:** `lpr -P q` from a legacy LPR client prints; `systemctl start cups.socket`→auto-start+idle-exit; `cupsd -t` validates all stock configs.

### P7 — PPD & full 2.x parity
- `ppd` crate: full PPD parser/validator (`libcups ppd.c` ~9k→Rust; groups/options/constraints/UI/Custom*/JCL/cupsFilter/cupsICCProfile/APPrinterIconPath etc.), `ppd/` dir index, `CUPS-Get-PPDs` model-match, `cupsPPD`-equivalent attr synthesis (`printer-make-and-model`, `media-col` from PageSize…), `*cupsFilter:` → mime.convs injection, `*cupsManualCopies`, `*cupsIPPReasons`, `cupsMarker` attrs → TXT/reporting.
- `cups-driverd` equivalent if still needed for parity (mark deprecated).
- Implicit classes (`CUPS_PTYPE_IMPLICIT`/class failover), `RemoteRoot`, `BrowsePoll`/`BrowseRelay` legacy knobs (no-op-safe), `ServerTokens`/`ServerAlias` behavior, `HostNameLookups`.
- **Gate:** a PPD-based PostScript queue (foomatic/ghostscript filter) prints end-to-end; `test/5.*` CLI suite (which exercises lpadmin/lpoptions/lp/lpstat against the daemon) passes; `testps.ppd`-based queues enumerate drivers.

### P8 — Hardening & release
- Fuzz: `cargo-fuzz` on ipp-codec, mime-db rules, config parsers, LPD framer, PPD parser; corpus from CUPS `test/` + crash minimization.
- Differential test rig: same `ipptool`/CLI sequence vs C cupsd and cupsd-rs, diff normalized responses (status, attr sets incl. `-default`/`-supported` triplets, error strings).
- Interop matrix: macOS/iOS, Windows IPP client, GNOME/KDE, `cups-browsed`, `ippeveprinter`, `smb` print path.
- Security review: root daemon — minimize `unsafe`, isolate `sys` crate, default `Encryption Required` on non-localhost listeners? (compat: keep `IfRequested`), AppArmor/SELinux profiles, `systemd` sandbox knobs (ProtectSystem…), CVE-hardening notes vs C cupsd (e.g. the 2024 `cups-browsed`/foomatic chain — document how Rust model avoids injection classes: strict argv, no string-sprintf envs into shell).
- Packaging: `cargo install`, deb/rpm Arch examples, file perm map (0700 ssl, 0755 backends…), `ConfigFilePerm/LogFilePerm` enforcement, PAM file `/etc/pam.d/cups`, docs/man parity for directives.
- Release gates: full `test/*.test` green + `run-stp-tests.sh`, real-printer matrix, mem-leak/perf smoke vs cupsd, `cargo audit` clean, MSRV pin.

---

## 6. Verification & conformance assets (mostly free)

- `test/4.1-4.4*.test` — upstream `ipptool` conformance scripts: **reuse verbatim**, zero cost, authoritative.
- `test/5.*.sh` — upstream CLI integration suite (lpadmin/lpq/lp/lpstat/cancel/lpinfo).
- `ippeveprinter` (libcups3 tools) — spec-correct fake printer for backend tests; `ippfind` for DNS-SD checks; `istopwg/ippsample` server for IPP-System interop.
- `cups-browsed` — must pick up our DNS-SD queues unchanged.
- `cupsfilter` — compare chain decisions (`-p` dry runs) against C output on same doc set.
- Real hardware matrix: IPP Everywhere printer, AirPrint, raw JetDirect socket, USB, LPD host, snmp-capable.
- Static corpus: `conf/*.in`, `mime.types/convs`, `snmp.conf`, PPD samples (`testps.ppd`, `testpin.ppd`, `testhp.ppd`), templates for web CGI.

---

## 7. Risks & mitigations

| Risk | Mitigation |
|---|---|
| **Exact-parity attr/status semantics** — biggest failure mode; clients key off status codes, `*-default` triplets, dedup rules | Per-op test matrix + differential runner vs C cupsd; port `ipp.c`'s per-op validators attribute-set-by-attribute-set; keep `ipp-op.h` tables data-driven |
| HTTP edge behavior (chunked+Expect:100+2817-upgrade on one socket) | Proven by ippper; write focused interop tests incl. macOS `cups` client which *requires* upgrade path; keep `Encryption`/`Allow` enforcement pre-upgrade |
| Filter/backend contract drift | Single `pipeline` crate owns it; golden tests assert argv/env/fds; run stock `cups-filters` binaries in CI |
| Privilege/security surface (root daemon spawning children) | `unsafe` only in `sys` crate; privdrop+rlimits+fds via `nix`; default-deny parsing; no `system()` anywhere; `cargo-audit`+fuzz in CI; document sandbox profiles |
| PPD scope creep (full PPD is a beast) | Gate behind P7 milestone + feature; driverless path fully functional first (today's default anyway; CUPS 3 drops PPD entirely) |
| DNS-SD subtleties (subtypes, URF, TLS keys, dual-stack, iface flaps) | `mdns-sd` handles transport; TXT build ported line-for-line from `dnssdBuildTxtRecord`; AirPrint regression tests (iOS print dialog discovery is the bar) |
| Async vs cupsd's serial ordering (event order, job ordering, `select_timeout` deadline semantics) | Serialize queue/job mutations through one actor/lock domain; deterministic timer wheel; keep `compare_active_jobs` ordering (FIFO by `job-id` unless Promote/Schedule-Job-After) |
| Kerberos/OAuth | Feature-flagged; neither needed for a working desktop/server print path; parity via `<Policy kerberos>`+Bearer later |
| CGI web UI edge cases | We serve the *stock* CGIs via exec (same as cupsd) — behavior is inherited, not reimplemented |
| License/provenance | Fresh code, format parsers written from spec/docs; where porting algorithmic details (mimeFilter2, TXT build) keep Apache-2.0 attribution |

---

## 8. Resolved decisions

1. **Target surface → CUPS 2.x drop-in parity.** The deliverable is a replacement for the cupsd that exists on every Linux/macOS system today: permanent queues, `printers.conf`, the filter+backend pipeline, `<Policy>`/`<Location>` auth, DNS-SD sharing, D-Bus events. Driverless (IPP-queried attributes → synthesized `*/pwg-raster`+`*/urf` types) is the primary path; **PPD is phased to P7** behind a `ppd` feature. The CUPS 3.x local/sharing split is *not* the target — it's a different product shape.
2. **Codec → own `ipp-codec` crate.** Byte-exact libcups semantics matter: delimiter-group ordering, out-of-band tags (`not-settable`, `delete-attribute`, `admin-define`), unknown-tag passthrough, `memberAttrName` collection pairs, 11-byte dateTime, `rangeOfInteger`, `resolution`, dedup on repeated names, `IPP_OP_CUPS_*` private ops. ~3–4k LOC of pure Rust, no deps — full control beats adapting a client-oriented crate. `ipp` v8 stays an interop/fuzz oracle.
3. **Kerberos + OAuth → feature-gated parity.** `AuthType Negotiate` (via `libgssapi`) and `Bearer`/`OAuthServer` (via `jsonwebtoken`+`reqwest`/rustls) ship behind `gssapi`/`oauth` cargo features, off by default. The authz model treats AuthType as an enum from day one so enabling them later is additive, not a redesign.
4. **Web UI → stock CGI passthrough.** `WebInterface On` execs the stock `cgi-bin/*.cgi` binaries with the same env/argv contract cupsd uses — we inherit the entire admin UI instead of reimplementing it.
5. **Platform → Linux-first, macOS tier-2, no Windows.** PAM/systemd/`/dev/usb/lp*`/netlink on Linux; `local-cert` auth and IOKit USB on macOS behind `cfg`. The sandbox-exec profile (`cupsdCreateProfile`) is macOS-only and skipped.
6. **Repo → one cargo workspace** producing binaries with CUPS names: `cupsd`, `cups-lpd`, `cups-deviced`, `cupsfilter`, `cups-exec`, and `backend/{socket,ipp,ipps,lpd,snmp,usb,dnssd,serial,parallel}` (`ipps`/`ippusb` fold into the `ipp` binary like upstream).
7. **Runtime → tokio multi-thread**; queue/job mutations serialized through a scheduler domain so ordering matches cupsd's single-writer semantics while I/O (TLS, CGI, DNS-SD, process pipes) runs parallel.
8. **License → Apache-2.0 OR MIT.**

---

## 9. Research appendix (what I verified in source)

- `ipp.c` op table: all 50 ops enumerated (above); handlers `add_printer`/`print_job`/`create_subscriptions`/… mirror the dispatch.
- `job.c::start_job` + `cupsdContinueJob`: argv/env construction, `mimeFilter2` call, `gziptoany`/prefilter/port-monitor insertion, `FilterLimit`, remote vs local, `current_file` multi-doc loop, `single_file` PPD quirk.
- `process.c`: `posix_spawn` → `cups-exec` wrapper → `setgid(Group)/setuid(user)/umask 077`/execve; macOS `sandbox-exec` profile (skip).
- `client.c`: conn states `HTTP_STATE_*`, RFC 2817 `OPTIONS *`/upgrade, CGI dispatch table (`/admin`→admin.cgi etc.), `is_cgi` exec, file GETs.
- `dirsvc.c::dnssdBuildTxtRecord`: full TXT key list ported above.
- `subscriptions.c`: notifier procs = `ServerBin/notifier/<scheme>` argv `[scheme, notify-recipient-uri, notify-user-data]` fed IPP event msgs on stdin; `subscriptions.conf` fields incl. `NextEventId`/`LeaseDuration`/`Interval`/`ExpirationTime`/`UserData` (hex).
- `printers.c::write printers.conf`: `<Printer>/<DefaultPrinter>` + `NextPrinterId`, `UUID`, `State`, `StateTime`, `ConfigTime`, `Type`, `Accepting`, `Shared`, `Quota*`, `Attribute` lines (marker arrays), `AuthInfoRequired`, `JobSheets`, `AllowUser`, `DenyUser`, `Policy`, `ErrorPolicy`, `PortMonitor`, `OpPolicy`.
- `statbuf.c`: `INFO:/DEBUG:/DEBUG2:/ERROR:/WARNING:/NOTICE:/STATE:/PAGE:/ATTR:` line classes → log levels/state/attributes.
- `main.c`: flags `-c/-f/-F/-h/-l/-s/-t`; on-demand `service_checkin/checkout` KeepAlive file; `sd_notifyf READY=1`; timer sources in `select_timeout()` (client timeouts, DirtyCleanTime, JobHistoryUpdate, job cancel/kill/hold times, sleep-jobs, ListeningPaused, IdleExitTimeout).
- `cups-lpd.c`: RFC 1179 cmds incl. control-file directives and report formats.
- Auth: `CUPSD_AUTH_{NONE,BASIC,NEGOTIATE,BEARER,IP,INTERFACE,NAME}` + `Order`/`Allow`/`Deny`/`Require`/`Policy` model + OAuthGroup files (2.5).
- Backends: `ipp.c` forwards jobs via create-job/send-document w/ auth, compression, raster/urf selection, status sync, `auth-info-required` re-prompt; `snmp.c` supplies+scan; `usb.c` 1284 devid + quirks; `dnssd.c` resolves `dnssd://` → `ipp://`.
- No polkit integration in cupsd itself (cups-pk-helper is a separate package) — out of scope.
