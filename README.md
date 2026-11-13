# presswork

[![CI](https://github.com/vindeckyy/presswork/actions/workflows/ci.yml/badge.svg)](https://github.com/vindeckyy/presswork/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue)](LICENSE-APACHE)
[![MSRV](https://img.shields.io/badge/rust-1.88%2B-orange)](Cargo.toml)
[![Conformance](https://img.shields.io/badge/upstream%20conformance-34%2F0%2F1-brightgreen)](docs/conformance.md)

A memory-safe **CUPS replacement in Rust**: a drop-in `cupsd` print
server and print spooler that speaks the IPP protocol to every
application, driverless IPP Everywhere printer, and AirPrint client on
your network.

**Status:** upstream conformance green - `test/4.x` + `examples/`
matrix 34 passed / 0 failed / 1 skipped, `test/5.x` stock-client suite
34/34. See [`docs/conformance.md`](docs/conformance.md) for the full
evidence matrix and methodology.

## What this is

Rust IPP crates today let applications *talk to* printers or build
printer applications. Nothing implements the local print spooler that
applications submit jobs to: queue management, job scheduling, the
filter/backend pipeline, permissions and policy. presswork builds that -
byte-compatible with the `cupsd` that exists on every Linux and macOS
system today:

- Same IPP wire protocol, op codes, and status codes (validates with the
 upstream `ipptool` test suite)
- Same config files: `cupsd.conf`, `cups-files.conf`, `printers.conf`,
 `classes.conf`, `subscriptions.conf`
- Same spool layout: `/var/spool/cups/c%05d`, `d%05d-%03d`
- Same filter/backend process contract (argv 0-6, environment, fds 0-4)
 - existing `cups-filters` and third-party backends work unchanged
- Same DNS-SD sharing (`_ipp._tcp` etc.) and D-Bus notifier signals
- Same stock CGI web interface, served by exec'ing the stock CGIs

## Features

- **IPP server** - the full CUPS 2.x operation set (50+ ops): print,
  hold, release, cancel, subscriptions with lease semantics, push/pull
  event notifications
- **Print spooler & scheduler** - permanent queues, job state machine,
  spool persistence across restarts, quota and policy engine
- **Driverless printing** - IPP Everywhere / driverless-IPP attribute
  synthesis; PPD-based legacy drivers work too (`.drv`, `ppd-name`,
  `lpadmin -o cups*=`)
- **Print backends** - `socket`, `ipp`/`ipps` (rustls), `lpd`, `dnssd`,
  `usb`, `parallel`, `serial`, `snmp` discovery, plus third-party
  CUPS backends unchanged
- **Sharing & discovery** - AirPrint/mDNS (`_ipp._tcp`), Bonjour TXT
  records, D-Bus signals, `cups-lpd` for RFC 1179 clients
- **Drop-in config** - `cupsd.conf`, `printers.conf`, `subscriptions.conf`
  parsed with upstream semantics; `<Policy>`/`<Location>` auth,
  `SO_PEERCRED`, TLS via `SSLPort`/`SSLOptions`
- **Security by construction** - `#![forbid(unsafe_code)]` outside one
  audited `sys` crate; cargo-fuzz on every wire parser; `cargo audit`
  clean; systemd sandboxing

## Why a rewrite

Every byte from the network, every IPP attribute, every generated PPD is
parsed by a strictly-typed, fuzzed codec with `#![forbid(unsafe_code)]`.
The September 2024 CUPS chain (CVE-2024-47176 et al.) demonstrated remote
unauthenticated command injection through the C print stack's parsers;
the entire exposed surface is what presswork replaces. Filters and
backends additionally run under Linux sandboxing (Landlock/seccomp)
beyond what the C scheduler can express.

## Layout

```
crates/ independently testable library crates
 ipp-codec/ IPP wire codec + model (byte-exact libcups semantics)
 cups-config/ cupsd.conf/cups-files.conf parsers
 httpd/ HTTP/1.1 server + RFC 2817 TLS upgrade
 mime-db/ mime.types/convs + least-cost filter graph
 printer/ queue registry + printers.conf
 job/ job state machine + spool files
 pipeline/ filter/backend process supervisor
 ops/ the 50-op IPP dispatcher
 authz/ authn/ policy/location ACLs, PAM/Kerberos/OAuth
 events/ subscriptions + notifier feeder
 dnssd/ mDNS registration/browsing
 cups-tls/ rustls + cert management
 cups-dbus/ zbus notifier + colord
 cups-log/ error_log/access_log/page_log writers
 backend-common/ shared backend-side protocol helpers
 sys/ the only unsafe-permitted crate
bins/
 cupsd the scheduler daemon
 cups-lpd RFC 1179 LPD shim
 cups-deviced device discovery multiplexer
 cupsfilter standalone filter-chain tool
 cups-exec privilege-drop exec helper
 backends/ socket ipp lpd snmp usb dnssd serial parallel
```

`presswork` is a working name; the installed binaries keep the CUPS
names for drop-in compatibility.

## Install

One command, x86_64 Linux:

```
curl -fsSL https://raw.githubusercontent.com/vindeckyy/presswork/main/install.sh | sh
```

The installer resolves the latest release, verifies its SHA256SUMS
entry, lands the upstream FHS layout (`/usr/sbin/cupsd`,
`/usr/lib/cups/{daemon,backend,filter}`, `/etc/cups`,
`/var/{spool,log,cache}/cups`), creates `lp`/`lpadmin`, and enables
socket activation (`cups.socket` + `cups.path`, upstream's model).
Flags: `--no-start`, `--version X`, `--from DIR`, `--force`.

Prefer a package or the manual path? Each
[release](https://github.com/vindeckyy/presswork/releases) also ships a
`.deb` (`sudo dpkg -i presswork_0.1.0-1_amd64.deb`, declared
`Conflicts: cups,cups-daemon`) and the raw FHS tarball.

Verify: `lpstat -t`, then `lpadmin -p test -E -v ipp://<printer> -m
everywhere` and `lp -d test /etc/hostname`. Because the wire, config
files, and spool paths match CUPS 2.x, existing clients (`lp`, `lpq`,
`lpstat`, `lpr`, `cancel`, `lpoptions`, `cups-lpd`, GNOME/KDE print
dialogs) work unmodified. `docs/migration.md` covers swapping stock
cupsd in and out; side-by-side evaluation on a nonstandard port is a
three-line `cupsd.conf`.

## Building

Rust 1.88+:

```
cargo build --workspace --release
cargo test --workspace
sudo make install        # same FHS layout; respects DESTDIR/PREFIX
```

Distro packaging lives in `packaging/` (debian, rpm, arch, alpine, nix);
`./scripts/dist.sh` reproduces the release artifacts.

## Compatibility

Target: CUPS 2.5 semantics on Linux (macOS tier-2). Divergences are
documented in `docs/deviations.md` once they exist - the goal is none
you can observe without reading the source.

## License

Apache-2.0 OR MIT. `presswork` is an independent implementation of the
IPP protocols and CUPS file formats; where algorithms are ported from
upstream CUPS (Apache-2.0), attribution is retained.
