# presswork

A memory-safe, drop-in replacement for the CUPS 2.x print scheduler —
`cupsd` and the printing stack — written in Rust.

**Status: early development (P0).** Not yet usable. See
[`PLAN.md`](PLAN.md) for the full design, contract surfaces, and
milestones.

## What this is

Rust IPP crates today let applications *talk to* printers or build
printer applications. Nothing implements the local print spooler that
applications submit jobs to: queue management, job scheduling, the
filter/backend pipeline, permissions and policy. presswork builds that —
byte-compatible with the `cupsd` that exists on every Linux and macOS
system today:

- Same IPP wire protocol, op codes, and status codes (validates with the
  upstream `ipptool` test suite)
- Same config files: `cupsd.conf`, `cups-files.conf`, `printers.conf`,
  `classes.conf`, `subscriptions.conf`
- Same spool layout: `/var/spool/cups/c%05d`, `d%05d-%03d`
- Same filter/backend process contract (argv 0–6, environment, fds 0–4)
  — existing `cups-filters` and third-party backends work unchanged
- Same DNS-SD sharing (`_ipp._tcp` etc.) and D-Bus notifier signals
- Same stock CGI web interface, served by exec'ing the stock CGIs

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
crates/          independently testable library crates
  ipp-codec/     IPP wire codec + model (byte-exact libcups semantics)
  cups-config/   cupsd.conf/cups-files.conf parsers
  httpd/         HTTP/1.1 server + RFC 2817 TLS upgrade
  mime-db/       mime.types/convs + least-cost filter graph
  printer/       queue registry + printers.conf
  job/           job state machine + spool files
  pipeline/      filter/backend process supervisor
  ops/           the 50-op IPP dispatcher
  authz/ authn/  policy/location ACLs, PAM/Kerberos/OAuth
  events/        subscriptions + notifier feeder
  dnssd/         mDNS registration/browsing
  cups-tls/      rustls + cert management
  cups-dbus/     zbus notifier + colord
  cups-log/      error_log/access_log/page_log writers
  backend-common/ shared backend-side protocol helpers
  sys/           the only unsafe-permitted crate
bins/
  cupsd          the scheduler daemon
  cups-lpd       RFC 1179 LPD shim
  cups-deviced   device discovery multiplexer
  cupsfilter     standalone filter-chain tool
  cups-exec      privilege-drop exec helper
  backends/      socket ipp lpd snmp usb dnssd serial parallel
```

`presswork` is a working name; the installed binaries keep the CUPS
names for drop-in compatibility.

## Building

```
cargo build --workspace
cargo test --workspace
```

## Compatibility

Target: CUPS 2.5 semantics on Linux (macOS tier-2). Divergences are
documented in `docs/deviations.md` once they exist — the goal is none
you can observe without reading the source.

## License

Apache-2.0 OR MIT. `presswork` is an independent implementation of the
IPP protocols and CUPS file formats; where algorithms are ported from
upstream CUPS (Apache-2.0), attribution is retained.
