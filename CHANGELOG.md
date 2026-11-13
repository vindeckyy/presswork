# Changelog

All notable changes to yindle are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.1] - 2026-11-13

### Changed

- **Renamed: presswork is now yindle.** The old name collided with
  PressWork (https://presswork.it/), a commercial office suite, see
  issue #8. Thanks to Till Kamppeter for flagging it.
- Repository, docs, package and crate names move to `yindle`.
- The installed binaries keep their CUPS names (`cupsd`, `cupsfilter`,
  and the rest) and all config, spool and service paths are unchanged,
  so this is not a compatibility break.
- One wire-visible string changes: the IEEE 1284 manufacturer token is
  now `MFG:yindle`.
- The Alpine OpenRC service is also renamed from `presswork` to
  `yindle`; the systemd units keep their `cups.*` names.

## [0.1.0] - 2026-11-12

First public release: a memory-safe Rust reimplementation of the CUPS 2.x
print spooler and IPP scheduler, built for drop-in compatibility.

### Highlights

- **cupsd** scheduler: Tokio-based, reads `/etc/cups/cupsd.conf`,
  `cups-files.conf`, and `printers.conf` in place; runs as `lp` with the
  upstream FHS layout, socket activation, and `SO_PEERCRED` local auth.
- **Full IPP surface**: operations, status codes, attribute groups, and
  wire encoding verified against the upstream `ipptool` corpus -
  34 passed / 0 failed / 1 skipped (the skip is a stock-tool strictness
  artifact, documented in `docs/conformance.md`).
- **Stock client compatibility**: upstream `lp`, `lpq`, `lpr`, `cancel`,
  `lpstat`, `lpadmin`, `lpinfo`, `lpoptions`, `cupsenable`, `cupsaccept`,
  and `cups-lpd` (RFC 1179) all verified end to end - the complete
  upstream `test/5.x` client suite passes 34/34.
- **Driverless first**: IPP Everywhere and `driverless` PPD generation
  via cups-driverd, plus a PPD/legacy-driver layer - saved PPDs persist
  under `ServerRoot/ppd`, `lpadmin -o cups*=` patches them, and
  `CUPS-Get-PPD` resolves `drv://` and `everywhere`.
- **Backends**: socket, file, ipp/ipps (TLS via native roots plus the
  CUPS `ssl/` store), lpd, dnssd, snmp discovery, and real usb/parallel/
  serial device backends - all emitting the upstream discovery contract.
- **Auth, TLS, sharing**: policy/`Location`/authz evaluation matching
  upstream `cupsdIsAuthorized` semantics (including `Satisfy any`
  default), `SSLPort`/`SSLListen` with rustls, subscription and
  notification support, and DNS-SD advertising.
- **Safety boundary**: `#![forbid(unsafe_code)]` workspace-wide; the only
  unsafe code is the audited `crates/sys` FFI shim, enforced in CI.

### Validation

- `cargo audit` and `cargo deny`: clean.
- `cargo clippy --workspace --all-targets -D warnings`: clean on stable
  and MSRV 1.88; `cargo fmt --check`: clean.
- Fuzz: `ipp-codec`, `config-lexer`, `printers-conf`, and `mime-db`
  targets exercised (~1.5M execs); three `mime-db` crashes found and
  fixed before release.
- Differential runner (`scripts/differential.sh`) executes the same
  matrix against stock cupsd and yindle; every stock-pass test also
  passes on yindle.
- Memory: RSS flat at ~4.3 MB across 100 Print-Job requests in soak
  testing.

### Known limitations

- Physical-printer matrix (real USB/serial/network devices) is not yet
  covered by CI; backends are tested against the device-node layer.
- Kerberos/GSSAPI and OAuth are feature-gated and off by default.
- Web/CGI integration is present as a compatibility boundary; the stock
  CUPS CGI set is retained for v0.1.0.

### Install

Prebuilt x86_64 Linux tarball and `.deb` are attached to this release.
See README for source builds (`cargo build --release && sudo make
install`) and `docs/migration.md` for moving from stock CUPS.
