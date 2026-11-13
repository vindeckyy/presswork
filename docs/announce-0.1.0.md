# presswork 0.1.0: a memory-safe CUPS replacement in Rust

Today we are releasing **presswork 0.1.0**, a drop-in replacement for
the CUPS print spooler and scheduler (`cupsd`) written entirely in
Rust. It speaks the same IPP wire protocol, reads the same
`/etc/cups` configuration files, uses the same `/var/spool/cups`
layout, and honors the same filter/backend process contract - so the
clients, queues, admin tools, and third-party drivers you already have
keep working, unmodified.

## Why rewrite the print spooler

Every byte the print stack handles - IPP attributes, HTTP, PPDs, MIME
rules, driver files - crosses parser boundaries that have historically
been C's least safe territory. The September 2024 CUPS vulnerability
chain (CVE-2024-47176 and friends) showed remote unauthenticated
command injection through exactly those parsers. presswork replaces
that surface with a strictly-typed, fuzzed codec: `unsafe` code is
forbidden workspace-wide outside a single audited FFI crate.

## What 0.1.0 proves

- **Wire-level conformance**: the upstream OpenPrinting `ipptool`
  corpus passes 34/0/1 against presswork (the one skip is a
  stock-client strictness artifact, documented in
  [conformance.md](conformance.md)).
- **Real-client compatibility**: the upstream `test/5.x` suite -
  `lp`, `lpq`, `lpr`, `cancel`, `lpstat`, `lpadmin`, `lpinfo`,
  `lpoptions`, `cups-lpd` - passes 34/34 using unmodified stock
  binaries over the same domain socket.
- **Differential testing**: `scripts/differential.sh` runs the same
  matrix against stock cupsd and presswork; every stock-pass test also
  passes on presswork.
- **A real scheduler**: persistent queues and jobs across restarts,
  subscriptions with lease semantics, IPP notifications, PPD
  persistence and patching (`lpadmin -o cups*=`), driverless
  IPP Everywhere and `drv://` resolution, TLS (`SSLPort`), policy and
  `Location` ACLs, `SO_PEERCRED` local auth, DNS-SD sharing, and the
  RFC 1179 `cups-lpd` shim - all verified end to end.
- **Real backends**: socket, file, ipp/ipps, lpd, dnssd, snmp
  discovery, plus usb/parallel/serial device nodes.

## Try it in one command

```sh
curl -fsSL https://raw.githubusercontent.com/vindeckyy/presswork/main/install.sh | sh
```

Or grab the `.deb` or tarball from the
[v0.1.0 release](https://github.com/vindeckyy/presswork/releases/tag/v0.1.0),
or evaluate in user space on port 8631 via
`brew install vindeckyy/tap/presswork`.

## Roadmap

Short term: crates.io publication for the library crates (`ipp-codec`
is the reusable piece for other Rust printing stacks), distro
packaging (nixpkgs submission is open, AUR package prepared), and the
hardware-printer test matrix. Longer term: macOS support and a native
web admin surface to replace the CGI layer.

presswork is Apache-2.0 OR MIT, independently implemented, and not
affiliated with OpenPrinting. Bug reports and compatibility
divergences are welcome on the
[issue tracker](https://github.com/vindeckyy/presswork/issues).
