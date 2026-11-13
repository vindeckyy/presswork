# yindle - a CUPS replacement in Rust

yindle is a memory-safe, drop-in replacement for the CUPS print
server (`cupsd`): a print spooler and IPP scheduler written in Rust that
keeps the Common UNIX Printing System's wire protocol, configuration
files, spool layout, and filter/backend contracts, so existing clients,
print dialogs, and admin tools work unmodified.

## Why yindle

- **Memory safety by construction** - every byte from the network is
  parsed by a strictly-typed, fuzzed codec; `unsafe` is forbidden
  workspace-wide outside one audited FFI crate.
- **Drop-in CUPS 2.x compatibility** - same IPP operations and status
  codes, same `cupsd.conf` / `cups-files.conf` / `printers.conf`
  parsing, same `/var/spool/cups` layout, same backend/filter contract.
- **Driverless printing first** - IPP Everywhere and AirPrint work out
  of the box; PPD and legacy-driver queues are supported for parity.
- **Verified against upstream** - the stock `ipptool` conformance
  matrix passes 34/0/1 and the upstream `test/5.x` client suite passes
  34/34, including `lp`, `lpq`, `lpr`, `cancel`, `lpstat`, `lpadmin`,
  and `cups-lpd` (RFC 1179).

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/vindeckyy/yindle/main/install.sh | sh
```

Or grab the `.deb` / tarball from the
[releases page](https://github.com/vindeckyy/yindle/releases), or
build from source with `cargo build --release && sudo make install`.

## Documentation

- [Installation guide](install.md)
- [0.1.0 announcement](announce-0.1.0.md)
- [Conformance matrix and methodology](conformance.md)
- [Migrating from stock CUPS](migration.md)
- [Compatibility surface](compatibility.md)
- [Documented deviations](deviations.md)
- [Security model](security.md)

Source, issues, and releases:
[github.com/vindeckyy/yindle](https://github.com/vindeckyy/yindle)
