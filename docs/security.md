# Security posture

presswork is a long-lived, network-facing daemon that historically runs
with elevated privileges and parses attacker-controlled input - the exact
profile that made the C printing stack's CVE history so costly. This
document records the threat model and the structural mitigations.

## The headline: the Sept 2024 disclosure chain cannot recur here

CVE-2024-47176 / -47076 / -47175 / -47177 (CVSS 9.9) gave remote,
unauthenticated RCE in `cups-browsed`/`cups-filters`. The chain: an
attacker-controlled IPP `printer-uri`/`printer-privacy-policy-uri` flowed
**unsanitized** into a generated PPD, then into a `foomatic-rip` command
line built via string substitution - classic command injection through a
config file.

Every stage of that *class* is structurally prevented:

| Stage in the C chain | presswork equivalent | Why it can't recur |
|---|---|---|
| Untrusted IPP attrs parsed into a PPD | `ipp-codec` - `#![forbid(unsafe_code)]`, fuzzed round-trip vs libcups | Strictly-typed decode; no format-string or buffer classes in the parser |
| PPD text spliced into a command line | argv built as `Vec<OsString>`; backends/filters are `execv`-style spawns | No `system()`/`popen` anywhere; a printer URI can never become a shell token |
| `foomatic-rip` template substitution | `.drv`→PPD compilation is typed synthesis, not text templating | Output escaping exists where libppd had none |
| Driver runs with daemon privileges | filters/backends spawn as the queue's user with `NoNewPrivileges` | No privilege gain path in the child contract |

## Memory safety

* Every crate **except `sys`** is `#![forbid(unsafe_code)]`. `sys` is the
 only crate permitted `unsafe` - it wraps `getspnam`/`crypt`, `SO_PEERCRED`,
 `ioctl`, fd and uid/gid syscalls. `grep -rn unsafe` returns only `sys`
 plus the `#![forbid]` declarations.
* The IPP wire codec, HTTP/1.1 parser, config lexer/parser, MIME magic
 evaluator, `.drv` parser, and `printers.conf` reader are all safe Rust.
* `cargo-fuzz` targets cover the wire codec, config lexer, `mime.convs`/
 `mime.types`, and `printers.conf` - run in CI with crashes blocking.

## Spawner / privilege model

* Filter+backend argv is constructed as an exact `Vec` (never a shell
 string): `[prog, job-id, user, title, copies, options, file]`. Options
 that reach `argv[5]` are a `name=value` string the filter parses - it is
 never re-evaluated by a shell.
* Environment for children is a fixed allowlist (`CONTENT_TYPE`,
 `DEVICE_URI`, `CUPS_*`, `PPD`…) - no user-controlled env names.
* systemd sandboxing ships in `data/systemd/cups.service`:
 `ProtectSystem=full` + `ReadWritePaths`, `ProtectHome=read-only`,
 `PrivateTmp`, `NoNewPrivileges`, `RestrictSUIDSGID`, `LockPersonality`,
 `ProtectKernel*/ControlGroups/Clock/Hostname`, `RestrictAddressFamilies`
 - tuned so filters/backends still function.

## Auth surface

* `Basic` auth verifies against the system shadow DB (`getspnam`+`crypt`),
 the same trust decision PAM-backed cupsd makes.
* Unix-socket `SO_PEERCRED` is kernel-verified - the username and group set
 come from the peer's uid, not a client-claimed header.
* `@SYSTEM` expands to the *configured* `SystemGroup` (no hardcoded
 `lp`/`root`), so distro `lpadmin`/`wheel` conventions are honored.
* Feature-gated `Bearer`/OAuth and `Negotiate`/Kerberos are off by default.

## Reporting

See `SECURITY.md` for the disclosure process. Run `cargo audit` and the
fuzz targets before any release; the SBOM is generated with
`cargo cyclonedx` from `Cargo.lock`.
