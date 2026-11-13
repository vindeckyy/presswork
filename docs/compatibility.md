# Compatibility matrix

Where yindle stands against the CUPS 2.x surface it replaces. The
authoritative evidence is `docs/conformance.md` (per-test results against
the upstream `ipptool` suite) and `docs/deviations.md` (intentional
non-matches).

## Wire & protocol

| Surface | Status |
|---|---|
| IPP/1.0-2.2 wire codec | byte-compatible with libcups `ipp` (delimiter order, out-of-band tags, collections, dateTime, range, resolution) |
| IPP Everywhere (PWG 5100.14) | full required-attribute set - `ipp-everywhere` suite passes |
| HTTP/1.1 | keep-alive, chunked, `Expect: 100-continue`, `Host` requirement |
| TLS | `SSLListen`, HTTP `OPTIONS`→Upgrade (2817), cert/key config |
| Unix domain socket | `Listen /path`, perms, `SO_PEERCRED` auth |

## Operations

* **Read ops** - Get-Printer-Attributes / Get-Printers / Get-Jobs /
 Get-Job-Attributes / Get-Subscriptions / Get-Notifications /
 Get-Devices / Get-PPDs / Get-PPD - all implemented and tested.
* **Job ops** - Print-Job, Print-URI, Create-Job, Send-Document,
 Validate-Job, Cancel(-Current), Hold/Release/Restart/Reprocess,
 Suspend/Resume/Promote, Get-Document(s), Identify - implemented.
* **Admin ops** - CUPS-Add/Delete-Printer(-Class), CUPS-Set-Default,
 Accept/Reject-Jobs, Enable/Disable, Pause/Resume, Create-Local-Printer,
 Set-Printer-Attributes - implemented behind the same `<Policy>/<Limit>`
 authz as upstream.
* **Subscriptions & events** - RFC 3995 pull (ippget) delivery, lease
 durations, per-event groups, job/printer/system masks.

## Printer models

| Model | Status |
|---|---|
| Driverless IPP / IPP Everywhere | first-class - synthesized `everywhere` PPD, native formats |
| `.drv` driver database | parsed → `drv://` listing + PPD compilation (`ModelName`/`PCFileName`/capabilities) |
| `.ppd` files | listed + served under the PPD dir |
| PPD job processing | `*cupsFilter`/`*cupsFilter2` final driver-filter stage in the pipeline |
| Legacy C filters/backends | same argv/env/fd contract - external programs run unmodified |

## Config & persistence

* `cupsd.conf`, `cups-files.conf`, `mime.types`, `mime.convs`,
 `printers.conf`, `classes.conf`, `<Location>/<Limit>/<Policy>` - same
 syntax, read in place.
* `printers.conf` write-back is byte-compatible field order; queues,
 options, `Option ppd-name`/`printer-device-id` driver bindings persist.

## Platforms

* **Linux** - primary target (PAM, `SO_PEERCRED`, systemd socket
 activation + `sd_notify`, `/dev/usb/lp*`, netlink DNS-SD).
* **macOS** - tier-2 roadmap; `local-cert` auth and IOKit USB behind `cfg`.
* **Windows** - out of scope (upstream doesn't run there either).
