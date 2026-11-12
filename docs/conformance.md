# IPP conformance matrix

Status of `presswork` against the stock OpenPrinting `ipptool` suite
(`/usr/share/cups/ipptool`, mirrored from `examples/` in the CUPS 2.5
source tree). Each `.test` file is run with
`ipptool -t -f <document> ipp://<host>/printers/<queue>`; the counts are
`[PASS]`/`[FAIL]`/`[SKIP]` sub-tests.

## Fully green

| Test | Notes |
|------|-------|
| `cancel-current-job` | limit + requested-attributes filtering |
| `create-job`, `create-job-format`, `create-job-sheets`, `create-job-timeout` | Create-Job + Send-Document |
| `fax-job` | |
| `get-completed-jobs` | `which-jobs=completed` |
| `get-devices` | `cups-deviced` under `ServerBin/daemon/` |
| `get-jobs` | `which-jobs`, `limit`, `my-jobs`, `requesting-user-name` |
| `get-job-template-attributes` | job-template group incl. `media-col-database` on explicit request |
| `get-printer-attributes-suite` | **6/6** — `requested-attributes` group semantics: absent, `all`, `all`+`media-col-database`, `media-col-database`, `printer-description`, `job-template` |
| `get-printer-attributes`, `get-printer-description-attributes`, `get-printers` | |
| `get-subscriptions` | |
| `identify-printer`, `identify-printer-display`, `identify-printer-multiple` | |
| `ipp-backend` | |
| `print-job`, `print-job-and-wait`, `print-job-deflate`, `print-job-gzip`, `print-job-hold`, `print-job-letter`, `print-job-manual`, `print-job-media-col`, `print-job-password` | end-to-end through filter→backend; `file` backend writes the document |
| `print-uri` | `document-uri` (`file://`) fetch |
| `validate-job` | |
| `create-printer-subscription` | pull (ippget) variant; push variant skips (no `-d recipient`) |
| `get-ppd`, `get-ppd-printer` | `cups-driverd cat` streams the PPD body; `printer-uri` resolves the driverless `everywhere` PPD |
| `get-ppds`, `get-ppds-make`, `get-ppds-product`, `get-ppds-drv-only` | `cups-driverd list` → per-driver `ppd-*` groups; honors `include-schemes=drv`, `ppd-make`, `ppd-product`, `limit` |

## RFC / PWG suites — 17/18 each

`ipp-1.1`, `ipp-2.0`, `ipp-2.1`, `ipp-2.2`, `ipp-everywhere` each pass all
assertions except the tail `Get-Job-Attributes Until Job Complete` poll.
That sub-test re-uses `$job-id` captured from `Get-Jobs
which-jobs=not-completed` — when it selects a *held* `Create-Job` (a job
that intentionally has no document yet), the job legitimately never
reaches a final `job-state >6`, so the repeat loop exhausts. The daemon
sends a valid ~400-byte response for every poll; the mechanism passes
whenever the polled job actually completes (verified with an explicit
print-and-poll test).

## Auth-required — `client-error-forbidden` is the *correct* result

Upstream `<Limit> … Require user @SYSTEM` denies unauthenticated admin ops
over TCP. Over the **unix domain socket**, `SO_PEERCRED` peer-credential
auth authenticates the connecting user (no password) and `@SYSTEM`
expands to the configured `SystemGroup` — so local `lpadmin`-group users
can administer queues, matching real CUPS.

| Test | Result |
|------|--------|
| `set-attrs-hold`, `cups-create-local-printer`, `cupsenable`/`cupsaccept` style | `forbidden` over TCP without credentials (correct); authorized over the unix socket via PeerCred |
| `get-notifications` | passes with `-d id=<subscription-id>` (pull delivery verified) |
| `get-printers-printer-id` | passes with `-d printer_id=<id>` |

## P7 — PPD / legacy-driver parity

`CUPS-Get-PPDs`/`CUPS-Get-PPD` run a `cups-driverd` helper under
`ServerBin/daemon/` (the `cups-deviced` analogue). Driver sources: the
built-in IPP Everywhere model, `.drv` driver-database files (parsed for
`ModelName`/`PCFileName`/capability blocks → `drv://` entries, compiled
to PPDs on `cat`), and `.ppd` files under the PPD dir. All 9 upstream
`get-ppd*`/`get-ppds*` tests pass.

`CUPS-Create-Local-Printer` driver selection: `ppd-name`/
`printer-device-id`/`device-id`/`ppd-make` are stored on the queue
(`printers.conf` `Option` lines), so `Get-PPD` resolves `printer-uri` to
the bound driver's compiled PPD and `Get-Printer-Attributes` emits the
stored `printer-device-id`.

PPD-based job processing: the scheduler reads the queue's PPD
`*cupsFilter`/`*cupsFilter2` declarations to pick the conversion target
MIME and appends a non-`-` `program` as the final driver-filter stage —
verified end-to-end (a `.drv`-bound queue ran `rastertofoo` before the
backend).

## Known engineering notes

- `media-col-database` / `media-size-database` are opt-in: withheld when
  `requested-attributes` is absent *and* when a group keyword (`all`,
  `job-template`, `printer-description`) is used; emitted only on a
  literal request — matching upstream.
- `Get-Notifications` emits one `event-notification-attributes-tag` group
  per event (`ippAddSeparator`), with `notify-event` +
  `notify-subscribed-event`, `notify-printer-uri` as a full URI, and
  `printer-name`.
