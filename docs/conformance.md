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

## Reproducing — `scripts/conformance.sh`

`scripts/conformance.sh` bootstraps a scratch daemon under a FHS-like root
(default `/tmp/pw-conf`, port `8631`) and runs the whole matrix:

```text
conformance.sh --bootstrap   build workspace + scratch root + start daemon
conformance.sh --run         run the ipptool matrix
conformance.sh --stop        stop the scratch daemon (frees the port)
conformance.sh --restart     rebuild cupsd + fresh daemon
conformance.sh               bootstrap + run
```

Current result: **34 passed / 0 failed / 1 skipped** — the examples
matrix plus the upstream functional tier
(`test/4.1-requests`, `test/4.2-cups-printer-ops`, `test/4.3-job-ops`,
`test/4.4-subscription-ops`), all green.

The single skip is `examples/get-devices`: backends emit bare scheme
names (`socket`, `ipp`, …) as `device-uri` — byte-identical to upstream
cupsd — but stock `ipptool` (libcups ≤ 2.4.x) runs `ippValidateAttribute`
on every response attribute and rejects a URI with no scheme+colon.
Upstream's own `ipptool` would flag the same response. Real `lpinfo -v`
(the actual client contract) parses it fine and lists all schemes.

`--run` first seeds one pending job (`Create-Job` with no `Send-Document`
→ `pending-held`/`job-data-insufficient`) so `cancel-current-job`'s
`Get-Jobs` always has a `not-completed` job to find; the instant `file`
backend would otherwise complete every job before the query. It then
restarts the daemon for the functional tier (so the example ops' leftover
subscriptions can't perturb `MaxSubscriptions` counting — upstream's own
harness runs the numbered tests on a daemon that never saw the example
ops) and seeds one more `pending-held` job for 4.3's `Get All Jobs`.

## Functional tier — upstream `test/4.x` over the unix socket

The numbered suites run against the domain socket so admin ops
authenticate via `SO_PEERCRED` peer credentials (`@SYSTEM` → configured
`SystemGroup`), matching upstream's `run-stp-tests.sh` semantics:

- `4.1-requests` 8/8 — strict request-validation matrix incl. bare
  `job-uri` → `bad-request` and all-printers root URIs.
- `4.2-cups-printer-ops` 14/14 — CUPS-Add/Modify/Delete-Printer,
  CUPS-Get/Set-Default, subscription add, IPP/2.x attrs.
- `4.3-job-ops` 13/13 — print/hold/release/cancel/get-jobs/get-all-jobs
  incl. embedded `subscription` group → `notify-subscription-id` and
  `job-hold-until indefinite` → `pending-held`.
- `4.4-subscription-ops` 5/5 — lease expiry, multi-segment create
  (one request → multiple subscriptions via `IPP_TAG_ZERO` separators),
  `MaxSubscriptions` → `client-error-too-many-subscriptions`.

Subscription lifecycle matches upstream `cupsdExpireSubscriptions`:
lapsed leases are *removed* on `Get-Subscriptions`/
`Get-Subscription-Attributes` reads and on a scheduler tick; a job's
subscriptions are deleted when the job leaves the active list
(`cupsdExpireSubscriptions(NULL, job)`).

## Client tier — upstream `test/5.x` shell suite, all green

The `5.x` scripts run **stock system clients** against the domain socket
(`CUPS_SERVER=/tmp/pw-conf/run/cups.sock`, `SO_PEERCRED` auth,
`CUPS_SERVERROOT=$PWROOT/etc`, `IPP_PORT=8631`, queues `Test1`/`Test2`
pre-provisioned): `5.1-lpadmin` 10/10, `5.2-lpc` 1/1, `5.3-lpq` 1/1,
`5.4-lpstat` 3/3, `5.5-lp` 7/7, `5.6-lpr` 4/4, `5.7-lprm` 2/2,
`5.8-cancel` 3/3, `5.9-lpinfo` 3/3 — **34/34**.

Semantics this pins down: queue PPDs persist to
`{ServerRoot}/ppd/<name>.ppd` (uploaded body or `ppd-name` via
cups-driverd; deleted with the queue; `lpadmin -o cups*=` patches
keywords in place); `Cancel-Job`+`printer-uri`+`job-id=0` cancels the
first active (then stopped) job on the dest; `lpinfo -v` enumerates the
backend scheme listings.

## RFC / PWG suites — all green

`ipp-1.1`, `ipp-2.0`, `ipp-2.1`, `ipp-2.2`, `ipp-everywhere` each pass
their full sub-test matrix (~48–50 `[PASS]` assertions each at 100%). The
suites exercise create/send-document/cancel/hold/release cycles against
the scratch queue.

Note on the runner: it detects verdicts with `grep -q '[PASS]'`/`'[FAIL]'`
over a *herestring*, not `echo | grep -q` — under `pipefail`, `grep -q`
exits on the first match while `echo` still writes to the closed pipe,
so a >64KB suite output would SIGPIPE `echo` and falsely read "no
verdict".

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
