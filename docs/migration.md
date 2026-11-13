# Migrating from C cupsd - the zero-risk path

presswork is designed to run **alongside** the stock `cupsd` so a distro
or admin can prove equivalence on live traffic before committing. Nothing
below touches the running spooler until the final swap.

## 1. Install on an alternate port

Build or install the package, then run presswork on a non-conflicting
listener with its own config root:

```sh
# Copy the stock config into a scratch root (no changes to /etc/cups).
mkdir -p /tmp/presswork/etc
cp /etc/cups/{cupsd.conf,cups-files.conf,printers.conf,mime.types,mime.convs} /tmp/presswork/etc/

# Add a non-conflicting listener.
echo 'Listen 127.0.0.1:8631' >> /tmp/presswork/etc/cupsd.conf
echo 'Listen /tmp/presswork/cups.sock' >> /tmp/presswork/etc/cupsd.conf

/usr/sbin/cupsd -c /tmp/presswork/etc/cupsd.conf -f &
```

## 2. A/B with `CUPS_SERVER` - no disruption

Every standard CUPS client honors `CUPS_SERVER`. Point it at the
presswork listener and run the real workload:

```sh
export CUPS_SERVER=127.0.0.1:8631
ipptool ipp://localhost/printers/<queue> get-printer-attributes.test
lpq # query the presswork daemon
lp /path/to/file # submit a real job
```

The stock daemon keeps serving `:631` and the domain socket throughout.
To compare an op directly, run it against both endpoints and diff the
IPP responses - the conformance matrix in `docs/conformance.md` is the
expected-equivalence reference.

## 3. Validate the lifecycle

* Submit jobs through a filter→backend chain; confirm output and
 `job-state` transitions (`pending→processing→completed`).
* Exercise the ops your site uses (`lp`, `lpstat`, `cancel`, `lpadmin`,
 the CUPS web dialogs via the CGI layer).
* Run the upstream `ipptool` examples against the presswork endpoint.

## 4. Swap when satisfied

```sh
systemctl stop cups cups.socket cups.path
systemctl disable cups cups.socket cups.path
systemctl enable --now presswork.service presswork.socket presswork.path
```

presswork reads `/etc/cups` **in place** - `printers.conf`, `cupsd.conf`,
`cups-files.conf`, `ppd/` all carry over unchanged, so existing queues,
policies, and PPD bindings survive the cutover. To roll back, re-enable
the stock units; the config files were never rewritten.

## What deliberately differs

`docs/deviations.md` lists every intentional non-match (dropped legacy
knobs, tightened defaults). Anything not listed there that behaves
differently is a conformance bug - report it.
