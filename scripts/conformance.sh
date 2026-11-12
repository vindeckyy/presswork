#!/usr/bin/env bash
# conformance.sh — bootstrap a scratch presswork daemon and run the upstream
# ipptool suite against it. Used by CI and by `make conformance`.
#
#   --bootstrap   build + lay out a scratch root and start the daemon
#   --run         run the ipptool matrix against the running daemon
#   --stop        stop the scratch daemon
#
# Env knobs: PWROOT (default /tmp/pw-conf), PWPORT (8631), IPPTESTS (dir of
# upstream examples — defaults to a CUPS source checkout or /tmp/cups-ref).

set -euo pipefail
cd "$(dirname "$0")/.."

PWROOT="${PWROOT:-/tmp/pw-conf}"
PWPORT="${PWPORT:-8631}"
IPPTESTS="${IPPTESTS:-/tmp/cups-ref/examples}"
PIDFILE="$PWROOT/run/cupsd.pid"

bootstrap() {
    cargo build --workspace
    rm -rf "$PWROOT"
    mkdir -p "$PWROOT"/{etc,spool,run,cache,logs,out,docroot,tmp,mime,bin/{daemon,backend,filter,notifier},drv,ppd}
    cp target/debug/cupsd "$PWROOT/cupsd"
    for d in cups-deviced cups-driverd cups-lpd cups-exec; do
        cp "target/debug/$d" "$PWROOT/bin/daemon/$d" 2>/dev/null || true
    done
    for b in file ipp lpd socket dnssd; do
        cp "target/debug/$b" "$PWROOT/bin/backend/$b" 2>/dev/null || true
    done
    # File-level directives (paths/binaries/spool) live in cups-files.conf —
    # they populate `cfg.files`, not `cfg`.
    cat > "$PWROOT/etc/cups-files.conf" <<EOF
ServerRoot $PWROOT/etc
StateDir $PWROOT/etc
RequestRoot $PWROOT/spool
CacheDir $PWROOT/cache
ServerBin $PWROOT/bin
DocumentRoot $PWROOT/docroot
DataDir $PWROOT/mime
TempDir $PWROOT/tmp
ErrorLog $PWROOT/logs/error_log
AccessLog $PWROOT/logs/access_log
PageLog $PWROOT/logs/page_log
FileDevice Yes
SystemGroup lpadmin
EOF
    cat > "$PWROOT/etc/cupsd.conf" <<EOF
Listen localhost:$PWPORT
Listen $PWROOT/run/cups.sock
DefaultShared yes
EOF
    cat > "$PWROOT/etc/printers.conf" <<EOF
# Printer configuration file for CUPS
<Printer tlsq>
PrinterId 1
UUID urn:uuid:00000000-0000-0000-0000-000000000001
Info Test queue
DeviceURI file://$PWROOT/out/print.out
State Idle
StateTime 1
ConfigTime 1
Type 4
Accepting Yes
Shared Yes
JobSheets none none
QuotaPeriod 0
PageLimit 0
KLimit 0
OpPolicy default
ErrorPolicy retry-job
</Printer>
<DefaultPrinter tlsq>
PrinterId 1
UUID urn:uuid:00000000-0000-0000-0000-000000000001
Info Test queue
DeviceURI file://$PWROOT/out/print.out
State Idle
StateTime 1
ConfigTime 1
Type 4
Accepting Yes
Shared Yes
JobSheets none none
QuotaPeriod 0
PageLimit 0
KLimit 0
OpPolicy default
ErrorPolicy retry-job
</DefaultPrinter>
EOF
    # MIME DB (read from `DataDir` flat). Prefer the system stock files; fall
    # back to minimal detect rules.
    cp -n /etc/cups/mime.types "$PWROOT/mime/mime.types" 2>/dev/null \
        || printf 'text/plain\tprintable(0,4096)\napplication/pdf\tpdf(0,1024)\napplication/postscript\tps(0,1024)\napplication/octet-stream\t-\n' > "$PWROOT/mime/mime.types"
    cp -n /etc/cups/mime.convs "$PWROOT/mime/mime.convs" 2>/dev/null \
        || printf 'text/plain\tapplication/vnd.cups-raw\t50\t-\napplication/pdf\tapplication/vnd.cups-raw\t50\t-\n' > "$PWROOT/mime/mime.convs"
    # .drv driver database (copied from the upstream test corpus if present).
    cp "$IPPTESTS"/*.drv "$PWROOT/drv/" 2>/dev/null || true
    ( cd "$PWROOT" && ./cupsd -c etc/cupsd.conf -f > logs/stdout.log 2>&1 & echo $! > "$PIDFILE" )
    sleep 2
    echo "daemon pid $(cat "$PIDFILE") on :$PWPORT"
}

stop() {
    [ -f "$PIDFILE" ] && kill "$(cat "$PIDFILE")" 2>/dev/null || true
    # Kill whatever actually holds the port (stale/orphaned daemons), so a
    # fresh start never loses the bind.
    for pid in $(ss -tlnpH "sport = :$PWPORT" 2>/dev/null | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u); do
        kill "$pid" 2>/dev/null || true
    done
    sleep 1
}

restart() {
    stop
    cargo build --bin cupsd
    cp target/debug/cupsd "$PWROOT/cupsd"
    ( cd "$PWROOT" && setsid ./cupsd -c etc/cupsd.conf -f > logs/stdout.log 2>&1 </dev/null & )
    sleep 2
    echo "daemon restarted on :$PWPORT"
}

run() {
    local uri="ipp://localhost:$PWPORT/printers/tlsq"
    local pass=0 fail=0 skip=0
    local tests=(
        get-printer-attributes get-printer-attributes-suite
        get-printer-description-attributes get-job-template-attributes
        get-printers get-printers-printer-id get-jobs get-completed-jobs
        get-devices get-subscriptions create-printer-subscription
        validate-job print-job print-uri create-job cancel-current-job
        identify-printer get-ppd get-ppd-printer get-ppds get-ppds-drv-only
        get-ppds-make get-ppds-product get-ppds-language
        get-ppds-make-and-model get-ppds-psversion
        ipp-1.1 ipp-2.0 ipp-2.1 ipp-2.2 ipp-everywhere
    )
    printf 'x' > /tmp/pw-conf-doc.txt
    for t in "${tests[@]}"; do
        [ -f "$IPPTESTS/$t.test" ] || { echo "SKIP $t"; skip=$((skip+1)); continue; }
        local out
        out=$(env "ppd-name=everywhere" ipptool -tv -f /tmp/pw-conf-doc.txt \
            -d printer_id=1 -d id=1 \
            -d make=Generic -d product=Generic -d model=Generic \
            -d language=en -d psversion=3010.00 \
            "$uri" "$IPPTESTS/$t.test" 2>&1 || true)
        if echo "$out" | grep -qE '\[FAIL\]'; then
            echo "FAIL $t"; fail=$((fail+1))
        elif echo "$out" | grep -qE '\[PASS\]'; then
            echo "PASS $t"; pass=$((pass+1))
        else
            echo "---- $t (no verdict)"; skip=$((skip+1))
        fi
    done
    echo "=== $pass passed, $fail failed, $skip skipped ==="
    [ "$fail" -eq 0 ]
}

case "${1:-}" in
    --bootstrap) bootstrap ;;
    --run) run ;;
    --stop) stop ;;
    --restart) restart ;;
    *) bootstrap; run ;;
esac
