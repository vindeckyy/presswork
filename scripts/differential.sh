#!/usr/bin/env bash
# differential.sh — run the same upstream ipptool matrix against stock
# /usr/sbin/cupsd and presswork cupsd, then diff the per-test verdicts.
#
# The gate: any test that PASSES on stock cupsd but FAILS (or vice-versa)
# on presswork is a semantic-parity gap to fix, not an ipptool artifact.
#
#   --stock    run the matrix against a scratch stock cupsd (port 8641)
#   --ours     run the matrix against presswork via conformance.sh (8631)
#   (no args)  run both and print the verdict diff
#
# Env: DIFFROOT (stock scratch root, /tmp/pw-diff), DIFFPORT (8641),
# IPPTESTS / TESTDIR as in conformance.sh.

set -euo pipefail
cd "$(dirname "$0")/.."

DIFFROOT="${DIFFROOT:-/tmp/pw-diff}"
DIFFPORT="${DIFFPORT:-8641}"
IPPTESTS="${IPPTESTS:-/tmp/cups-ref/examples}"
TESTDIR="${TESTDIR:-$IPPTESTS/../test}"
STOCK_BIN="${STOCK_BIN:-/usr/sbin/cupsd}"

verdict() {
    local name="$1" uri="$2" file="$3" out
    out=$(env "ppd-name=everywhere" ipptool -tv -f /tmp/pw-diff-doc.txt \
        -d printer_id=1 -d id=1 \
        -d make=Generic -d product=Generic -d model=Generic \
        -d language=en -d psversion=3010.00 \
        "$uri" "$file" 2>&1 || true)
    if grep -qE '\[FAIL\]' <<<"$out"; then
        printf '%s\n' "$out" > "/tmp/diff-fail-$(printf '%s' "$name" | tr '/.' '__').log"
        echo "FAIL $name"
    elif grep -qE '\[PASS\]' <<<"$out"; then
        echo "PASS $name"
    else
        echo "---- $name"
    fi
}

matrix() {
    # $1 = base URI (ipp://host:port/printers/tlsq), $2 = socket root URI
    printf 'x' > /tmp/pw-diff-doc.txt
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
    for t in "${tests[@]}"; do
        [ -f "$IPPTESTS/$t.test" ] || { echo "MISS examples/$t"; continue; }
        verdict "examples/$t" "$1" "$IPPTESTS/$t.test"
    done
    for t in 4.1-requests 4.2-cups-printer-ops 4.3-job-ops 4.4-subscription-ops; do
        [ -f "$TESTDIR/$t.test" ] || { echo "MISS test/$t"; continue; }
        verdict "test/$t" "$2" "$TESTDIR/$t.test"
    done
}

start_stock() {
    rm -rf "$DIFFROOT"
    mkdir -p "$DIFFROOT"/{etc,spool,run,cache,logs,out,docroot,tmp,ppd,bin/{notifier,daemon,backend}}
    # Notifier stubs — upstream's harness ships a `testnotify` binary in
    # bin/notifier; cupsd rejects subscription URIs whose scheme has no
    # notifier executable (4.2's "Subscribe to Printer Events").
    printf '#!/bin/sh\nexit 0\n' > "$DIFFROOT/bin/notifier/testnotify"
    chmod +x "$DIFFROOT/bin/notifier/testnotify"
    # Upstream test .drv corpus so CUPS-Get-PPDs sees real drivers.
    cp "$IPPTESTS"/*.drv "$DIFFROOT/" 2>/dev/null || true
    cat > "$DIFFROOT/etc/cups-files.conf" <<EOF
ServerRoot $DIFFROOT/etc
RequestRoot $DIFFROOT/spool
CacheDir $DIFFROOT/cache
DocumentRoot $DIFFROOT/docroot
DataDir /usr/share/cups
TempDir $DIFFROOT/tmp
ErrorLog $DIFFROOT/logs/error_log
AccessLog $DIFFROOT/logs/access_log
PageLog $DIFFROOT/logs/page_log
FileDevice Yes
ServerBin $DIFFROOT/bin
EOF
    cat > "$DIFFROOT/etc/cupsd.conf" <<EOF
Listen localhost:$DIFFPORT
Listen $DIFFROOT/run/cups.sock
DefaultShared yes
MaxSubscriptions 3
Sandboxing Relaxed
<Policy default>
<Limit All>
Order Allow,Deny
</Limit>
</Policy>
EOF
    cat > "$DIFFROOT/etc/printers.conf" <<EOF
<Printer tlsq>
PrinterId 1
UUID urn:uuid:00000000-0000-0000-0000-000000000001
Info Test queue
DeviceURI file://$DIFFROOT/out/print.out
State Idle
Accepting Yes
Shared Yes
JobSheets none none
</Printer>
EOF
    ( cd "$DIFFROOT" && setsid "$STOCK_BIN" -f -c etc/cupsd.conf > logs/stdout.log 2>&1 </dev/null & )
    sleep 3
    # Give the fixture queue a real driver PPD — upstream's tests EXPECT
    # media-col-default etc., which raw queues don't synthesize.
    CUPS_SERVER="localhost:$DIFFPORT" lpadmin -p tlsq -E \
        -v "file://$DIFFROOT/out/print.out" -m drv:///sample.drv >/dev/null 2>&1 || true
}

stop_stock() {
    for pid in /proc/[0-9]*/cwd; do
        pid="${pid%/cwd}"; pid="${pid#/proc/}"
        [ "$(readlink "/proc/$pid/cwd" 2>/dev/null)" = "$DIFFROOT" ] || continue
        case "$(readlink "/proc/$pid/exe" 2>/dev/null)" in
            *cupsd*) kill "$pid" 2>/dev/null || true ;;
        esac
    done
    for pid in $(ss -tlnpH "sport = :$DIFFPORT" 2>/dev/null | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u); do
        kill "$pid" 2>/dev/null || true
    done
    rm -f "$DIFFROOT/run/cups.sock"
}

stock() {
    stop_stock || true
    start_stock
    # Upstream runs the numbered 4.x tier over TCP /printers with an
    # all-allow policy (run-stp-tests.sh:730) — mirror that here.
    matrix "ipp://localhost:$DIFFPORT/printers/tlsq" \
           "ipp://localhost:$DIFFPORT/printers"
    stop_stock
}

ours() {
    PWROOT=/tmp/pw-diff-ours PWPORT=8643 \
        ./scripts/conformance.sh --bootstrap >/dev/null
    PWROOT=/tmp/pw-diff-ours PWPORT=8643 \
        ./scripts/conformance.sh --run 2>&1 | grep -E "^(PASS|FAIL|----|SKIP)" \
        | sed 's/SKIP /---- /;s/ (.*//'
    PWROOT=/tmp/pw-diff-ours PWPORT=8643 ./scripts/conformance.sh --stop >/dev/null 2>&1 || true
}

case "${1:-all}" in
    --stock) stock ;;
    --ours)  ours ;;
    *)
        echo "== stock cupsd =="; stock | tee /tmp/diff-stock.txt
        echo "== presswork ==";  ours  | tee /tmp/diff-ours.txt
        echo "== verdict diff (< stock, > presswork) =="
        diff /tmp/diff-stock.txt /tmp/diff-ours.txt || true
        ;;
esac
