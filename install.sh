#!/bin/sh
# yindle one-command installer.
#
#   curl -fsSL https://raw.githubusercontent.com/vindeckyy/yindle/main/install.sh | sh
#
# Options: --no-start  install but leave the daemon stopped
#          --version X install a specific release (default: latest)
#          --from DIR install an already-unpacked release tree
#          --force    proceed even if another cupsd is installed
#
# Run standalone it downloads the matching release tarball, verifies its
# SHA256SUMS entry, lands the upstream FHS layout, creates the lp/lpadmin
# accounts, and enables socket activation (cups.socket + cups.path).
set -eu

REPO=vindeckyy/yindle

START=1 VERSION="" SRC="" FORCE=0
while [ $# -gt 0 ]; do
    case "$1" in
        --no-start) START=0 ;;
        --force)    FORCE=1 ;;
        --version)  VERSION=$2; shift ;;
        --from)     SRC=$2; shift ;;
        -h|--help)
            sed -n '3,11p' "$0" 2>/dev/null || true
            exit 0 ;;
        *) echo "install.sh: unknown option $1" >&2; exit 2 ;;
    esac
    shift
done

die() { echo "install.sh: $*" >&2; exit 1; }

fetch() {  # url dest
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$1" -o "$2"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$2" "$1"
    else
        die "need curl or wget"
    fi
}

SUDO=""
if [ "$(id -u)" != 0 ]; then
    command -v sudo >/dev/null 2>&1 || die "run as root or install sudo"
    SUDO=sudo
fi

# Refuse to silently overwrite a distro-managed cupsd.
if [ "$FORCE" = 0 ] && [ -x /usr/sbin/cupsd ] && [ ! -f /usr/share/doc/yindle/README.md ]; then
    cat >&2 <<'EOF'
install.sh: an existing /usr/sbin/cupsd was found.
  On Debian/Ubuntu remove it first (apt remove cups-daemon; keep
  cups-client for the lp* tools) or install the .deb instead.
  Re-run with --force to overwrite anyway.
EOF
    exit 1
fi

# ---- obtain the release tree ----------------------------------------------
TMP=""
if [ -z "$SRC" ]; then
    if [ -d usr ] && [ -x usr/sbin/cupsd ]; then
        SRC=.
    else
        arch=$(uname -m)
        [ "$arch" = "x86_64" ] || die "no prebuilt package for $arch yet; build from source (see README)"
        TARGET=$arch-unknown-linux-gnu

        if [ -z "$VERSION" ]; then
            TMP=$(mktemp -d)
            fetch "https://api.github.com/repos/$REPO/releases/latest" "$TMP/latest.json"
            VERSION=$(sed -n 's/.*"tag_name": *"v\{0,1\}\([^"]*\)".*/\1/p' "$TMP/latest.json" | head -1)
            [ -n "$VERSION" ] || die "could not determine latest release"
        else
            TMP=$(mktemp -d)
        fi

        PKG=yindle-$VERSION-$TARGET
        BASE=https://github.com/$REPO/releases/download/v$VERSION
        echo "install.sh: fetching $PKG"
        fetch "$BASE/$PKG.tar.gz" "$TMP/$PKG.tar.gz"
        if fetch "$BASE/SHA256SUMS" "$TMP/SHA256SUMS" 2>/dev/null && command -v sha256sum >/dev/null 2>&1; then
            ( cd "$TMP" && grep " $PKG.tar.gz\$" SHA256SUMS | sha256sum -c - ) \
                || die "checksum verification failed"
        else
            echo "install.sh: warning: could not verify checksum" >&2
        fi
        tar -C "$TMP" -xzf "$TMP/$PKG.tar.gz"
        SRC=$TMP/yindle-$VERSION
    fi
fi
trap '[ -n "$TMP" ] && rm -rf "$TMP"' EXIT

[ -x "$SRC/usr/sbin/cupsd" ] || die "$SRC does not look like a yindle release tree"

# ---- accounts ---------------------------------------------------------------
getent group lp >/dev/null 2>&1 || $SUDO groupadd -r lp
id lp >/dev/null 2>&1 || $SUDO useradd -r -g lp -d /var/spool/cups -s /usr/sbin/nologin lp
getent group lpadmin >/dev/null 2>&1 || $SUDO groupadd -r lpadmin
$SUDO usermod -aG lpadmin lp 2>/dev/null || true

# ---- file tree --------------------------------------------------------------
$SUDO cp -a "$SRC/usr/." /usr/
$SUDO cp -a "$SRC/etc/." /etc/
[ -d "$SRC/var" ] && $SUDO cp -a "$SRC/var/." /var/
$SUDO chown -R lp:lp /var/spool/cups /var/log/cups /var/cache/cups 2>/dev/null || true
$SUDO chmod 0700 /etc/cups/ssl 2>/dev/null || true

# ---- activation -------------------------------------------------------------
if command -v systemctl >/dev/null 2>&1; then
    $SUDO systemctl daemon-reload || true
    $SUDO systemctl enable cups.socket cups.path 2>/dev/null || true
    if [ "$START" = 1 ]; then
        $SUDO systemctl restart cups.socket cups.path 2>/dev/null || true
        $SUDO systemctl start cups.service 2>/dev/null || true
    fi
fi

echo "yindle ${VERSION:-release} installed."
echo "  status:    systemctl status cups.socket cups.service"
echo "  add queue: lpadmin -p <name> -E -v <uri> -m everywhere"
echo "  verify:    lpstat -t"
