#!/bin/sh
# presswork installer — run as root from inside the unpacked release tarball:
#   tar xzf presswork-<ver>-<target>.tar.gz && cd presswork-<ver> && sudo ./install.sh
#
# Copies the FHS tree onto /, creates the lp/lpadmin accounts, reloads
# systemd, and enables socket activation (cups.socket + cups.path).
# Pass --no-start to leave the daemon stopped after install.
set -eu

START=1
[ "${1:-}" = "--no-start" ] && START=0

[ "$(id -u)" = 0 ] || { echo "install.sh: run as root" >&2; exit 1; }
[ -d usr ] || { echo "install.sh: run from the unpacked release directory" >&2; exit 1; }

# Accounts (mirrors the deb postinst / upstream cups-daemon).
getent group lp >/dev/null 2>&1 || groupadd -r lp
id lp >/dev/null 2>&1 || useradd -r -g lp -d /var/spool/cups -s /usr/sbin/nologin lp
getent group lpadmin >/dev/null 2>&1 || groupadd -r lpadmin
usermod -aG lpadmin lp 2>/dev/null || true

# File tree.
cp -a usr/. /usr/
cp -a etc/. /etc/
[ -d var ] && cp -a var/. /var/
chown -R lp:lp /var/spool/cups /var/log/cups /var/cache/cups 2>/dev/null || true
chmod 0700 /etc/cups/ssl 2>/dev/null || true

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
    systemctl enable cups.socket cups.path 2>/dev/null || true
    if [ "$START" = 1 ]; then
        systemctl restart cups.socket cups.path 2>/dev/null || true
        systemctl start cups.service 2>/dev/null || true
    fi
fi

echo "presswork installed."
echo "  status:    systemctl status cups.socket cups.service"
echo "  add queue: lpadmin -p <name> -E -v <uri> -m everywhere"
echo "  verify:    lpstat -t"
