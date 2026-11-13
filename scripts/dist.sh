#!/bin/sh
# dist.sh — build release artifacts into ./dist:
#   presswork-$VER-$TARGET.tar.gz   FHS tree + install.sh
#   presswork_${VER}-1_amd64.deb    Debian package (dpkg-deb)
#   SHA256SUMS
# Run from the repo root. Used by release.yml; safe to run locally.
set -eu

command -v cargo >/dev/null 2>&1 || PATH="$HOME/.cargo/bin:$PATH"

VER=${1:-$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)}
TARGET=$(rustc -vV | sed -n 's/^host: //p')
STAGE=dist/stage
PKG=presswork-$VER-$TARGET

rm -rf dist
mkdir -p "$STAGE"

cargo build --workspace --release --locked

# Stage the FHS tree as the build user (install -o fails without root);
# archives are normalized to root:root below and install.sh / the deb
# postinst chowns mutable state to lp at install time.
make install DESTDIR="$STAGE" PROFILE=release \
    USER="$(id -un)" GROUP="$(id -gn)" >/dev/null
install -m 0755 install.sh "$STAGE/install.sh"
install -m 0644 README.md LICENSE* "$STAGE/" 2>/dev/null || true

# ---- tarball --------------------------------------------------------------
mv "$STAGE" "dist/presswork-$VER"
tar -C dist --owner=0 --group=0 --numeric-owner \
    -czf "dist/$PKG.tar.gz" "presswork-$VER"
mv "dist/presswork-$VER" "$STAGE"

# ---- deb ------------------------------------------------------------------
DEB="$STAGE/DEBIAN"
mkdir -p "$DEB"
cat > "$DEB/control" <<EOF
Package: presswork
Version: $VER-1
Section: net
Priority: optional
Architecture: amd64
Maintainer: presswork contributors <presswork@localhost>
Depends: adduser
Provides: cups
Conflicts: cups, cups-daemon
Replaces: cups-daemon
Description: memory-safe CUPS-compatible print spooler and IPP scheduler
 A Rust reimplementation of the CUPS 2.x scheduler: cupsd, helper
 daemons, and the standard backends, speaking the same IPP on the same
 sockets and reading /etc/cups in place.
EOF

sed 's/#DEBHELPER#//' packaging/debian/presswork.postinst > "$DEB/postinst"
cat >> "$DEB/postinst" <<'EOF'

case "$1" in
    configure)
        if command -v systemctl >/dev/null 2>&1; then
            systemctl daemon-reload || true
            systemctl enable cups.socket cups.path 2>/dev/null || true
        fi
        ;;
esac
EOF
chmod 0755 "$DEB/postinst"

cat > "$DEB/prerm" <<'EOF'
#!/bin/sh
set -e
if command -v systemctl >/dev/null 2>&1; then
    systemctl stop cups.path cups.socket cups.service cups-lpd.socket 2>/dev/null || true
    systemctl disable cups.socket cups.path 2>/dev/null || true
fi
exit 0
EOF
chmod 0755 "$DEB/prerm"

dpkg-deb --root-owner-group --build "$STAGE" "dist/presswork_${VER}-1_amd64.deb" >/dev/null

# ---- checksums -------------------------------------------------------------
(cd dist && sha256sum "$PKG.tar.gz" "presswork_${VER}-1_amd64.deb" > SHA256SUMS)

ls -l dist/
