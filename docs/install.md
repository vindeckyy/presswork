# Installing yindle

All paths land the same thing: a drop-in `cupsd` on port 631 plus the
IPP helpers, backends, configs, and spool layout CUPS 2.x clients
expect.

## One-command install (x86_64 Linux)

```sh
curl -fsSL https://raw.githubusercontent.com/vindeckyy/yindle/main/install.sh | sh
```

Resolves the latest release, verifies SHA256SUMS, lands the FHS tree
(`/usr/sbin/cupsd`, `/usr/lib/cups/{daemon,backend}`, `/etc/cups`,
`/var/{spool,log,cache}/cups`), creates `lp`/`lpadmin`, and enables
systemd socket activation. Flags: `--no-start`, `--version X`,
`--from DIR`, `--force`.

## Container (zero-touch eval)

```sh
docker run -d -p 631:631 \
  -v cups-etc:/etc/cups -v cups-spool:/var/spool/cups \
  ghcr.io/vindeckyy/yindle:latest
```

or `docker compose up` with `docker-compose.yml`. Nothing is installed
on the host; remove the container and volumes to uninstall.

## Debian / Ubuntu package

```sh
sudo dpkg -i yindle_0.1.0-1_amd64.deb
```

from the
[releases page](https://github.com/vindeckyy/yindle/releases).
Declares `Provides: cups` / `Conflicts: cups,cups-daemon`; postinst
creates the lp user and enables the units.

## Homebrew on Linux

```sh
brew install vindeckyy/tap/yindle && brew services start yindle
```

User-space eval on port 8631 with configs under the brew prefix -
coexists with a system CUPS.

## Manual tarball

Untar `yindle-0.1.0-x86_64-unknown-linux-gnu.tar.gz`, run
`./install.sh` inside (or copy the tree by hand), then
`systemctl enable --now cups.socket cups.path`.

## From source

```sh
cargo build --workspace --release
sudo make install
sudo systemctl enable --now cups.socket cups.path
```

## Other channels

- **Arch / AUR**: `packaging/aur-bin/` is a ready `yindle-bin`
  package; `packaging/arch/PKGBUILD` builds from source.
- **Nix**: `packaging/nix/package.nix`; submission pending as
  NixOS/nixpkgs#587503.
- **crates.io**: `ipp-codec`, `yindle-sys`, `backend-common`,
  `cups-tls`, `cups-log`, `cups-config` publish via
  `.github/workflows/publish.yml` on release.

## Verify

```sh
lpstat -t
lpadmin -p test -E -v ipp://<printer> -m everywhere
lp -d test /etc/hostname
```

See [migration.md](migration.md) for swapping a stock cupsd in place,
and [conformance.md](conformance.md) for the compatibility report.
