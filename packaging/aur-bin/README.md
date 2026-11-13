# AUR submission: presswork-bin

This directory is a ready-to-push AUR package repo. `presswork-bin`
installs the CI-built release tarball; `presswork` (source build) uses
`packaging/arch/PKGBUILD` instead.

## Submitting (needs an AUR account + SSH key)

```sh
# 1. clone the empty AUR repo for the package name
git clone ssh://aur@aur.archlinux.org/presswork-bin.git aur-presswork-bin
cd aur-presswork-bin

# 2. copy these files in, then generate .SRCINFO and sums
cp /path/to/presswork/packaging/aur-bin/* .
updpkgsums          # fills sha256sums for the two aux files
makepkg --printsrcinfo > .SRCINFO
makepkg -si         # sanity check: installs presswork locally

# 3. push
git add -A && git commit -m "presswork-bin 0.1.0-1" && git push
```

## Per-release maintenance

Bump `pkgver`, refresh the release-tarball hash from the release page
(`SHA256SUMS` asset), `updpkgsums`, regenerate `.SRCINFO`, push.

The aux files mirror `packaging/arch/presswork.{sysusers,tmpfiles}`;
keep them in sync if the runtime user/dirs ever change.
