# AUR submission: yindle-bin

This directory is a ready-to-push AUR package repo. `yindle-bin`
installs the CI-built release tarball; `yindle` (source build) uses
`packaging/arch/PKGBUILD` instead.

## Submitting (needs an AUR account + SSH key)

```sh
# 1. clone the empty AUR repo for the package name
git clone ssh://aur@aur.archlinux.org/yindle-bin.git aur-yindle-bin
cd aur-yindle-bin

# 2. copy these files in, then generate .SRCINFO and sums
cp /path/to/yindle/packaging/aur-bin/* .
updpkgsums          # fills sha256sums for the two aux files
makepkg --printsrcinfo > .SRCINFO
makepkg -si         # sanity check: installs yindle locally

# 3. push
git add -A && git commit -m "yindle-bin 0.1.0-1" && git push
```

## Per-release maintenance

Bump `pkgver`, refresh the release-tarball hash from the release page
(`SHA256SUMS` asset), `updpkgsums`, regenerate `.SRCINFO`, push.

The aux files mirror `packaging/arch/yindle.{sysusers,tmpfiles}`;
keep them in sync if the runtime user/dirs ever change.
