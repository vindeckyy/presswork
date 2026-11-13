# nixpkgs-ready derivation for presswork.
#
# Before submitting upstream (pkgs/by-name/pr/presswork/package.nix):
#   1. replace both lib.fakeHash placeholders - the first build failure
#      prints the real hash for each.
#   2. keep `meta.homepage` and `meta.changelog` pointing at the repo.
{ lib
, rustPlatform
, fetchFromGitHub
, avahi
, pkg-config
}:

rustPlatform.buildRustPackage rec {
  pname = "presswork";
  version = "0.1.0";

  src = fetchFromGitHub {
    owner = "vindeckyy";
    repo = "presswork";
    rev = "v${version}";
    hash = lib.fakeHash; # prefetch: nix-prefetch-github vindeckyy presswork --rev v0.1.0
  };

  cargoHash = lib.fakeHash; # printed by the first build attempt

  nativeBuildInputs = [ pkg-config ];
  buildInputs = [ avahi ];

  # The ipptool conformance suite needs a live daemon; run unit tests only.
  checkFlags = [ "--workspace" ];

  postInstall = ''
    make install DESTDIR=$out PROFILE=release USER=lp GROUP=lp \
      SYSCONFDIR=/etc/cups SPOOLDIR=/var/spool/cups LOGDIR=/var/log/cups \
      CACHEDIR=/var/cache/cups RUNDIR=/run/cups
  '';

  meta = with lib; {
    description = "Memory-safe CUPS 2.x-compatible print spooler and IPP scheduler in Rust";
    longDescription = ''
      presswork is a drop-in replacement for the CUPS scheduler (cupsd):
      the same IPP wire protocol, config files, spool layout, and
      filter/backend contracts, implemented in Rust with unsafe code
      confined to a single audited FFI crate.
    '';
    homepage = "https://github.com/vindeckyy/presswork";
    changelog = "https://github.com/vindeckyy/presswork/blob/main/CHANGELOG.md";
    license = with licenses; [ mit asl20 ];
    platforms = platforms.linux;
    mainProgram = "cupsd";
    maintainers = [ ];
  };
}
