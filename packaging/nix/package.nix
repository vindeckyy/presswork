{ lib
, rustPlatform
, fetchFromGitHub
, avahi
, pkg-config
}:

rustPlatform.buildRustPackage rec {
  pname = "presswork";
  version = "0.1.0";

  src = ./../..;

  cargoLock = {
    lockFile = ./../../Cargo.lock;
  };

  nativeBuildInputs = [ pkg-config ];
  buildInputs = [ avahi ];

  # Unit tests only — the ipptool conformance suite needs a live daemon.
  checkFlags = [ "--workspace" ];

  postInstall = ''
    make install DESTDIR=$out PROFILE=release USER=lp GROUP=lp \
      SYSCONFDIR=/etc/cups SPOOLDIR=/var/spool/cups LOGDIR=/var/log/cups \
      CACHEDIR=/var/cache/cups RUNDIR=/run/cups
  '';

  meta = with lib; {
    description = "Memory-safe CUPS-compatible print spooler and IPP scheduler in Rust";
    homepage = "https://example.invalid/presswork";
    license = with licenses; [ mit asl20 ];
    platforms = platforms.linux;
    mainProgram = "cupsd";
  };
}
