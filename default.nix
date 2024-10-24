{ pkgs ? <nixpkgs> { }
, stdenv ? pkgs.stdenv
# A set providing `buildRustPackage :: attrsets -> derivation`
, rustPlatform ? pkgs.rustPlatform
}:

stdenv.mkDerivation {
  pname = "gkey";
  version = "0.1.0";

  src = ./.;

  cargoDeps = rustPlatform.importCargoLock {
    lockFile = ./Cargo.lock;
  };

  buildInputs = with pkgs;[
    gtk4
    glib
  ];


  nativeBuildInputs = [ 
    pkgs.pkg-config
    rustPlatform.cargoSetupHook
    pkgs.rustc
    pkgs.cargo
    pkgs.autoconf
  ];

  configurePhase = ''
    autoconf
    ./configure
  '';
  makeFlags = [ "prefix=${placeholder "out"}" ];


  meta = with pkgs; {
    homepage = "https://github.com/Krishap-s/gkey";
    description = "An On Device Fido Platform Authenticator For The GNU Project ";
    license = lib.licenses.gpl3;
  };
}
