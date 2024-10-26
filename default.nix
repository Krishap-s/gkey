{ pkgs ? <nixpkgs> { }
, stdenv ? pkgs.stdenv
# A set providing `buildRustPackage :: attrsets -> derivation`
}:
let 
  rustPlatform =  pkgs.makeRustPlatform {
    rustc = pkgs.rust-bin.stable.latest.default;
    cargo = pkgs.rust-bin.stable.latest.default;
  };
in
stdenv.mkDerivation {
  pname = "gkey";
  version = "0.1.0";

  src = ./.;

  cargoDeps = rustPlatform.importCargoLock {
    lockFile = ./Cargo.lock;
  };

  env = {
    LOCALE_ARCHIVE= "${pkgs.glibcLocales}/lib/locale/locale-archive";
  };  

  buildInputs = with pkgs;[
    gtk4
    glib
  ];


  nativeBuildInputs = [ 
    pkgs.pkg-config
    rustPlatform.cargoSetupHook
    rustPlatform.bindgenHook
    pkgs.cargo
    pkgs.autoconf
  ];

  configurePhase = ''
    autoconf
    ./configure --prefix=$out
  '';


  meta = with pkgs; {
    homepage = "https://github.com/Krishap-s/gkey";
    description = "An On Device Fido Platform Authenticator For The GNU Project ";
    license = lib.licenses.gpl3;
  };
}
