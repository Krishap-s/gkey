{ pkgs ? import <nixpkgs> { }
, stdenv ? pkgs.stdenv
# A set providing `buildRustPackage :: attrsets -> derivation`
, rustPlatform ? pkgs.rustPlatform
}:

rustPlatform.buildRustPackage rec {
  pname = "gkey";
  version = "0.0.1";
  src = ./.;
  cargoLock.lockFile = ./Cargo.lock;
  nativeBuildInputs = [ pkgs.pkg-config ];
  buildInputs = with pkgs;[
    gtk4
    glib
  ];
  meta = with stdenv.lib; {
    homepage = "";
    description = "Sample flake repository for a Rust application";
    license = licenses.gplv2;
  };
}
