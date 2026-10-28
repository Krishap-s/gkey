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

  buildInputs = with pkgs; [
    tpm2-tss
  ];


  nativeBuildInputs = [ 
    pkgs.pkg-config
    rustPlatform.cargoSetupHook
    pkgs.autoconf
    pkgs.texinfo
    pkgs.cargo
    pkgs.rustc
  ];

  configurePhase = ''
    autoconf
    ./configure --prefix=$out --localstatedir=/var
  '';

  postBuild = ''
    make info
  '';


  meta = with pkgs; {
    homepage = "https://github.com/Krishap-s/gkey";
    description = "A TPM backed FIDO2 passkey authenticator";
    license = lib.licenses.gpl3Plus;
    platforms = lib.platforms.linux;
  };
}
