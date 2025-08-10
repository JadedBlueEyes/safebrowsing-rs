{
  inputs = {
    naersk.url = "github:nix-community/naersk/master";
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, utils, naersk }:
    utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        naersk-lib = pkgs.callPackage naersk { };
        buildInputs = with pkgs; [
          protobuf
        ];
        nativeBuildInputs = with pkgs; [
          # openssl setup
          openssl
          pkg-config
        ];
      in
      {
        defaultPackage = naersk-lib.buildPackage {
          src = ./.;

          buildInputs = buildInputs;
          nativeBuildInputs = nativeBuildInputs;
        };
        devShell = with pkgs; mkShell {
          buildInputs = [
            cargo
            rustc
            rustfmt
            pre-commit
            rustPackages.clippy
          ] ++ buildInputs;

          nativeBuildInputs = nativeBuildInputs;

          RUST_SRC_PATH = rustPlatform.rustLibSrc;
        };
      }
    );
}
