{
  inputs = {
    naersk.url = "github:nix-community/naersk/master";
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    utils.url = "github:numtide/flake-utils";
    nixpkgs-mozilla = {
      url = "github:mozilla/nixpkgs-mozilla";
      flake = false;
    };
  };

  outputs = {
    self,
    nixpkgs,
    utils,
    naersk,
    nixpkgs-mozilla,
  }:
    utils.lib.eachDefaultSystem (
      system: let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [(import nixpkgs-mozilla)];
        };
        toolchain =
          (pkgs.rustChannelOf {
            rustToolchain = ./rust-toolchain.toml;
            sha256 = "sha256-+9FmLhAOezBZCOziO0Qct1NOrfpjNsXxc/8I0c7BdKE="; # Update on toolchain change
          }).rust;
        naersk-lib = pkgs.callPackage naersk {
          cargo = toolchain;
          rustc = toolchain;
        };
        buildInputs = with pkgs; [
          protobuf
          toolchain
        ];
        nativeBuildInputs = with pkgs; [
          openssl
          pkg-config
        ];
      in {
        defaultPackage = naersk-lib.buildPackage {
          src = ./.;
          buildInputs = buildInputs;
          nativeBuildInputs = nativeBuildInputs;
        };
        devShell = pkgs.mkShell {
          buildInputs = buildInputs;
          nativeBuildInputs = nativeBuildInputs;
          RUST_SRC_PATH = pkgs.rustPlatform.rustLibSrc;
        };
      }
    );
}
