{
  inputs = {
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
    nixpkgs.url = "nixpkgs/nixos-unstable";
  };

  outputs = { self, fenix, flake-utils, nixpkgs }:
    flake-utils.lib.eachDefaultSystem (system:
      let pkgs = nixpkgs.legacyPackages.${system}; in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = with fenix.packages.${system}.stable; [
            cargo
            rustc
            clippy
            rustfmt
            rust-analyzer
            rust-src
          ] ++ (with pkgs;[
            docker-compose
          ]);
        };

        defaultPackage = (pkgs.makeRustPlatform {
          inherit (fenix.packages.${system}.stable.minimal) cargo rustc;
        }).buildRustPackage {
          pname = "redproxy-rs";
          version = "0.10.0";
          src = ./.;
          #cargoSha256 = "sha256-zvG0eT5xH/uk6jrxIDXV37i9nB24kVovwCsKrsBxFsk=";
          cargoLock = {
            lockFile = ./Cargo.lock;
          };
        };
      }
    );
}
