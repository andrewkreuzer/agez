{
  description = "age encryption";

  inputs = {
    nixpkgs.url      = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url  = "github:numtide/flake-utils";
    treefmt-nix.url  = "github:numtide/treefmt-nix";
    zig.url          = "github:mitchellh/zig-overlay";
  };

  outputs = { nixpkgs, zig, flake-utils, ... }@inputs:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [
          (final: prev: {
            zig = inputs.zig.packages.${prev.system}."0.15.1";

            agez = prev.callPackage ./nix/package.nix {};
          })
        ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
      in rec {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            zig.packages.${system}."0.15.1"
            age
            rage
            lldb
            gdb
          ];
        };

        packages.agez = pkgs.agez;
        defaultPackage = packages.agez;
      }
    );
}
