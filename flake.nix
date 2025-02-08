{
  description = "age encryption";

  inputs = {
    nixpkgs.url      = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url  = "github:numtide/flake-utils";
    treefmt-nix.url = "github:numtide/treefmt-nix";
    zig.url = "github:mitchellh/zig-overlay";
    zls.url = "github:zigtools/zls";
  };

  outputs = { nixpkgs, zig, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
        meta = {
          description = "age encryption";
          homepage = "https://github.com/andrewkreuzer/agez";
          license = with pkgs.lib.licenses; [ mit unlicense ];
          maintainers = [{
            name = "Andrew Kreuzer";
            email = "me@andrewkreuzer.com";
            github = "andrewkreuzer";
            githubId = 17596952;
          }];
        };
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = [
            zig.packages.${system}."0.13.0"
            pkgs.age
          ];
        };
      }
    );
}
