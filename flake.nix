{
  description = "A very basic flake";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-darwin" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      perSystem = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          shellPackages = [
            pkgs.nodejs_22
            pkgs.go
          ];
        in {
          packages = {
            hello = pkgs.hello;
            default = pkgs.hello;
          };
          devShells = {
            default = pkgs.mkShell {
              packages = shellPackages;
            };
          };
        }
      );
    in {
      packages = nixpkgs.lib.mapAttrs (_: v: v.packages) perSystem;
      devShells = nixpkgs.lib.mapAttrs (_: v: v.devShells) perSystem;
    };
}
