{
  description = "GyroidOS Compartment Management Layer (CML)";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      perSystem = builtins.mapAttrs (system: pkgs':
        let
          pkgs = pkgs'.extend (final: prev: {
            ibmtss = final.callPackage ./nix/ibmtss.nix { };
            protobuf-c-text = final.callPackage ./nix/protobuf-c-text.nix { };
          });

	  lib = pkgs.lib;

          cmld = pkgs.callPackage ./nix/cml.nix { };

          cmldStarter = import ./nix/cmld-starter.nix {
	    inherit (pkgs) lib writeShellApplication;
            inherit cmld;
          };
        in
        {
          packages = rec {
            cml = cmld;
            default = cml;
          };

          apps = rec {
            cml-control = {
              type = "app";
              program = "${self.packages.${system}.cml}/sbin/cml-control";
            };

            default = cml-control;
          } // cmldStarter;
        }
      ) nixpkgs.legacyPackages;
    in
    {
      packages = builtins.mapAttrs (_: out: out.packages) perSystem;
      apps = builtins.mapAttrs (_: out: out.apps) perSystem;
    };
}
