{
  description = "Reticulum in Haskell";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forEach = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});

      compiler = "ghc984";
    in
    {
      packages = forEach (pkgs: {
        default = pkgs.haskell.packages.${compiler}.callCabal2nix "reticulum" ./. { };
      });

      devShells = forEach (pkgs:
        let
          hp = pkgs.haskell.packages.${compiler};
          ghc = hp.ghcWithPackages (p: [ p.bytestring p.containers p.crypton ]);
        in
        {
          default = pkgs.mkShell {
            packages = [
              ghc
              hp.cabal-install

              pkgs.git
              pkgs.gcc
              pkgs.gnumake
              pkgs.coreutils
              pkgs.diffutils
              pkgs.findutils
              pkgs.gawk
              pkgs.gnused
            ];

            shellHook = ''
              {
                echo 'cabal build   build the library and the node'
                echo './check       run the corpus against the harness'
              } >&2
            '';
          };
        });
    };
}
