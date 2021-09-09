with import <nixpkgs> {};
mkShell {
  nativeBuildInputs = [
    bashInteractive
    rustc
    cargo
  ];
}
