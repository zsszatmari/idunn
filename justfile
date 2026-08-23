test-minimal:
    rustup install nightly
    cargo install cargo-hack cargo-minimal-versions --locked
    cargo minimal-versions test --direct --workspace
