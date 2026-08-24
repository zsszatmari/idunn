[private]
tools:
    @command -v cargo-hack >/dev/null || cargo install cargo-hack --locked
    @command -v cargo-minimal-versions >/dev/null || cargo install cargo-minimal-versions --locked

test-minimal-versions: tools
    rustup install nightly
    cargo minimal-versions test --direct --workspace

check-features: tools
    cargo hack check --workspace --each-feature --no-dev-deps --keep-going

check-powerset: tools
    cargo hack check --workspace --feature-powerset --depth 2 --no-dev-deps --keep-going

check-powerset-full: tools
    cargo hack check --workspace --feature-powerset --no-dev-deps --keep-going

test-features: tools
    cargo hack test --workspace --each-feature --keep-going

check-all: check-powerset test-features test-minimal-versions
