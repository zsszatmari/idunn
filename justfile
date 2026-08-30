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

# Lint all targets and features, failing on any warning (the invocation CI runs).
clippy:
    cargo clippy --workspace --all-targets --all-features

check-all: check-powerset test-features test-minimal-versions

[private]
coverage-tools:
    rustup toolchain install nightly --component llvm-tools

# Local HTML coverage report, opened in the browser.
coverage: coverage-tools
    cargo +nightly llvm-cov --html --open

# Machine-readable coverage plus a line-coverage gate, for CI.
# Region coverage is deliberately NOT gated: matches!, assert!, ? and derives
# leave never-taken regions even in fully exercised code.
coverage-ci min="80": coverage-tools
    cargo +nightly llvm-cov --lcov --output-path lcov.info --fail-under-lines {{ min }}

cargo-deny:
    cargo deny check
