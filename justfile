test-minimal-versions:
    rustup install nightly
    cargo minimal-versions test --direct --workspace

check-features:
    cargo hack check --workspace --each-feature --no-dev-deps --keep-going

check-powerset:
    cargo hack check --workspace --feature-powerset --depth 2 --no-dev-deps --keep-going

check-powerset-full:
    cargo hack check --workspace --feature-powerset --no-dev-deps --keep-going

test-features:
    cargo hack test --workspace --each-feature --keep-going

# Lint all targets and features, failing on any warning (the invocation CI runs).
clippy:
    cargo clippy --workspace --all-targets --all-features -- -D warnings

check-all: check-powerset test-features test-minimal-versions

# Local HTML coverage report, opened in the browser.
coverage: cargo-deny cooldown
    @rustup run nightly true 2>/dev/null \
      || { echo "error: nightly toolchain missing (needed for coverage(off)); install with 'rustup toolchain install nightly --component llvm-tools'"; exit 1; }
    cargo +nightly llvm-cov --branch --html

# Machine-readable coverage plus a line-coverage gate, for CI.
# Region coverage is deliberately NOT gated: matches!, assert!, ? and derives
# leave never-taken regions even in fully exercised code.
coverage-ci min="90":
    @rustup run nightly true 2>/dev/null \
      || { echo "error: nightly toolchain missing (needed for coverage(off)); install with 'rustup toolchain install nightly --component llvm-tools'"; exit 1; }
    cargo +nightly llvm-cov --branch --lcov --output-path lcov.info --fail-under-lines {{ min }}

cargo-deny:
    cargo deny check

cooldown:
    cargo cooldown


# TODO: look into cargo-mutants
