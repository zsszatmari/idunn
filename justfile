test-minimal-versions:
    rustup install nightly
    cargo minimal-versions test --direct --workspace

# aws_lc_rs/rust_crypto are mutually exclusive and one of them is required (see the
# compile_error! in lib.rs); the four recipes below all pass
# --mutually-exclusive-features/--at-least-one-of to cargo-hack so they skip the
# zero- or two-backend combinations, which the guard rejects.

# test-fixtures/tokio-refresh don't get a standalone run here: a standalone run also
# needs a backend. check-powerset-full's full powerset still covers them.
# Each crypto backend compiles in isolation.
check-features:
    cargo hack check --workspace --feature-powerset --depth 1 --no-dev-deps --keep-going --mutually-exclusive-features aws_lc_rs,rust_crypto --at-least-one-of aws_lc_rs,rust_crypto

check-powerset:
    cargo hack check --workspace --feature-powerset --depth 2 --no-dev-deps --keep-going --mutually-exclusive-features aws_lc_rs,rust_crypto --at-least-one-of aws_lc_rs,rust_crypto

check-powerset-full:
    cargo hack check --workspace --feature-powerset --no-dev-deps --keep-going --mutually-exclusive-features aws_lc_rs,rust_crypto --at-least-one-of aws_lc_rs,rust_crypto

test-features:
    cargo hack test --workspace --feature-powerset --keep-going --mutually-exclusive-features aws_lc_rs,rust_crypto --at-least-one-of aws_lc_rs,rust_crypto

# Not --all-features: aws_lc_rs/rust_crypto are mutually exclusive (see the compile_error!
# in lib.rs). idunn's own code doesn't branch on which backend is picked, so this already
# covers everything clippy could flag without it.
# Lint all targets and non-crypto features, failing on any warning (the invocation CI runs).
clippy:
    cargo clippy --workspace --all-targets --features test-fixtures,tokio-refresh,reqwest -- -D warnings

check-all: check-powerset test-features test-minimal-versions

# One-time per clone: run the versioned hooks in .githooks/ (rustfmt check before each commit).
install-hooks:
    git config core.hooksPath .githooks

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
    cargo cooldown metadata >/dev/null


# TODO: look into cargo-mutants
