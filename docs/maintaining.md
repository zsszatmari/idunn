# Maintaining idunn

Why the tooling, CI and coverage setup looks the way it does. This is for contributors; the crate's design rationale is in [src/docs/architecture.md](../src/docs/architecture.md).

## Why coverage excludes test modules (and needs nightly)

`cargo llvm-cov` instruments the crate's inline `#[cfg(test)] mod tests` modules along with the production code. Test code runs by definition, so it reports ~100% covered and inflates the totals (measured: ~95% overall while `lib.rs`, the file with the real gap, was at 53%; roughly half of `jwks_store.rs`'s measured lines were test code). Excluding the test modules makes the number measure production code only.

The exclusion uses cargo-llvm-cov's documented `#[cfg_attr(coverage_nightly, coverage(off))]` on each test module (plus the `#![feature(coverage_attribute)]` crate attribute, likewise `cfg_attr`-gated). `#[coverage(off)]` is unstable ([rust-lang/rust#84605](https://github.com/rust-lang/rust/issues/84605)), so it sits behind `cfg(coverage_nightly)` — a cfg that *only* cargo-llvm-cov sets. `cargo build`, `cargo test`, `cargo clippy` and any consumer of the crate compile on stable and never see the feature gate; only the coverage measurement run uses nightly, into its own target dir. There is no `rust-toolchain.toml`: nightly is requested per invocation by the `just coverage` / `just coverage-ci` recipes. `Cargo.toml`'s `[lints.rust] unexpected_cfgs` check-cfg entry is what keeps stable builds warning-free about the `coverage_nightly` cfg name.

The CI gate (`coverage-ci`) is on **line** coverage. Region coverage is structurally noisy in Rust: `matches!`, `assert!`, `assert_eq!`, `?`, `unwrap()` and `derive`s all expand to branches whose non-taken arm (e.g. the `_ => false` in a `matches!` that succeeds) is mapped back to the invocation site and rendered as uncovered, even in fully exercised, correct code. Region coverage stays useful for browsing the HTML report; it is not something a gate can meaningfully enforce.

Rejected alternative: moving the tests into `src/*_tests.rs` files, which cargo-llvm-cov excludes by default on stable with no nightly needed. Rejected to keep each module's tests inline next to the code they exercise.

## Why CI runs what it runs

CI (`.github/workflows/ci.yml`) calls the same `just` recipes used locally — `just clippy`, `just cargo-deny`, `just check-powerset-full`, `just test-features`, `just test-minimal-versions`, `just coverage-ci`, `just doc`, `just doc-links`.

The live Apple contract tests (`#[ignore]`d, `cargo test -- --ignored real_apple`) are deliberately excluded from PR CI. They depend on Apple's endpoints being reachable and behaving as documented, which is independent of whatever change is under review — a PR would fail or pass based on Apple's availability that day. `.github/workflows/live-apple.yml` runs them weekly (and on demand via `workflow_dispatch`) to catch drift in Apple's API or in the fakes' assumptions.

Every job in `ci.yml` pins its actions by full commit SHA, with a `# vX.Y.Z` comment giving the human-readable version next to it. A tag is a mutable pointer a repository owner (or an attacker who compromises that owner's account) can repoint after the fact — this is exactly what happened to `tj-actions/changed-files` in March 2025, when its existing version tags were repointed to a malicious commit. A commit SHA can't be moved. The set of third-party actions is kept deliberately small — `actions/checkout`, `actions/upload-artifact`, `Swatinem/rust-cache`, `taiki-e/install-action` — each pulled in for something a shell script can't easily replace (checkout auth handling, artifact storage, cache key management, prebuilt-binary installs across recipes). Toolchains are installed with plain `rustup`, which avoids a dedicated toolchain action for the same reason: one fewer third-party action to pin, review and update.

A SHA pin is exact by design, so nothing moves it forward on its own — `.github/dependabot.yml` bumps these pins so they don't go stale. The `actions` group there covers version updates only (Dependabot's default for a group with no `applies-to`) and batches them into one PR; each waits out a 14-day cooldown first, giving a hastily-cut or since-compromised release time to be caught before idunn builds against it. Security updates, if ever enabled in the repository settings, are a separate mechanism: ungrouped, one PR per affected action, landing immediately with no cooldown and no `open-pull-requests-limit` cap — deliberately left that way, since bundling an urgent, isolated fix with an unrelated action's PR would let the unrelated one block it. Cargo dependencies are left out of this config entirely — those stay a manual `cargo cooldown update`.

## Why the feature-matrix recipes skip zero- and two-backend combinations

This follows from the compile-time backend guard described in src/docs/architecture.md, "Why exactly one crypto backend is enforced at compile time".

Every recipe that iterates feature combinations has to skip the zero- and two-backend states: the compile-time guard makes them fail to build. `check-features`, `check-powerset`, `check-powerset-full` and `test-features` (`justfile`) all pass `--mutually-exclusive-features aws_lc_rs,rust_crypto --at-least-one-of aws_lc_rs,rust_crypto` to cargo-hack; both flags require `--feature-powerset`, which `check-features` and `test-features` therefore use. `check-features` runs at `--depth 1`: each crypto backend compiles in isolation. `test-fixtures`/`tokio-refresh` don't get a standalone run in this recipe, because a standalone run also needs a backend; `check-powerset-full`'s full powerset still covers them.

`test-features` needs one more thing beyond the hack flags: `Cargo.toml`'s dev-dependency self-reference (`idunn = { path = ".", features = [...] }`, which forces `reqwest`/`tokio-refresh` on for `cargo test`) requests idunn's own `default` feature too whenever `default-features` isn't set to `false` on it. A plain `cargo test` doesn't notice — the root package already pulls in `aws_lc_rs` through its own `default` — but it silently adds `aws_lc_rs` on top of whatever cargo-hack asks for: without `default-features = false`, `cargo test --no-default-features --features rust_crypto` builds both backends. `default-features = false` on that dev-dependency removes the side effect while keeping its stated purpose (forcing `reqwest`/`tokio-refresh`) intact — it is not redundant with the crate's own default, since it only matters once a caller picks a non-default feature set.

`clippy` (`justfile`) drops `--all-features` for the same reason, with a simpler fix: idunn's own code doesn't branch on which crypto backend is active — that distinction lives entirely inside `jsonwebtoken` — so linting once under the crate's default backend plus every non-crypto feature (`test-fixtures,tokio-refresh,reqwest`) already covers everything clippy could flag; the crypto features themselves are exercised for real by `check-powerset-full`/`test-features`.

`just check-powerset-full` runs the full feature powerset on every PR; `just check-powerset` covers only depth 2. That is 25 check combinations across the crate's 4 declared features (`aws_lc_rs`, `rust_crypto`, `test-fixtures`, `tokio-refresh`) — cheap enough that sampling a subset buys nothing. Revisit if the feature count grows past roughly 7, where the powerset's combinatorial growth would start to cost real CI time.

## Why docs.rs builds with `reqwest` and `tokio-refresh`

docs.rs builds default features only, which would hide `ReqwestTransport`, `AppleAuthClient::new` and `AppleSeed::with_background_refresh`. `[package.metadata.docs.rs]` in `Cargo.toml` enables `reqwest` and `tokio-refresh`, and the `docs` CI job builds the same way through `just doc`, failing on any rustdoc warning.

- `all-features` is impossible: `aws_lc_rs` and `rust_crypto` are mutually exclusive (the `compile_error!` in `src/lib.rs`). The default `aws_lc_rs` is used, and the public API is the same for both backends.
- `test-fixtures` stays off: it exists for downstream dev-dependencies.
- There are no `rustdoc-args`: docs.rs passes `--cfg docsrs` itself.
- `#![cfg_attr(docsrs, feature(doc_cfg))]` produces the "Available on crate feature … only" badges. `doc_cfg` is nightly-only; `cfg(docsrs)` is set only by docs.rs and `just doc`, so stable builds never see the feature gate. The older `doc_auto_cfg` no longer exists; its behaviour is part of `doc_cfg`.
- The feature list appears in both `Cargo.toml` and the `just doc` recipe. Change them together.

## Why the design rationale is an embedded module

`src/docs/architecture.md` is part of the crate as `idunn::_architecture` (`#[doc = include_str!(...)]` on an empty `pub mod` in `src/lib.rs`), and the API docs and `src/docs/usage.md` link into its sections. The rationale on docs.rs therefore matches the published version, works offline, and rustdoc checks the module path of every link.

The two files live in `src/docs/` because rustdoc is their primary reader, the same standing as the `///` comments in `src/*.rs`. The README does not link them. Their intra-doc links are valid on docs.rs for every version at every moment; GitHub shows them as inert text, as it does in the doc comments.

- The `_` prefix marks the module as no API. It is public, so cargo-semver-checks treats removing or renaming it as a breaking change; keep the name.
- Heading anchors (`#why-…`) derive from the heading text, and rustdoc does not check them. `just doc-links` runs lychee with fragment checking over the generated HTML in CI. Renaming a heading changes its anchor: grep `src/` for the old title and update the links.
- `src/docs/architecture.md` has no top-level heading: rustdoc takes the module's summary line from the first block, so the intro paragraph comes first.
- `just doc-links` excludes rustdoc's own source-view links (`.rs.html#12-14`): JavaScript creates those line anchors, so a static check cannot find them.
