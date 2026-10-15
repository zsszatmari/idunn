# Maintaining idunn

Why the tooling, CI and coverage setup looks the way it does. This is for contributors; the crate's design rationale is in [src/docs/architecture.md](../src/docs/architecture.md).

## Why coverage excludes test modules (and needs nightly)

`cargo llvm-cov` instruments the crate's inline `#[cfg(test)] mod tests` modules along with the production code. Test code runs by definition, so it reports ~100% covered and inflates the totals (measured: ~95% overall while `lib.rs`, the file with the real gap, was at 53%; roughly half of `jwks_store.rs`'s measured lines were test code). Excluding the test modules makes the number measure production code only.

The exclusion uses cargo-llvm-cov's documented `#[cfg_attr(coverage_nightly, coverage(off))]` on each test module (plus the `#![feature(coverage_attribute)]` crate attribute, likewise `cfg_attr`-gated). `#[coverage(off)]` is unstable ([rust-lang/rust#84605](https://github.com/rust-lang/rust/issues/84605)), so it sits behind `cfg(coverage_nightly)` — a cfg that *only* cargo-llvm-cov sets. `cargo build`, `cargo test`, `cargo clippy` and any consumer of the crate compile on stable and never see the feature gate; only the coverage measurement run uses nightly, into its own target dir. There is no `rust-toolchain.toml`: nightly is requested per invocation by the `just coverage` / `just coverage-ci` recipes. `Cargo.toml`'s `[lints.rust] unexpected_cfgs` check-cfg entry is what keeps stable builds warning-free about the `coverage_nightly` cfg name.

The CI gate (`coverage-ci`) is on **line** coverage. Region coverage is structurally noisy in Rust: `matches!`, `assert!`, `assert_eq!`, `?`, `unwrap()` and `derive`s all expand to branches whose non-taken arm (e.g. the `_ => false` in a `matches!` that succeeds) is mapped back to the invocation site and rendered as uncovered, even in fully exercised, correct code. Region coverage stays useful for browsing the HTML report; it is not something a gate can meaningfully enforce.

Rejected alternative: moving the tests into `src/*_tests.rs` files, which cargo-llvm-cov excludes by default on stable with no nightly needed. Rejected to keep each module's tests inline next to the code they exercise.

## Why coverage is uploaded to Codecov

The README's coverage badge needs a number that follows `main`, and crates.io keeps each version's README as published, so a service outside the repository has to serve it. Codecov is the coverage service well-known Rust crates use (rustls, chrono, quick-xml). The `coverage` job uploads `lcov.info` with `codecov/codecov-action`, authenticated by the repository's Codecov upload token from the `CODECOV_TOKEN` Actions secret, the setup rustls uses. The job keeps `contents: read`. Codecov receives the lcov report, the commit, branch and pull-request metadata, and the list of file paths in the repository.

`just coverage-ci` is the gate. The upload step has `continue-on-error`, because Codecov's availability is independent of the change under review, the same reasoning that keeps the live Apple tests out of PR CI. A failed upload still shows as a failed step. `codecov.yml` makes Codecov's commit statuses informational, so its separately computed numbers cannot fail a pull request.

The token protects `main` only while the Codecov account's "Token authentication for public repositories" setting (Settings page, Global Upload Token tab) is `Required`. Pull requests from forks get no secrets; the action uploads them tokenless under an `owner:branch` branch name, which `Required` accepts.

The SHA pin covers the action. The Codecov CLI, which the action downloads at run time, is pinned by the action's `version` input, and the action checks the download's GPG signature. Dependabot does not update that input: when bumping the action, bump `version` by hand to a CLI release at least 14 days old, the cooldown the `actions` group uses.

Rejected alternatives:

- Tokenless uploads with the setting at `Not required`: Codecov then checks only that the repository is public, so anyone could add reports to `main` and change the badge.
- OIDC (`use_oidc: true`): it needs `id-token: write` on the `coverage` job, where the dependencies' build scripts and tests run and could request tokens in the repository's name. Codecov checks only the repository claim, so OIDC proves no more than the upload token does.
- A `main`-only job that commits a shields.io endpoint JSON to a `badges` branch: it needs a CI job holding a `contents: write` token, and the repository's rules block the force push that would keep that branch to one commit.
- Coveralls: its action asks for the @coveralls user to be invited to the repository with the Write role.
- A gist updated by `schneegans/dynamic-badges-action`: it needs a GitHub personal access token as a secret, a credential that acts as the maintainer's GitHub account within its scopes.

## Why CI runs what it runs

CI (`.github/workflows/ci.yml`) calls the same `just` recipes used locally — `just clippy`, `just cargo-deny`, `just check-powerset-full`, `just test-features`, `just test-minimal-versions`, `just coverage-ci`, `just mutants`, `just doc`, `just doc-links` — plus `cargo package --locked` and the `msrv` job (`cargo +1.88.0 check`).

The live Apple contract tests (`#[ignore]`d, `cargo test -- --ignored real_apple`) are deliberately excluded from PR CI. They depend on Apple's endpoints being reachable and behaving as documented, which is independent of whatever change is under review — a PR would fail or pass based on Apple's availability that day. `.github/workflows/live-apple.yml` runs them weekly (and on demand via `workflow_dispatch`) to catch drift in Apple's API or in the fakes' assumptions.

Every job in `ci.yml` pins its actions by full commit SHA, with a `# vX.Y.Z` comment giving the human-readable version next to it. A tag is a mutable pointer a repository owner (or an attacker who compromises that owner's account) can repoint after the fact — this is exactly what happened to `tj-actions/changed-files` in March 2025, when its existing version tags were repointed to a malicious commit. A commit SHA can't be moved. The set of third-party actions is kept deliberately small — `actions/checkout`, `actions/upload-artifact`, `Swatinem/rust-cache`, `taiki-e/install-action`, `codecov/codecov-action` — each pulled in for something a shell script can't easily replace (checkout auth handling, artifact storage, cache key management, prebuilt-binary installs across recipes, the coverage upload). Toolchains are installed with plain `rustup`, which avoids a dedicated toolchain action for the same reason: one fewer third-party action to pin, review and update.

A SHA pin is exact by design, so nothing moves it forward on its own — `.github/dependabot.yml` bumps these pins so they don't go stale. The `actions` group there covers version updates only (Dependabot's default for a group with no `applies-to`) and batches them into one PR; each waits out a 14-day cooldown first, giving a hastily-cut or since-compromised release time to be caught before idunn builds against it. Tools installed through `taiki-e/install-action` without a version (`just`, `cargo-hack`, `cargo-mutants`, …) are pinned transitively: the action installs the tool versions listed in its own manifests, so the SHA pin and the 14-day cooldown apply to them too, on top of install-action's own delay of a few days behind upstream releases. That is why no `tool@x.y.z` versions appear in `ci.yml`: an explicit version would bypass the cooldown and need hand-bumping. A Dependabot bump of install-action can bring a newer cargo-mutants with new mutation operators and turn the `mutants` job red; the fix is a test, or a justified exclusion. Security updates, if ever enabled in the repository settings, are a separate mechanism: ungrouped, one PR per affected action, landing immediately with no cooldown and no `open-pull-requests-limit` cap — deliberately left that way, since bundling an urgent, isolated fix with an unrelated action's PR would let the unrelated one block it. Cargo dependencies are left out of this config entirely — those stay a manual `cargo cooldown update`.

## Why the feature-matrix recipes skip zero- and two-backend combinations

This follows from the compile-time backend guard described in src/docs/architecture.md, "Crypto backend".

Every recipe that iterates feature combinations has to skip the zero- and two-backend states: the compile-time guard makes them fail to build. `check-features`, `check-powerset`, `check-powerset-full` and `test-features` (`justfile`) all pass `--mutually-exclusive-features aws_lc_rs,rust_crypto --at-least-one-of aws_lc_rs,rust_crypto` to cargo-hack; both flags require `--feature-powerset`, which `check-features` and `test-features` therefore use. `check-features` runs at `--depth 1`: each crypto backend compiles in isolation. `test-fixtures`/`tokio-refresh` don't get a standalone run in this recipe, because a standalone run also needs a backend; `check-powerset-full`'s full powerset still covers them.

`test-features` needs one more thing beyond the hack flags: `Cargo.toml`'s dev-dependency self-reference (`idunn = { path = ".", features = [...] }`, which forces `reqwest`/`tokio-refresh` on for `cargo test`) requests idunn's own `default` feature too whenever `default-features` isn't set to `false` on it. A plain `cargo test` doesn't notice — the root package already pulls in `aws_lc_rs` through its own `default` — but it silently adds `aws_lc_rs` on top of whatever cargo-hack asks for: without `default-features = false`, `cargo test --no-default-features --features rust_crypto` builds both backends. `default-features = false` on that dev-dependency removes the side effect while keeping its stated purpose (forcing `reqwest`/`tokio-refresh`) intact — it is not redundant with the crate's own default, since it only matters once a caller picks a non-default feature set.

`clippy` (`justfile`) drops `--all-features` for the same reason, with a simpler fix: idunn's own code doesn't branch on which crypto backend is active — that distinction lives entirely inside `jsonwebtoken` — so linting once under the crate's default backend plus every non-crypto feature (`test-fixtures,tokio-refresh,reqwest`) already covers everything clippy could flag; the crypto features themselves are exercised for real by `check-powerset-full`/`test-features`.

`just check-powerset-full` runs the full feature powerset on every PR; `just check-powerset` covers only depth 2. That is 25 check combinations across the crate's 4 declared features (`aws_lc_rs`, `rust_crypto`, `test-fixtures`, `tokio-refresh`) — cheap enough that sampling a subset buys nothing. Revisit if the feature count grows past roughly 7, where the powerset's combinatorial growth would start to cost real CI time.

## Why cargo-deny runs advisories a second time for `rust_crypto`

`just cargo-deny` runs `cargo deny check` on the default graph (`aws_lc_rs`), then `cargo deny --no-default-features --features rust_crypto check`. The README offers `rust_crypto`, and its dependencies (`rsa`, `num-bigint-dig`, the pkcs crates) need the same advisory, license and ban checks as the default tree. cargo-deny reads `cargo metadata` and never compiles, so each run sees exactly the graph of one real build.

The `RUSTSEC-2023-0071` ignore for `rsa` matches only in the `rust_crypto` run. The default run therefore prints `advisory-not-detected` for it on every invocation; the warning is expected there. `unused-ignored-advisory` stays at its default (`warn`), so the `rust_crypto` run reports the ignore as unmatched once it goes stale.

Rejected: `all-features = true` in `deny.toml`. One run would cover both backends and the warning would disappear, but licenses and bans would run on a union graph that no real build has.

Rejected: `unused-ignored-advisory = "allow"`. It would hide a stale ignore in the `rust_crypto` run too.

## Why docs.rs builds with `reqwest` and `tokio-refresh`

docs.rs builds default features only, which would hide `ReqwestTransport`, `AppleAuthClient::new` and `AppleSeed::with_background_refresh`. `[package.metadata.docs.rs]` in `Cargo.toml` enables `reqwest` and `tokio-refresh`, and the `docs` CI job builds the same way through `just doc`, failing on any rustdoc warning.

- `all-features` is impossible: `aws_lc_rs` and `rust_crypto` are mutually exclusive (the `compile_error!` in `src/lib.rs`). The default `aws_lc_rs` is used, and the public API is the same for both backends.
- `test-fixtures` stays off: it exists for downstream dev-dependencies.
- There are no `rustdoc-args`: docs.rs passes `--cfg docsrs` itself.
- `#![cfg_attr(docsrs, feature(doc_cfg))]` produces the "Available on crate feature … only" badges. `doc_cfg` is nightly-only; `cfg(docsrs)` is set only by docs.rs and `just doc`, so stable builds never see the feature gate. The older `doc_auto_cfg` no longer exists; its behaviour is part of `doc_cfg`.
- The feature list appears in both `Cargo.toml` and the `just doc` recipe. Change them together.

## Why the README is the crate root documentation

docs.rs opens on the crate root, and the README is idunn's introduction, so `src/lib.rs` includes it there, followed by `src/docs/usage.md`. RustCrypto, getrandom, rand_core and schemars include their READMEs the same way; most well-known crates keep README and crate docs separate.

The README is read on GitHub, crates.io and docs.rs, which constrains it:

- Its Rust example has no hidden `#` lines: GitHub and crates.io show them verbatim, and crates.io declined to hide them (rust-lang/crates.io#8325). `cfg_attr(not(doctest), …)` keeps rustdoc from collecting the example as a doctest. `tests/readme_example.rs` compiles a copy of it inside the scaffolding it needs and fails when the copy and the README differ, so edit both together.
- Links into the crate docs are reference-style. The README defines each name with its docs.rs URL; `src/lib.rs` defines the same name as an intra-doc link before including the README. CommonMark uses the first definition of a name, so docs.rs gets a link that matches the version being read, checked by rustdoc and `just doc-links`, and GitHub and crates.io get the docs.rs URL. A name missing from `src/lib.rs` still resolves on docs.rs through the README's URL, unchecked. The technique is from https://linebender.org/blog/doc-include/.
- Other links are absolute URLs, since a relative link such as `CONTRIBUTING.md` resolves on GitHub only.
- The badges, the crate comparison and the license section appear on docs.rs as well.

Rejected alternatives:

- The README example as a doctest marked `ignore`: rustdoc labels it "This example is not tested" at the top of the front page, and nothing compiles it.
- Generating the README from the crate docs with cargo-rdme: among the top 200 crates only the ICU4X repository uses it, and its intra-doc link resolution needs a pinned nightly in CI.
- Separate README and crate docs, with the README doctested through a hidden `#[cfg(doctest)]` item as clap does: docs.rs would open on the usage guide.

## Why the design rationale is an embedded module

`src/docs/architecture.md` is part of the crate as `idunn::_architecture` (`#[doc = include_str!(...)]` on an empty `pub mod` in `src/lib.rs`), and the API docs and `src/docs/usage.md` link into its sections. The rationale on docs.rs therefore matches the published version, works offline, and rustdoc checks the module path of every link.

The two files live in `src/docs/` because rustdoc is their primary reader, the same standing as the `///` comments in `src/*.rs`. The README links into them through link definitions that `src/lib.rs` overrides, see "Why the README is the crate root documentation". Their intra-doc links are valid on docs.rs for every version at every moment; GitHub shows them as inert text, as it does in the doc comments.

- The `_` prefix marks the module as no API. It is public, so cargo-semver-checks treats removing or renaming it as a breaking change; keep the name.
- Heading anchors derive from the heading text, and rustdoc does not check them. `just doc-links` runs lychee with fragment checking over the generated HTML in CI. Renaming a heading changes its anchor: grep `src/` for the old title and update the links.
- `src/docs/architecture.md` has no top-level heading: rustdoc takes the module's summary line from the first block, so the intro paragraph comes first.
- `just doc-links` excludes rustdoc's own source-view links (`.rs.html#12-14`): JavaScript creates those line anchors, so a static check cannot find them.
- `just doc-links` also excludes one link, `dispatcher#setting-the-default-subscriber`. Every type page lists tracing's blanket impls (`WithSubscriber`, `Instrument`) with their docs, and rustdoc leaves the intra-doc links in those docs unresolved. The text is tracing's and the rendering is rustdoc's, so idunn cannot fix it. lychee skips the other unresolved links there (`super::Subscriber`, `crate::Span`) because they are not file URLs. Any other broken link, including a new one from a dependency, still fails the check. Remove the exclusion once rustdoc resolves these links. Rejected: excluding every href whose last path segment has no file extension, which would also hide later breakage of the same kind.

## Why one cargo-mutants mutant is excluded

The mutation run gates CI, so every mutant must be killed or justified. One class cannot be killed: `JwksStore` compares `Instant::elapsed()` from the real monotonic clock against a configured `Duration` in two places, the `refresh_interval` check in `get_key` (a fresh snapshot is confident evidence that a kid does not exist) and the `cooldown_period` check in `try_refresh`. Replacing `<` with `<=` changes the result only when the elapsed time equals the bound to the nanosecond. No test can produce that without a fake clock, and either answer at that instant is correct, so the mutant is equivalent.

Both strict `<` comparisons go through the private `is_within` helper in `src/jwks_store.rs`, and `.cargo/mutants.toml` excludes only `replace < with <= in is_within`. The exclusion names one concept. A `<` added to `get_key` or `try_refresh` later is still mutated.

The `>=` comparisons (`past_grace_period`, `snapshot_past_max_age`, the `max_key_age` branch of `get_key`) stay inline. Their mutants are killable and each guards a separate fail-closed or grace-period decision, so each call site keeps its own mutants and needs its own test.

Trade-off: the helper's other mutants (`true`, `false`, `==`, `>`) exist once and are shared by its two call sites. A test at either site kills them, so a missing test at the other site would not be flagged. Accepted for these two sites.

Rejected alternatives:

- Excluding by function name (`in JwksStore<T>::get_key` / `try_refresh`): silently excludes any later `<` in those functions.
- One helper for all five elapsed-time comparisons: its mutants would exist once, so one site's test would kill them for all, and a missing test for the `max_key_age` branch would go unnoticed.
- Injecting a fake clock: a large refactor only to pin behavior at a meaningless nanosecond boundary.
- Rewriting with `checked_sub` to avoid the operator: hides the mutant from the tool instead of justifying it.
- `#[mutants::skip]` on the functions: hides every other mutant in the core logic.

CI runs `just mutants` from the repo root, which is the crate root and the place `.cargo/mutants.toml` is read from. A run started from a parent directory (output paths prefixed with `idunn/`) does not read the exclusion and reports the `is_within` mutant as MISSED. When the job fails, it uploads `mutants.out` (`missed.txt`, `timeout.txt`, per-mutant logs) as the `mutants-out` artifact.
