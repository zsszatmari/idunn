# Architecture

TODO: ezt at kell neznem szemelyesen majd

## Why `AppleAuthClient` is one client with one constructor

`idunn` does two things for Sign in with Apple:

1. **Verify identity tokens** (`AppleIdentity`, `verify_identity_token`, `src/identity_verification.rs`) — needs only the app's `client_id` (`AppleTokenConfig::client_id`), checked against Apple's own published keys via idunn's own `JwksStore` and `jsonwebtoken`-based verification.
2. **Exchange an authorization code for tokens** (`VerifiedAuthorization`, `exchange_authorization_code`, `src/token_exchange.rs`) — needs a signed JWT client secret, which requires `team_id`, `key_id`, `client_id` and Apple's private key (`.p8`).

These two features barely touch the same code, which is why they live in separate submodules. They are nonetheless exposed through a single `AppleAuthClient` with a single constructor, rather than two independent client types, for one reason: **Apple requires apps to support account-deletion / token-revocation** (see [TN3194](https://developer.apple.com/documentation/technotes/tn3194-handling-account-deletions-and-revoking-tokens-for-sign-in-with-apple) and the [revoke-tokens REST API](https://developer.apple.com/documentation/signinwithapplerestapi/revoke-tokens), both linked at the top of `src/lib.rs`). Revocation needs the very refresh token this feature fetches, plus the same client-secret-signing credentials as the exchange call.

If verification and token exchange were separate client types, it would be possible to wire up a working sign-in flow that can never revoke a token — an app that's compliant on day one but silently unable to meet Apple's mandatory requirement later. A single constructor that requires all the credentials up front makes that state unreachable: correct usage (a fully-configured client) is the only usage. Token revocation itself isn't implemented yet — this constructor shape is what lets it be added later without changing any caller's configuration.

## Why `AppleAuthClient` clones share their state

`AppleAuthClient` is a *handle* to shared state — a JWKS cache plus the mutex that gives fetches against Apple their single-flight and cooldown/rate-limit behaviour — not a plain value. So it follows the `reqwest::Client` / `sqlx::Pool` convention: `Clone` is cheap and every clone points at the same state. `#[derive(Clone)]` is on the struct, but the shared fields are wrapped so the derive shares rather than duplicates them.

A plain derive over the original field types was rejected. `ArcSwapOption` is itself `Clone`, so a derive would have failed to compile *only* on `JwksStore`'s `async_lock::Mutex` — and had that one field been made cloneable too, the derive would have silently given every clone its own JWKS snapshot and its own cooldown state. N clones would then mean N independent fetches against Apple, and the `cooldown_period` floor (documented in `jwks_store.rs` as protection against DoS) would be enforced per clone instead of per client.

Per-field `Arc`, not one `Arc<Inner>`:

- `identity_verification` holds the cache and the fetch mutex — it **must** be shared, so it is `Arc`'d.
- `transport` is left a bare field: `HttpGet` already requires `T: Clone` and the trait contract is that it is a cheap handle (`ReqwestTransport` wraps a `reqwest::Client`, itself `Arc`-backed and owning the connection pool). Wrapping it in another `Arc` would be indirection for nothing.
- `credentials` (`token_config` + the derived `signing_key`) is `Arc`'d not for sharing semantics — a duplicated copy would be harmless — but so that `clone()` stays allocation-free and never copies Apple's private key. `axum`'s `State<T>` clones per request, so a per-field clone here would mean copying the `.p8` key material on every request. Keeping it behind one `Arc` also means there is exactly one copy of the key alive at a time, dropped when the last clone goes.

Rejected alternative: leave the type non-`Clone` and tell callers to hold an `Arc<AppleAuthClient>`. Workable, but it leaves the cheap wrong path — calling the constructor a second time — open, and that silently duplicates the cache and the rate limiter.

## Why `AppleTokenConfig` zeroizes on drop

`AppleTokenConfig::private_key_pem` holds Apple's `.p8` signing key — long-lived credential material, not a short-lived token. As a plain `Vec<u8>` its bytes were simply freed on drop and left readable in the freed allocation. The `EncodingKey` idunn derives from it in `AppleAuthClient::with_transport` already wipes itself — jsonwebtoken 11 puts `#[derive(Clone, Zeroize, ZeroizeOnDrop)]` on `EncodingKey` — which made idunn's own copy of the same secret the weaker link. `#[derive(ZeroizeOnDrop)]` on `AppleTokenConfig` closes that gap: all fields are wiped on drop (`team_id`/`key_id`/`client_id` aren't secret, but wiping them costs nothing and isn't worth a `#[zeroize(skip)]` each). `zeroize` is already in the build graph via jsonwebtoken, so this adds no new crate.

What it does **not** cover, and why the field doc says so:

- Copies the caller keeps are out of reach. The guarantee only holds if the caller moves the key `Vec` in rather than cloning it off a config object it retains, or leaving the PEM in a `String` env var.
- `Vec` zeroization is best-effort (documented as such in `zeroize`'s own source): it clears the current allocation's full capacity but can't chase down bytes an earlier reallocation left on the heap while the buffer was being built.

`AppleTokenConfig`'s `Debug` impl is hand-written rather than derived: it prints the non-secret identifiers (`team_id`/`key_id`/`client_id`) in full but replaces `private_key_pem` with a `<N redacted bytes>` placeholder, so the key can't leak into a log line or panic message. Written explicitly rather than just omitting the derive, so that a later `#[derive(Debug)]` can't silently reintroduce the leak.

## Why identity verification and token exchange share one `client_id`

Identity-token verification and token exchange used to take independently configurable identifiers: a `bundle_ids` slice passed into the constructor for verification's `aud` check, and `AppleTokenConfig::client_id` for signing the client secret used in exchange. Apple's own docs specify that an identity token's `aud` is always the developer's client_id — the same value already required for the client secret — so the two were never actually independent, just accidentally duplicated. `AppleTokenConfig::client_id` is now the single source for both, which also removes the possibility of the two silently drifting out of sync.

## Why the HTTP transport is injectable

`exchange_authorization_code` and `verify_identity_token` (via `JwksStore`'s fetch of Apple's published keys) both talk to Apple over HTTP through the same `HttpTransport` trait (`src/transport.rs`), defaulted to a `reqwest`-backed `ReqwestTransport`. This is injected rather than hardcoded for two reasons:

- It keeps `idunn` swappable to a different HTTP stack (proxying, custom TLS, a differently configured client) without forking the crate.
- It makes both `exchange_authorization_code` and `JwksStore` unit-testable with a small in-memory fake implementing `HttpTransport`, instead of requiring real network access or an HTTP-mocking dependency.

This abstraction covers every network call idunn makes, including the JWKS fetch — there's no third-party opacity left to carve out here.

`post_form`/`get` return a dedicated `TransportError` (network failure, or HTTP status + raw body) rather than `IdunnError`: the transport is a generic HTTP abstraction and shouldn't need to know about idunn's Apple-specific error variants. The Apple-aware callers (`exchange_authorization_code`, `JwksStore`) are what convert a `TransportError` into an `IdunnError`, parsing Apple's error body along the way. `TransportError::Network` itself carries a boxed `dyn Error` rather than concretely `reqwest::Error`, so a non-reqwest `HttpTransport` implementation can report its own underlying error type instead of being forced to produce one it doesn't have.

## Why `verify_identity_token` doesn't check the nonce itself

Apple's own verification checklist (see the comment in `IdentityVerificationClient::new`, `src/identity_verification.rs`) includes checking the token's `nonce` claim against whatever value the app generated for that authentication attempt. idunn deliberately stops short of that comparison: it requires knowing where and how the caller tracked the nonce it issued — typically a database lookup — which idunn has no generic way to perform. Instead, `verify_identity_token` extracts the `nonce` claim as-is onto `AppleIdentity` and leaves the value comparison to the caller.

idunn does, however, enforce nonce *presence*, controlled by `NoncePolicy` (part of `IdentityVerificationConfig`):

- `NoncePolicy::Strict` (the default): a token with no `nonce` claim is always `InvalidToken`, regardless of the token's `nonce_supported` claim. This is stricter than what Apple's docs technically require, chosen so replay protection is never silently disabled by a claim idunn has no way to verify the integrity of.
- `NoncePolicy::Permissive`: follows the handling Apple's own docs suggest (https://developer.apple.com/documentation/signinwithapplejs/authorizationi/id_token, `nonce_supported`) — a missing nonce is tolerated (`AppleIdentity::nonce` is `None`) only when `nonce_supported` is `false` or absent; a `nonce_supported: true` claim still fails the token even under this policy, since Apple's guidance is to treat the nonce as mandatory in that case.

When `nonce` is `None` under `Permissive`, `AppleIdentity::issued_at`/`expiration` (from the token's `iat`/`exp` claims) are exposed so the caller can still build its own replay-detection window (e.g. dedupe on the token itself within that range) instead of having no signal at all.

The same `NoncePolicy` also governs the `id_token` `exchange_authorization_code` gets back from Apple's token endpoint (see the section below) — there is only one verification path, not two with different rules.

## Why token exchange verifies the identity token itself

`exchange_authorization_code` used to hand Apple's token-endpoint response straight back to the caller as `AppleTokenResponse { access_token, refresh_token, id_token, expires_in }` — including the raw, unverified `id_token`. That put the crate's own reason for existing at risk: idunn already owns a conformant verifier (`verify_identity_token`), so exposing an unverified JWT invited exactly the mistake the crate is meant to prevent — a caller reading claims off a token whose signature, `iss`, `aud` and `exp` were never checked.

`exchange_authorization_code` now runs `verify_identity_token` on the `id_token` before returning, and the public result is `VerifiedAuthorization { refresh_token, identity: AppleIdentity }` — no raw `id_token` field at all. It is defined in `lib.rs`, not `token_exchange.rs`, so that module still needs no `identity_verification` import, keeping the two modules as disjoint as `verify_identity_token`'s own section above describes.

`access_token` and `expires_in` are dropped from the result entirely, not just hidden: idunn never uses the access token, and `expires_in` describes only that access token's lifetime. `RawTokenResponse` (the JSON deserialize target) stops declaring those two fields too — `serde` ignores the unknown fields Apple's response still sends, which `token_exchange.rs`'s own test fixture deliberately keeps sending to pin that.

**Consequence worth knowing:** because the exchange's `id_token` now goes through the same `NoncePolicy`-governed check as `verify_identity_token`, an authorization flow that never sends a `nonce` in its authorize request will fail every `exchange_authorization_code` call under the default `NoncePolicy::Strict` — previously this succeeded, because nothing verified the token at all. Such integrations need `NoncePolicy::Permissive`.

Rejected alternative: skip nonce-*presence* enforcement specifically on the exchange path, on the theory that this `id_token` arrives directly from Apple's token endpoint over TLS in response to the server's own POST, not from an untrusted client — the replay threat `NoncePolicy` exists for (see above) isn't present here. Rejected in favor of one uniform verification rule with no config-dependent divergence in what "verified" means, at the cost of the behavior change just described.

**Why verification failure carries the refresh token:** if the exchange succeeds but the `id_token` fails verification, Apple has already issued a live refresh token against a now-consumed authorization code. Returning a plain error and dropping that token would leave it un-revocable — in direct tension with Apple's mandatory account-deletion/revocation requirement (TN3194, see the top of `src/lib.rs`). `IdunnError::ExchangedTokenUnverified { refresh_token, cause }` carries the token instead, so the caller can revoke it via `revoke_refresh_token` — retrying on failure until it succeeds — rather than losing track of a live grant.

Every refresh token idunn hands back — success or error — is wrapped in `RefreshToken` (`src/token_exchange.rs`, next to `AppleTokenConfig` since both originate there), not a plain `String`: a derived `Debug` would print live credential material wherever the value ends up, and errors in particular get `{:?}`-printed into logs, `anyhow` chains and `unwrap()` panic messages by convention. `RefreshToken` has a hand-written, redacting `Debug` (no `Display` either, for the same reason) and no public constructor, so `VerifiedAuthorization::refresh_token` and `IdunnError::ExchangedTokenUnverified`'s copy are both safe by construction rather than by each caller remembering not to log the raw string. This mirrors `AppleTokenConfig`'s existing hand-written `Debug` for `private_key_pem`.

## Why the email claims are one struct and the flags aren't optional

Apple's `id_token` carries `email_verified` and `is_private_email` alongside `email`
(<https://developer.apple.com/documentation/signinwithapplejs/authorizationi/id_token>), but neither
flag means anything without an address to qualify. `AppleIdentity::email` is therefore
`Option<AppleEmail>` — one optional struct gated on whether the token carried an `email` claim at
all — rather than three independently optional fields on `AppleIdentity` that a caller could combine
into a nonsensical state (a `verified: true` with no address).

Inside `AppleEmail`, `verified` and `is_private` are plain `bool`s, not `Option<bool>`, despite both
source claims being optional on the wire:

- `verified` defaults to `false` when `email_verified` is absent. Apple's own docs already document
  the absent case as equivalent to a `false` value (Sign in with Apple at Work & School), so there is
  no distinct "unknown" state worth preserving — `Option<bool>` would just push a meaningless
  three-way match onto every caller.
- `is_private` defaults to checking whether the address ends with `@privaterelay.appleid.com` when
  `is_private_email` is absent. Apple's private relay domain is a known, stable string, so this
  fallback gives callers a real answer instead of `None` in the case — token issuers other than
  current Apple SDKs, or historical tokens — where the claim wasn't sent. The claim, when present,
  always wins over the heuristic in both directions: an explicit `false` on a relay-looking address
  is trusted over the domain guess, and vice versa. The heuristic only fires on absence.

`email_verified`/`is_private_email` also arrive as either a JSON Boolean or the strings `"true"` /
`"false"` — Apple's docs state this explicitly. Both forms are parsed inside a `serde`
`deserialize_with` function on `ApplePayload` (not converted after `jsonwebtoken::decode`), so a
malformed value (anything else, including an explicit `null`) becomes a plain deserialization
failure that flows through `jsonwebtoken::decode`'s existing JSON-error path and rejects the token as
`InvalidTokenCause::Rejected` — the same failure mode a missing `iat`/`aud` already produces, with no
new error variant needed.

`real_user_status` (`ASUserDetectionStatus`) is modeled as an enum with `Unsupported`/`Unknown`/
`LikelyReal` plus a catch-all `Other(i64)`, rather than a strict enum or a raw integer. Apple
documents the claim as absent for web-based apps and pre-iOS-14/macOS-11 clients, which
`Other`/`Unsupported` already models without a separate `Option` wrapper (absence maps to
`Unsupported`, since idunn can't distinguish "this client doesn't support the signal" from "Apple
sent 0"). `Other(i64)` exists so that a future additive value Apple introduces is preserved instead
of failing verification outright — deserializing the claim as `i64` (not `u8`) keeps that fallback
total, since a strict-width integer would itself reject an out-of-range value before the `Other` arm
ever ran.

## Why coverage excludes test modules (and needs nightly)

`cargo llvm-cov` instruments the crate's inline `#[cfg(test)] mod tests` modules along with the production code. Test code runs by definition, so it reports ~100% covered and pulls the totals up — the overall figure was ~95% while `lib.rs`, the file with the real gap, sat at 53%. For `jwks_store.rs`, roughly half the measured lines were test code. Excluding the test modules makes the number measure the production code again.

The exclusion uses cargo-llvm-cov's documented `#[cfg_attr(coverage_nightly, coverage(off))]` on each test module (plus the `#![feature(coverage_attribute)]` crate attribute, likewise `cfg_attr`-gated). `#[coverage(off)]` is still unstable ([rust-lang/rust#84605](https://github.com/rust-lang/rust/issues/84605)), so it sits behind `cfg(coverage_nightly)` — a cfg that *only* cargo-llvm-cov sets. `cargo build`, `cargo test`, `cargo clippy` and any consumer of the crate compile on stable and never see the feature gate; only the coverage measurement run uses nightly, into its own target dir. No `rust-toolchain.toml` is added — nightly is requested per invocation by the `just coverage` / `just coverage-ci` recipes. `Cargo.toml`'s `[lints.rust] unexpected_cfgs` check-cfg entry is what keeps stable builds warning-free about the new cfg names.

The CI gate (`coverage-ci`) is on **line** coverage, not region coverage. Region coverage is structurally noisy in Rust: `matches!`, `assert!`, `assert_eq!`, `?`, `unwrap()` and `derive`s all expand to branches whose non-taken arm (e.g. the `_ => false` in a `matches!` that succeeds) is mapped back to the invocation site and rendered as uncovered, even in fully exercised, correct code. Region coverage stays useful for browsing the HTML report; it is not something a gate can meaningfully enforce.

Rejected alternative: moving the tests into `src/*_tests.rs` files, which cargo-llvm-cov excludes by default on stable with no nightly needed. Rejected to keep each module's tests inline next to the code they exercise.
