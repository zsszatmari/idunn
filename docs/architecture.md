# Architecture

TODO: ezt at kell neznem szemelyesen majd

## Why `AppleAuthClient` is one client with one constructor

`idunn` does two things for Sign in with Apple:

1. **Verify identity tokens** (`AppleIdentity`, `verify_identity_token`, `src/identity_verification.rs`) — needs only the app's `client_id` (`AppleTokenConfig::client_id`), checked against Apple's own published keys via idunn's own `JwksStore` and `jsonwebtoken`-based verification.
2. **Exchange an authorization code for tokens** (`SignInDetails`, `exchange_authorization_code`, `src/token_exchange.rs`) — needs a signed JWT client secret, which requires `team_id`, `key_id`, `client_id` and Apple's private key (`.p8`).

These two features barely touch the same code, which is why they live in separate submodules. They are nonetheless exposed through a single `AppleAuthClient` with a single constructor, rather than two independent client types, for one reason: **Apple requires apps to support account-deletion / token-revocation** (see [TN3194](https://developer.apple.com/documentation/technotes/tn3194-handling-account-deletions-and-revoking-tokens-for-sign-in-with-apple) and the [revoke-tokens REST API](https://developer.apple.com/documentation/signinwithapplerestapi/revoke-tokens), both linked at the top of `src/lib.rs`). Revocation needs the very refresh token this feature fetches, plus the same client-secret-signing credentials as the exchange call.

If verification and token exchange were separate client types, it would be possible to wire up a working sign-in flow that can never revoke a token — an app that's compliant on day one but silently unable to meet Apple's mandatory requirement later. A single constructor that requires all the credentials up front makes that state unreachable: correct usage (a fully-configured client) is the only usage.

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

`post_form`/`get` return a dedicated `TransportError` (network failure, or HTTP status + raw body) rather than an idunn Apple-domain error: the transport is a generic HTTP abstraction and shouldn't need to know about idunn's Apple-specific error variants. The Apple-aware callers convert a `TransportError` into the operation-specific error type — `JwksStore`'s fetch into `VerificationError::CannotVerifyToken`, `exchange_authorization_code` into `TokenExchangeError`, `revoke_refresh_token` into `TokenRevocationError` — parsing Apple's error body along the way. `TransportError::Network` itself carries a boxed `dyn Error` rather than concretely `reqwest::Error`, so a non-reqwest `HttpTransport` implementation can report its own underlying error type instead of being forced to produce one it doesn't have.

`HttpTransport`, `HttpGet`, `HttpPost`, `TransportError`, `VerificationConfig` and `NoncePolicy` are all re-exported from `lib.rs`. They have to be: `AppleAuthClient<T: HttpTransport>` is generic over its transport, so a downstream crate that stores one in a struct field must name a concrete `T` (`impl Trait` is not allowed there, and the RPITIT traits are not dyn-compatible), and `with_transport` takes a `VerificationConfig`. Left as private imports they made the whole injectable-transport abstraction unreachable from outside the crate — `with_transport` was public but uncallable.

`with_transport` takes one `VerificationConfig`: it configures a single operation — identity-token verification — and the JWKS cache exists only to serve that operation, so one struct expresses the whole decision. `transport` is the last parameter because it is the one callers most often leave at a default-constructed value (`ReqwestTransport::default()`), while the config is what they actually tune. The type lives in its own `config` module because both `jwks_store` and `identity_verification` need it and neither should depend on the other. `VerificationConfig` holds the JWKS cache's timing fields; the nonce-presence policy lives on `AppleAuthClient`'s `N: NonceRequirement` type parameter — see "Why the nonce policy is a type parameter" below.

## Why `verify_identity_token` doesn't check the nonce itself

Apple's own verification checklist (see the comment in `IdentityVerificationClient::new`, `src/identity_verification.rs`) includes checking the token's `nonce` claim against whatever value the app generated for that authentication attempt. idunn deliberately stops short of that comparison: it requires knowing where and how the caller tracked the nonce it issued — a session row, a hashed lookup, an async store, an HMAC — which idunn has no generic way to perform. Instead, `verify_identity_token` returns the `nonce` claim as-is and leaves the value comparison to the caller.

Where the claim is returned is itself a deliberate choice. The nonce is **not** an `AppleIdentity` field: `AppleIdentity` carries verified identity attributes (`apple_user_id`, `email`, ...), and the nonce is not one — it is an unfinished verification step. Burying it among `email` / `apple_user_id` is exactly what let earlier callers treat a "successful" `verify_identity_token` as fully authenticated and never compare the value. So the nonce is hoisted to the top level of both result types — `IdentityWithPendingNonce { nonce, identity }` from `verify_identity_token`, `SignInDetails { nonce, refresh_token, identity }` from `exchange_authorization_code` — each with a doc comment that states the remaining obligation on the value the caller actually holds. This is the same "make the wrong path unreachable / put the obligation on the type" principle already used for `RefreshToken`'s redacting `Debug` (below) and the single-constructor design (above): the type's shape, not a buried field doc or an external checklist, is what carries the message.

Rejected alternative: an `expected_nonce: &str` parameter on `verify_identity_token` that does a constant-time compare internally. It reads cleaner, but it hard-codes one strategy — synchronous plaintext equality against a value the caller already has in hand — and forecloses every other way a caller might have stored the nonce it issued (a hashed or async lookup, an HMAC, a session record keyed differently). Making the obligation structurally prominent without dictating how it is met keeps all of those open.

idunn does, however, enforce nonce *presence*, controlled by `NoncePolicy` (part of `VerificationConfig`):

- `NoncePolicy::Strict` (the default): a token with no `nonce` claim is always `InvalidToken`, regardless of the token's `nonce_supported` claim. This is stricter than what Apple's docs technically require, chosen so replay protection is never silently disabled by a claim idunn has no way to verify the integrity of.
- `NoncePolicy::Permissive`: follows the handling Apple's own docs suggest (https://developer.apple.com/documentation/signinwithapplejs/authorizationi/id_token, `nonce_supported`) — a missing nonce is tolerated (`nonce` is `None`) only when `nonce_supported` is `false` or absent; a `nonce_supported: true` claim still fails the token even under this policy, since Apple's guidance is to treat the nonce as mandatory in that case.

When `nonce` is `None` under `Permissive`, `AppleIdentity::issued_at`/`expiration` (from the token's `iat`/`exp` claims) are exposed so the caller can still build its own replay-detection window (e.g. dedupe on the token itself within that range) instead of having no signal at all.

The same `NoncePolicy` also governs the `id_token` `exchange_authorization_code` gets back from Apple's token endpoint (see the section below) — there is only one verification path, not two with different rules.

## Why token exchange verifies the identity token itself

`exchange_authorization_code` used to hand Apple's token-endpoint response straight back to the caller as `AppleTokenResponse { access_token, refresh_token, id_token, expires_in }` — including the raw, unverified `id_token`. That put the crate's own reason for existing at risk: idunn already owns a conformant verifier (`verify_identity_token`), so exposing an unverified JWT invited exactly the mistake the crate is meant to prevent — a caller reading claims off a token whose signature, `iss`, `aud` and `exp` were never checked.

`exchange_authorization_code` runs `verify_identity_token` on the `id_token` before returning, and the public result is `SignInDetails { nonce: Option<String>, refresh_token, identity: AppleIdentity }` — no raw `id_token` field at all. It is defined in `lib.rs`, not `token_exchange.rs`, so that module still needs no `identity_verification` import, keeping the two modules as disjoint as `verify_identity_token`'s own section above describes.

`access_token` and `expires_in` are dropped from the result entirely, not just hidden: idunn never uses the access token, and `expires_in` describes only that access token's lifetime. `RawTokenResponse` (the JSON deserialize target) stops declaring those two fields too — `serde` ignores the unknown fields Apple's response still sends, which `token_exchange.rs`'s own test fixture deliberately keeps sending to pin that.

**Consequence worth knowing:** because the exchange's `id_token` goes through the same `NoncePolicy`-governed check as `verify_identity_token`, an authorization flow that never sends a `nonce` in its authorize request will fail every `exchange_authorization_code` call under the default `NoncePolicy::Strict` — previously this succeeded, because nothing verified the token at all. Such integrations need `NoncePolicy::Permissive`.

Rejected alternative: skip nonce-*presence* enforcement specifically on the exchange path, on the theory that this `id_token` arrives directly from Apple's token endpoint over TLS in response to the server's own POST, not from an untrusted client — the replay threat `NoncePolicy` exists for (see above) isn't present here. Rejected in favor of one uniform verification rule with no config-dependent divergence in what "verified" means, at the cost of the behavior change just described.

**Why verification failure carries the refresh token:** if the exchange succeeds but the `id_token` fails verification, Apple has already issued a live refresh token against a now-consumed authorization code. Returning a plain error and dropping that token would leave it un-revocable — in direct tension with Apple's mandatory account-deletion/revocation requirement (TN3194, see the top of `src/lib.rs`). `CodeExchangeError::ExchangedTokenUnverified { refresh_token, cause }` carries the token instead, so the caller can revoke it via `revoke_refresh_token` — retrying on failure until it succeeds — rather than losing track of a live grant. `AppleAuthClient::sign_in`, built on top of `exchange_authorization_code`, takes over that retry for its own callers — see "Why `sign_in` revokes once and then hands the token back" below.

Every refresh token idunn hands back — success or error — is wrapped in `RefreshToken` (`src/token_exchange.rs`, next to `AppleTokenConfig` since both originate there), not a plain `String`: a derived `Debug` would print live credential material wherever the value ends up, and errors in particular get `{:?}`-printed into logs, `anyhow` chains and `unwrap()` panic messages by convention. `RefreshToken` has a hand-written, redacting `Debug` (no `Display` either, for the same reason) and no public constructor, so `SignInDetails::refresh_token` and `CodeExchangeError::ExchangedTokenUnverified`'s copy are both safely loggable by construction. This mirrors 
`AppleTokenConfig`'s existing hand-written `Debug` for `private_key_pem`.

## Why the nonce policy is a type parameter

`AppleAuthClient::sign_in_with_nonce` compares a token's `nonce` claim against one fixed `expected_nonce`. Under `NoncePolicy::Permissive`, a token may legitimately carry no `nonce` claim at all (see the section above) — nothing to compare against. Silently treating that as a match would defeat replay protection for exactly the clients `Permissive` exists to admit; treating it as a mismatch would reject a token idunn itself accepted, under a misleading `NonceMismatch`.

`AppleAuthClient<T, N: NonceRequirement = Strict>` resolves this by making `sign_in_with_nonce` a method on `AppleAuthClient<T, Strict>` only — a `Permissive` client has no such method, a compile error rather than a wrong answer at either runtime branch. `N` is a marker type (`Strict`/`Permissive`, sealed so no other type can implement `NonceRequirement`) rather than a runtime field, precisely so the compiler enforces this. `NonceRequirement::POLICY` reifies the marker back into a runtime `NoncePolicy` for `IdentityVerificationClient` to consume.

A `Permissive` client still signs in fine — through `sign_in` with a checker that decides what a missing nonce means for its flow, exactly as `verify_identity_token` already leaves that decision to the caller under `NoncePolicy::Permissive` (see above). `sign_in_with_nonce` is the narrower, single-question convenience: does this claim equal that string.

This is a different axis from "Why `AppleAuthClient` is one client with one constructor" above: that section keeps every client able to revoke a token; this one narrows which sign-in *method* a client exposes, not what it can construct or revoke. `with_transport`/`new` still build any `AppleAuthClient<T, N>` in one call — a `Permissive` client is `AppleAuthClient::<T, Permissive>::with_nonce_requirement(...)`, no separate constructor family.

## Why `sign_in` revokes once and then hands the token back

`sign_in` layers nonce and Apple-user matching on top of `verify_identity_token` and `exchange_authorization_code`. Once the code is exchanged, a rejection (`PostExchangeRejection`: the exchanged `id_token` fails verification, its nonce doesn't match, or it names a different Apple user) leaves a live refresh token that `sign_in`'s caller never asked for and cannot use.

`sign_in` makes one revocation attempt for that token before returning, splitting the outcome into two `SignInError` variants: `RejectedAfterExchange` when the revoke succeeds — the caller has nothing left to do — and `RevocationRequired`, carrying the token, when it doesn't. `idunn`'s core has no runtime dependency (no `tokio::spawn`, no sleep — see "Why background refresh is opt-in and takes a `Handle`" below for the one opt-in exception), so it can attempt the revoke exactly once, synchronously, but cannot itself retry on failure. `RevocationRequired` hands the token to the caller for that retry, mirroring `CodeExchangeError::ExchangedTokenUnverified` (see above) — the same obligation, now discharged once by `sign_in` before it ever reaches the caller.

`RevocationRequired` also carries the verified `AppleIdentity` from the caller's own identity token: a caller that can't revoke immediately must persist the pending revocation and retry later, possibly across a process restart, and an opaque refresh token alone gives it no key to file that record under. This is the identity of the sign-in *attempt*, not necessarily of the stuck token: under `PostExchangeRejection::SubjectMismatch` the exchanged `id_token` names a different Apple user than `identity` does — that mismatch is precisely why the sign-in was rejected — so the field answers "whose sign-in attempt produced this stuck token", not "who Apple considers the token's owner".

Apple answering `invalid_grant` to the revoke call is folded into a successful revocation rather than a `TokenRevocationError` (see `token_exchange::revoke_refresh_token`): it means Apple no longer recognizes the token as a usable grant, so what the call exists to guarantee — the token can't be used — already holds. Treating it as a failure would push `sign_in` into `RevocationRequired` for a retry that can never succeed. As a consequence, a caller holding a `RevocationRequired` will eventually see its retry of `revoke_refresh_token` succeed.

## Why sign_in's nonce checker is `Fn(Option<String>) -> Fut`, not `AsyncFn`

`sign_in`'s `nonce_checker` parameter looks like a natural fit for `AsyncFn(Option<&str>) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>` — it's called, awaited, and nothing about its job looks like it needs an owned `String` or a named future type. However, `AsyncFn` makes `sign_in`'s own returned future un-`Send`, and not in a way idunn's own test suite can see.

`AsyncFn` bounds desugar through an associated `CallRefFuture<'a>` GAT, parameterized by the closure's own self-borrow — `fn async_call(&self, args) -> Self::CallRefFuture<'_>` ties the returned future's type to however long that particular call borrows the closure. Proving `sign_in`'s opaque future `Send` then needs `for<'a> F::CallRefFuture<'a>: Send` — a higher-ranked, unstable GAT bound that cannot be written on stable and that rustc will not discharge through the binder. This holds even with an owned `Option<String>` argument: switching only the argument off `&str` was tried and still produces the same "implementation of `Send` is not general enough" error, confirming the self-borrow is what needs removing, not the argument's borrow. The failure surfaces as "implementation of `Send` is not general enough" — a higher-ranked-region error, not an ordinary "this type isn't `Send`" — and it lands wherever `Send` is first *demanded*, not inside idunn: nothing in idunn's own code requires `sign_in`'s future to be `Send`, so a downstream caller with a `Send`-bound API (an axum route registered via `post(handler)`, a multi-threaded-runtime `tokio::spawn`) is typically the first place the obligation becomes visible, as an opaque error pointing at its own call site rather than at `sign_in`.

`Fn(Option<String>) -> Fut` with `Fut: Future<Output = Result<bool, Box<dyn std::error::Error + Send + Sync>>> + Send` removes the GAT and the binder entirely, rather than fixing one source of it. `Send` becomes an ordinary where-clause obligation on the caller-supplied `Fut`, discharged locally when `sign_in` is called — a non-`Send` checker now fails at its own call site inside idunn, instead of resurfacing as an opaque error at a downstream route. The cost: callers write `|candidate| async move { .. }` instead of `async |candidate| { .. }`, and the claim arrives owned (`Option<String>`, cloned out of `IdentityWithPendingNonce`/`SignInDetails` at each call) rather than borrowed.

`verification_and_exchange_futures_are_send`, `sign_in_with_nonce_future_is_send` and `sign_in_future_is_send` (`src/lib.rs`, `mod tests`) guard this: each asserts a client method's returned future is `Send`, standing in for the downstream `Send`-bound caller that would otherwise be the first to notice a regression.

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
- `is_private` defaults to checking whether the address ends with `@privaterelay.appleid.com` or
  (as per Apple's newly publicly domain) `@private.icloud.com` when `is_private_email` is absent. 
  Apple's private relay domains are known, stable strings, so this   fallback gives callers a real 
  answer instead of `None` in the case — token issuers other than   current Apple SDKs, or historical
  tokens — where the claim wasn't sent. The claim, when present,   always wins over the heuristic in 
  both directions: an explicit `false` on a relay-looking address  is trusted over the domain guess, 
  and vice versa. The heuristic only fires on absence.

`email_verified`/`is_private_email` also arrive as either a JSON Boolean or the strings `"true"` /
`"false"` — Apple's docs state this explicitly. Both forms are parsed inside a `serde`
`deserialize_with` function on `ApplePayload` (not converted after `jsonwebtoken::decode`), so a
malformed value (anything else, including an explicit `null`) becomes a plain deserialization
failure that flows through `jsonwebtoken::decode`'s existing JSON-error path and rejects the token as
`InvalidTokenCause::Rejected` — the same failure mode a missing `iat`/`aud` already produces, with no
new error variant needed.

`real_user_status` (`ASUserDetectionStatus`) is modeled as `Option<RealUserStatus>`, an enum with
`Unsupported`/`Unknown`/`LikelyReal`, rather than a strict enum or a raw integer. `None` is Apple
"didn't tell us this time" — it covers both an absent claim (the signal isn't sent for web-based apps
or below iOS 14 / macOS 11) and a value idunn doesn't recognize. Folding an unrecognized value into
`None` rather than preserving it follows the same reasoning `AppleIdentity::real_user_status`'s own
doc gives for absence: an unrecognized fraud signal can't be interpreted, so the conservative read is
to treat it the same as no signal at all, rather than surface a value callers might mistake for one
of the three Apple currently documents.

## Why coverage excludes test modules (and needs nightly)

`cargo llvm-cov` instruments the crate's inline `#[cfg(test)] mod tests` modules along with the production code. Test code runs by definition, so it reports ~100% covered and pulls the totals up — the overall figure was ~95% while `lib.rs`, the file with the real gap, sat at 53%. For `jwks_store.rs`, roughly half the measured lines were test code. Excluding the test modules makes the number measure the production code again.

The exclusion uses cargo-llvm-cov's documented `#[cfg_attr(coverage_nightly, coverage(off))]` on each test module (plus the `#![feature(coverage_attribute)]` crate attribute, likewise `cfg_attr`-gated). `#[coverage(off)]` is still unstable ([rust-lang/rust#84605](https://github.com/rust-lang/rust/issues/84605)), so it sits behind `cfg(coverage_nightly)` — a cfg that *only* cargo-llvm-cov sets. `cargo build`, `cargo test`, `cargo clippy` and any consumer of the crate compile on stable and never see the feature gate; only the coverage measurement run uses nightly, into its own target dir. No `rust-toolchain.toml` is added — nightly is requested per invocation by the `just coverage` / `just coverage-ci` recipes. `Cargo.toml`'s `[lints.rust] unexpected_cfgs` check-cfg entry is what keeps stable builds warning-free about the new cfg names.

The CI gate (`coverage-ci`) is on **line** coverage, not region coverage. Region coverage is structurally noisy in Rust: `matches!`, `assert!`, `assert_eq!`, `?`, `unwrap()` and `derive`s all expand to branches whose non-taken arm (e.g. the `_ => false` in a `matches!` that succeeds) is mapped back to the invocation site and rendered as uncovered, even in fully exercised, correct code. Region coverage stays useful for browsing the HTML report; it is not something a gate can meaningfully enforce.

Rejected alternative: moving the tests into `src/*_tests.rs` files, which cargo-llvm-cov excludes by default on stable with no nightly needed. Rejected to keep each module's tests inline next to the code they exercise.

## Why background refresh is opt-in and takes a `Handle`

`JwksStore::refresh_keystore` (`src/jwks_store.rs`) has always been able to warm the cache and report back how long to wait before calling again, but nothing ever called it automatically — driving it was left to the caller's own schedule. `AppleAuthClient::keystore_refresh_loop` closes that gap without giving the crate a runtime dependency: it's a plain method, gated behind no feature, that returns a future implementing the loop; the caller supplies `sleep: impl Fn(Duration) -> impl Future` and decides how (or whether) to drive it. `tokio-refresh` (`Cargo.toml`, off by default like `reqwest`) adds exactly one more method on top, `with_background_refresh`, that wires `keystore_refresh_loop` to `tokio::time::sleep` and spawns it. Choosing the runtime stays the binary's job, matching `reqwest` — also optional — being the only other dependency this crate treats that way.

Three design choices fall out of that split:

**The loop future holds a `Weak<IdentityVerificationClient<T>>`, not a strong `Arc`.** Every `AppleAuthClient` clone shares one `Arc<IdentityVerificationClient<T>>` (see "Why `AppleAuthClient` clones share their state"). If the spawned task held a strong reference, the last `AppleAuthClient` clone being dropped would never actually free that state — the task would keep it alive and keep polling Apple forever, an unkillable background leak with no handle to cancel it. A `Weak` means `Weak::upgrade()` starts failing the moment the last clone drops, and the loop notices on its very next tick (at most one more sleep later) and returns on its own. The task's lifetime is tied to the client's, with nothing extra for the caller to manage.

**`with_background_refresh` takes a `tokio::runtime::Handle` as a parameter, rather than spawning implicitly during construction.** `tokio::spawn` panics outside a running runtime, but `AppleAuthClient::new`/`with_transport` are plain, non-async functions — exactly the kind reasonably called from a `OnceLock` initializer, a `lazy_static`, or other setup that runs before any runtime is entered. Requiring a `Handle` moves that runtime requirement into the signature, where a caller sees it before it can panic at runtime, instead of hiding it inside a constructor that only sometimes needs a runtime depending on how it's used. `Handle::spawn` also works from outside a runtime context (unlike the bare `tokio::spawn` free function, which needs a runtime already entered on the calling thread), so passing the handle explicitly is strictly more flexible, not just more explicit.

**Edition 2024's return-position-`impl-Trait` capture rules make `keystore_refresh_loop`'s signature more subtle than it looks.** Its return type is `impl Future<Output = ()> + Send + use<T, N, S, Fut>`, naming every type parameter in scope but no lifetime. In edition 2024, a method's RPIT captures *all* in-scope type and lifetime parameters by default — including `&self`'s anonymous lifetime — unless a precise-capturing `use<..>` bound says otherwise. Reaching for the seemingly-equivalent `+ 'static` instead doesn't opt out of that captured lifetime; it just adds an additional, conflicting bound on top of it, and the method fails to compile. Listing the type parameters (`N` included, even though the loop stores nothing of type `N` — the future only touches `T` through `IdentityVerificationClient<T>`) while omitting all lifetimes is what tells the compiler the returned future doesn't borrow from `&self` at all, which is what makes it spawnable (`tokio::spawn` requires `'static`) in the first place.

The loop also floors every sleep at `MIN_REFRESH_DELAY` (1 second), regardless of what `refresh_keystore()` suggests. That suggestion is `VerificationConfig::refresh_interval` on success or `cooldown_period` on failure — both caller-supplied and both documented as acceptable to set to `Duration::ZERO` (see `stale_key_grace_period`'s docs in `src/config.rs`). On the manual `refresh_keystore()` path a `ZERO` config is the caller's own problem to avoid; here the loop owns the task, so a `ZERO`-configured cooldown combined with a persistent fetch failure would otherwise busy-loop the task and flood Apple's endpoint with no backoff to stop it — precisely the DoS-shaped failure `cooldown_period` exists to prevent on every other path into `JwksStore`.
