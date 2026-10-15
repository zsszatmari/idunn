The design decisions behind idunn's API, one section per decision: what was chosen, why, and which alternatives were rejected.

## Why `AppleAuthClient` is one client with one constructor

`idunn` does two things for Sign in with Apple:

1. **Verify identity tokens** (`AppleIdentity`, `verify_identity_token`, `src/identity_verification.rs`) — needs only the app's `client_id` (`AppleTokenConfig::client_id`), checked against Apple's own published keys via idunn's own `JwksStore` and `jsonwebtoken`-based verification.
2. **Exchange an authorization code for tokens** (`SignInDetails`, `exchange_authorization_code`, `src/token_exchange.rs`) — needs a signed JWT client secret, which requires `team_id`, `key_id`, `client_id` and Apple's private key (`.p8`).

These two features are distinct but equally important part of the login flow. They are exposed through a single `AppleAuthClient` with a single constructor, for one reason: **Apple requires apps to support account-deletion / token-revocation** (see [TN3194](https://developer.apple.com/documentation/technotes/tn3194-handling-account-deletions-and-revoking-tokens-for-sign-in-with-apple) and the [revoke-tokens REST API](https://developer.apple.com/documentation/signinwithapplerestapi/revoke-tokens), both linked at the top of `src/lib.rs`). Revocation needs the very refresh token this feature fetches, plus the same client-secret-signing credentials as the exchange call.

If verification and token exchange were separate client types, it would be possible to wire up a working sign-in flow that can never revoke a token — an app that's compliant on day one but silently unable to meet Apple's mandatory requirement later. A single constructor that requires all the credentials up front makes that state unreachable: correct usage (a fully-configured client) is the only usage.

## Why `AppleAuthClient` clones share their state

`AppleAuthClient` is a *handle* to shared state — a JWKS cache plus the mutex that gives fetches against Apple their single-flight and cooldown/rate-limit behaviour. So it follows the `reqwest::Client` / `sqlx::Pool` convention: `Clone` is cheap and every clone points at the same state. `#[derive(Clone)]` is on the struct, but the shared fields are wrapped so the derive shares them.

A plain derive over unwrapped fields is rejected: it would give every clone its own JWKS snapshot and its own cooldown state. N clones would then mean N independent fetches against Apple, and the `VerificationConfig::cooldown_period` floor, which protects Apple's endpoint against a flood of fetches, would apply to each clone separately.

Rejected alternative: leave the type non-`Clone` and tell callers to hold an `Arc<AppleAuthClient>`. Workable, but it leaves the cheap wrong path — calling the constructor a second time — open, and that silently duplicates the cache and the rate limiter.

## Why `AppleTokenConfig` zeroizes on drop

`AppleTokenConfig::private_key_pem` holds Apple's `.p8` signing key — long-lived credential material. As a plain `Vec<u8>` its bytes were simply freed on drop and left readable in the freed allocation. The `EncodingKey` idunn derives from it in `AppleAuthClient::with_transport` already wipes itself — jsonwebtoken 11 puts `#[derive(Clone, Zeroize, ZeroizeOnDrop)]` on `EncodingKey` — which made idunn's own copy of the same secret the weaker link. `#[derive(ZeroizeOnDrop)]` on `AppleTokenConfig` closes that gap: all fields are wiped on drop (`team_id`/`key_id`/`client_id` aren't secret, but wiping them costs nothing and isn't worth a `#[zeroize(skip)]` each). `zeroize` is already in the build graph via jsonwebtoken, so this adds no new crate.

What it does **not** cover, and why the field doc says so:

- Copies the caller keeps are out of reach. The guarantee only holds if the caller moves the key `Vec` in; a clone off a config object it retains, or the PEM left in a `String` env var, is another copy.
- `Vec` zeroization is best-effort (documented as such in `zeroize`'s own source): it clears the current allocation's full capacity but can't chase down bytes an earlier reallocation left on the heap while the buffer was being built.

`AppleTokenConfig`'s `Debug` impl is hand-written: it prints the non-secret identifiers (`team_id`/`key_id`/`client_id`) in full but replaces `private_key_pem` with a `<N redacted bytes>` placeholder, so the key can't leak into a log line or panic message. The explicit impl keeps a later `#[derive(Debug)]` from silently reintroducing the leak: the two would conflict.

## Why identity verification and token exchange share one `client_id`

Verification's `aud` check and the client secret used in token exchange both take `AppleTokenConfig::client_id`. Apple's docs specify that an identity token's `aud` is always the developer's client_id — the same value the client secret needs — so a second, independently configurable identifier (say a `bundle_ids` slice) would only duplicate it and could silently drift out of sync.

## Why the HTTP transport is injectable

`exchange_authorization_code` and `verify_identity_token` (via `JwksStore`'s fetch of Apple's published keys) both talk to Apple over HTTP through the same `HttpTransport` trait (`src/transport.rs`), defaulted to a `reqwest`-backed `ReqwestTransport`. This is injected for two reasons:

- It keeps `idunn` swappable to a different HTTP stack (proxying, custom TLS, a differently configured client) without forking the crate.
- It makes both `exchange_authorization_code` and `JwksStore` unit-testable with a small in-memory fake implementing `HttpTransport`; no real network access or HTTP-mocking dependency is needed.

This abstraction covers every network call idunn makes, including the JWKS fetch — there's no third-party opacity left to carve out here.

`post_form`/`get` return a dedicated `TransportError` (network failure, or HTTP status + raw body): the transport is a generic HTTP abstraction and shouldn't need to know about idunn's Apple-specific error variants. The Apple-aware callers convert a `TransportError` into the operation-specific error type — `JwksStore`'s fetch into `VerificationError::CannotVerifyToken`, `exchange_authorization_code` into `TokenExchangeError`, `revoke_refresh_token` into `TokenRevocationError` — parsing Apple's error body along the way. `TransportError::Network` itself carries a boxed `dyn Error`, so a non-reqwest `HttpTransport` implementation can report its own underlying error type.

`HttpTransport`, `HttpGet`, `HttpPost`, `TransportError`, `VerificationConfig` and `NoncePolicy` are all re-exported from `lib.rs`. They have to be: `AppleAuthClient<T: HttpTransport>` is generic over its transport, so a downstream crate that stores one in a struct field must name a concrete `T` (`impl Trait` is not allowed there, and the RPITIT traits are not dyn-compatible), and `with_transport` takes a `VerificationConfig`.

`with_transport` takes one `VerificationConfig`: it configures a single operation — identity-token verification — and the JWKS cache exists only to serve that operation, so one struct expresses the whole decision. `VerificationConfig` holds the JWKS cache's timing fields; the nonce-presence policy lives on `AppleAuthClient`'s `N: NonceRequirement` type parameter — see "Why the nonce policy is a type parameter" below.

## Why `verify_identity_token` doesn't check the nonce itself

Apple's own verification checklist (see the comment in `IdentityVerificationClient::new`, `src/identity_verification.rs`) includes checking the token's `nonce` claim against whatever value the app generated for that authentication attempt. idunn deliberately stops short of that comparison: it requires knowing where and how the caller tracked the nonce it issued — a session row, a hashed lookup, an async store, an HMAC — which idunn has no generic way to perform. Instead, `verify_identity_token` returns the `nonce` claim as-is and leaves the value comparison to the caller.

Where the claim is returned is itself a deliberate choice. The nonce is **not** an `AppleIdentity` field: `AppleIdentity` carries verified identity attributes (`apple_user_id`, `email`, ...), and the nonce is not one — it is an unfinished verification step. Burying it among `email` / `apple_user_id` is exactly what let earlier callers treat a "successful" `verify_identity_token` as fully authenticated and never compare the value. So the nonce is hoisted to the top level of both result types — `IdentityWithPendingNonce { nonce, identity }` from `verify_identity_token`, `SignInDetails { nonce, refresh_token, identity }` from `exchange_authorization_code` — each with a doc comment that states the remaining obligation on the value the caller actually holds. This is the same "make the wrong path unreachable / put the obligation on the type" principle already used for `RefreshToken`'s redacting `Debug` (below) and the single-constructor design (above): the type's shape carries the message, where a buried field doc or an external checklist can be missed.

Rejected alternative: an `expected_nonce: &str` parameter on `verify_identity_token` that does a constant-time compare internally. It reads cleaner, but it hard-codes one strategy — synchronous plaintext equality against a value the caller already has in hand — and forecloses every other way a caller might have stored the nonce it issued (a hashed or async lookup, an HMAC, a session record keyed differently). Making the obligation structurally prominent without dictating how it is met keeps all of those open.

idunn does, however, enforce nonce *presence*, controlled by `NoncePolicy` (part of `VerificationConfig`):

- `NoncePolicy::Strict` (the default): a token with no `nonce` claim is always `InvalidToken`, regardless of the token's `nonce_supported` claim. This is stricter than what Apple's docs technically require, chosen so replay protection is never silently disabled by a claim idunn has no way to verify the integrity of.
- `NoncePolicy::Permissive`: follows the handling Apple's own docs suggest (<https://developer.apple.com/documentation/signinwithapplejs/authorizationi/id_token>, `nonce_supported`) — a missing nonce is tolerated (`nonce` is `None`) only when `nonce_supported` is `false` or absent; a `nonce_supported: true` claim still fails the token even under this policy, since Apple's guidance is to treat the nonce as mandatory in that case.

When `nonce` is `None` under `Permissive`, `AppleIdentity::issued_at`/`expiration` (from the token's `iat`/`exp` claims) are exposed so the caller can still build its own replay-detection window (e.g. dedupe on the token itself within that range).

The same `NoncePolicy` also governs the `id_token` `exchange_authorization_code` gets back from Apple's token endpoint (see the section below) — there is only one verification path.

## Why token exchange verifies the identity token itself

`exchange_authorization_code` does not hand Apple's token-endpoint response back as is. Returning the raw `id_token` would put the crate's own reason for existing at risk: idunn owns a conformant verifier (`verify_identity_token`), so exposing an unverified JWT invites exactly the mistake the crate is meant to prevent — a caller reading claims off a token whose signature, `iss`, `aud` and `exp` were never checked.

`exchange_authorization_code` runs `verify_identity_token` on the `id_token` before returning, and the public result is `SignInDetails { nonce: Option<String>, refresh_token, identity: AppleIdentity }` — no raw `id_token` field at all. It is defined in `lib.rs` so that `token_exchange.rs` needs no `identity_verification` import, keeping the two modules as disjoint as `verify_identity_token`'s own section above describes.

`access_token` and `expires_in` are dropped from the result entirely: idunn never uses the access token, and `expires_in` describes only that access token's lifetime.

**Consequence worth knowing:** because the exchange's `id_token` goes through the same `NoncePolicy`-governed check as `verify_identity_token`, an authorization flow that never sends a `nonce` in its authorize request will fail every `exchange_authorization_code` call under the default `NoncePolicy::Strict`. Such integrations need `NoncePolicy::Permissive`.

Rejected alternative: skip nonce-*presence* enforcement specifically on the exchange path, on the theory that this `id_token` arrives directly from Apple's token endpoint over TLS in response to the server's own POST, with no untrusted client in between — the replay threat `NoncePolicy` exists for (see above) isn't present here. Rejected in favor of one uniform verification rule with no config-dependent divergence in what "verified" means, at the cost of the consequence just described.

**Why verification failure carries the refresh token:** if the exchange succeeds but the `id_token` fails verification, Apple has already issued a live refresh token against a now-consumed authorization code. Returning a plain error and dropping that token would leave it un-revocable — in direct tension with Apple's mandatory account-deletion/revocation requirement (TN3194, see the top of `src/lib.rs`). `CodeExchangeError::ExchangedTokenUnverified { refresh_token, cause }` carries the token, so the caller can decide what to do with it: revoke a new authorization's token, retrying `revoke_refresh_token` until it succeeds, or drop a known user's refreshed token, since revoking it would end the stored authorization too (see "Why a refreshed token replaces the stored one and is never revoked" below). `AppleAuthClient::sign_up_or_log_in`, built on top of `exchange_authorization_code`, decides from `AccountState` itself (see "Why `sign_up_or_log_in` never revokes, and discards another user's token" below).

Every refresh token idunn hands back — success or error — is wrapped in `RefreshToken` (`src/token_exchange.rs`, next to `AppleTokenConfig` since both originate there). A plain `String` would print live credential material through a derived `Debug` wherever the value ends up, and errors in particular get `{:?}`-printed into logs, `anyhow` chains and `unwrap()` panic messages by convention. `RefreshToken` has a hand-written, redacting `Debug` (no `Display` either, for the same reason), so `SignInDetails::refresh_token` and `CodeExchangeError::ExchangedTokenUnverified`'s copy are both safely loggable by construction. The constructor is public only so a host can rebuild a stored token for `AccountState::AlreadyOnFile`. This mirrors 
`AppleTokenConfig`'s existing hand-written `Debug` for `private_key_pem`.

## Why the nonce policy is a type parameter

`AppleAuthClient::sign_up_or_log_in` compares a token's `nonce` claim against one fixed `expected_nonce`. Under `NoncePolicy::Permissive`, a token may legitimately carry no `nonce` claim at all (see the section above) — nothing to compare against. Silently treating that as a match would defeat replay protection for exactly the clients `Permissive` exists to admit; treating it as a mismatch would reject a token idunn itself accepted, under a misleading `NonceMismatch`.

`AppleAuthClient<T, N: NonceRequirement = Strict>` resolves this by making `sign_up_or_log_in` a method on `AppleAuthClient<T, Strict>` only — a `Permissive` client has no such method, a compile error, where either runtime branch would give a wrong answer. `N` is a marker type (`Strict`/`Permissive`, sealed so no other type can implement `NonceRequirement`) so that the compiler enforces this. `NonceRequirement::POLICY` reifies the marker back into a runtime `NoncePolicy` for `IdentityVerificationClient` to consume.

A `Permissive` client still signs in fine — through `sign_up_or_log_in_with_nonce_checker` with a checker that decides what a missing nonce means for its flow, exactly as `verify_identity_token` already leaves that decision to the caller under `NoncePolicy::Permissive` (see above). `sign_up_or_log_in` is the narrower, single-question convenience: does this claim equal that string.

This is a different axis from "Why `AppleAuthClient` is one client with one constructor" above: that section keeps every client able to revoke a token; this one narrows which sign-in *method* a client exposes; construction and revocation are unaffected. `with_transport`/`new` still build any `AppleAuthClient<T, N>` in one call, finished by one refresh-strategy call on the `AppleSeed<T, N>` they return (see "Why the JWKS refresh strategy is chosen at construction" below) — a `Permissive` client is `AppleAuthClient::<T, Permissive>::with_nonce_requirement(...)`, no separate constructor family.

## Why `sign_up_or_log_in` never revokes, and discards another user's token

`sign_up_or_log_in` layers nonce and Apple-user matching on top of `verify_identity_token` and `exchange_authorization_code`. Once the code is exchanged, a rejection leaves a live refresh token that `sign_up_or_log_in`'s caller never asked for and cannot use — and idunn itself never calls `revoke_refresh_token` on that token. Apple's `/auth/revoke` is authorization-scoped (see "Why a refreshed token replaces the stored one and is never revoked" below): revoking this token could tear down a concurrent sign-in for the same Apple user, minted by another process at the same time. Discovering that and coordinating around it needs a shared view of who's signing in and who's revoking right now — something only the host can provide, through `AppleAccounts`. See "Why revocations are coordinated by the host, through `AppleAccounts`" below for the rationale, and [The `AppleAccounts` contract](crate#the-appleaccounts-contract), for the obligations this places on the host.

Post-exchange rejection splits into two `SignInError` outcomes. When the exchanged `id_token` names a different Apple user than the caller's identity token — a stranger's authorization code paired with this identity token, possibly a stolen, single-use, short-lived code presented alongside someone else's stolen identity token — `sign_up_or_log_in` returns `SignInError::SubjectMismatch` and simply discards the token. It's never written to disk, so there's nothing an attacker could recover from it, and it belongs to an Apple user idunn's caller has no relationship with, so TN3194 imposes no obligation on it either. Revoking it would end that user's whole authorization of the app on the strength of a code the attacker could not have redeemed with their own client secret — exactly the capability an attacker wants and doesn't have. The subject is checked *before* the nonce for the same reason: a stolen code carries the thief's own nonce, and checking the nonce first would classify this case as an ordinary `NonceMismatch`, carrying the stranger's token back to the caller for revocation.

For a new authorization, every other post-exchange rejection (`PostExchangeRejection`: the exchanged `id_token` fails verification, or its nonce doesn't match) hands the token and the verified `AppleIdentity` from the caller's own identity token to the host's `schedule_revocation` hook as a `PendingRevocation`, awaits it, and returns `SignInError::RejectedAfterExchange(cause)` — mirroring `CodeExchangeError::ExchangedTokenUnverified` (see above) — the same obligation, now surfaced by `sign_up_or_log_in` before it ever reaches the caller. `identity` is the key the caller files the pending revocation under (`apple_user_id` is the JWT `sub`), needed because a caller that can't revoke immediately must persist the pending revocation and retry later, possibly across a process restart, and an opaque refresh token alone gives it no such key. Under `PostExchangeRejection::TokenUnverified` the exchanged token's owner could not be verified at all — in practice this means a JWKS outage during the exchange — so `identity` names the caller's sign-in attempt, and the token is treated as that caller's own for the purpose of the revocation obligation. This is a known, accepted residual risk: idunn cannot verify a token it cannot decode.

For a known user's refresh the same rejections drop the new token instead: it belongs to the authorization the stored token also belongs to, so revoking it would end that authorization (see "Why a refreshed token replaces the stored one and is never revoked" below).

Apple answering `invalid_grant` to a revoke call means Apple no longer recognizes the token as a usable grant, so what the call exists to guarantee — the token can't be used — already holds; `token_exchange::revoke_refresh_token` treats that answer as a successful revocation. As a consequence, a host retrying `revoke_refresh_token` for a token filed through `schedule_revocation` will eventually see that retry succeed. The arm is defensive: Apple's revoke documentation describes a 200 with an empty body even for a token that was already invalid, so `invalid_grant` may never actually arrive. A successful revoke response doesn't say whether anything was revoked either.

## Why every sign-in exchanges the authorization code

`AppleAccounts::lookup` runs after the identity token is verified and its nonce checked, but before `sign_up_or_log_in` touches Apple's token endpoint. It does not decide whether the authorization code is spent, since every sign-in spends it; it decides what the exchange means. `AccountState::NotOnFile` is a new authorization, and the result is `SignInOutcome::SignedUp`. `AccountState::AlreadyOnFile { refresh_token }` is a refresh of the stored token, and the result is `SignInOutcome::LoggedIn` with the new token.

The scenario that forces this: a user revokes the app in their Apple ID settings and signs in again. The stored token is dead, but the host only knows that a token is *stored*, and idunn cannot ask Apple whether it is alive without spending something. Had idunn skipped the exchange for a known user, the new authorization code would have expired unspent, and account deletion would later have revoked the dead token while the user's live authorization was never revoked (TN3194, App Store Review Guideline 5.1.1(v)). Exchanging every time makes the host's stored token follow the user's latest authorization without anyone detecting that a revocation happened.

Exchanging also acts as a de-facto single-use check: replaying a captured identity token fails once its code is spent. So `nonce_checker` is not the only replay defense, except on the fallback below.

**Fallback when Apple can't issue a new token for a known user.** Apple's `ErrorKind` decides:

- `Rejected` (Apple refused the code itself, e.g. `invalid_grant`, or the exchanged `id_token` fails verification) fails the sign-in. It is Apple's verdict on this sign-in's code; signing the user in with the stored token anyway would accept a code Apple says is bad.
- `Unavailable` and `Misconfigured` say nothing against the user, so idunn logs the error (`warn` and `error` level) and returns `LoggedIn` with the *stored* token. A verified, nonce-checked identity token already authenticates the user; an Apple outage or an operator's configuration mistake shouldn't lock every known user out. For a new user there is nothing to fall back to, so every failure fails the sign-in.
- A nonce mismatch on the exchanged `id_token` fails the sign-in either way.

The fallback hands the stored token back inside `LoggedIn`, so the host has one code path for a known user: write `refresh_token` next to the user. Writing back the stored token is a no-op. A separate variant for "nothing new was issued" would make the host tell two cases apart that it handles identically.

**Residual risk.** On the fallback nothing is spent, so `nonce_checker` is again the only replay defense for that sign-in. This lands hardest on a `Permissive` client whose checker is lax: `nonce_checker` must be effectively single-use.

**Rejected alternative: a storage hook idunn calls to write the token.** The host may want to do more in the same transaction as the token write (saving the user, say), which idunn cannot see. idunn decides what to store and what to do on failure; the host performs the write and its own error handling.

## Why a refreshed token replaces the stored one and is never revoked

Apple's `/auth/revoke` is authorization-scoped: Apple's documentation describes a revoke as invalidating the tokens and the user authorizations they belong to. The stored token and the one a refresh issues normally belong to the same authorization, so revoking either would end the other too, and with it the user's sign-in to the app at Apple. Hence the rules for a known user:

- The host overwrites the stored token with the refreshed one and drops the old one. One token per user remains; no list of old tokens is kept.
- If the host fails to write the refreshed (or handed-back) token, it drops it and never schedules it for revocation. The stored authorization stays intact.
- If idunn rejects the exchange after the fact (the exchanged nonce mismatches, or the exchanged `id_token` fails verification), it drops the new token and does not call `schedule_revocation`. Whether the sign-in then fails or falls back follows the `ErrorKind` rules above.

A *new* authorization is the opposite case: its token is the only handle on an authorization the host failed to record, so a failed store or a post-exchange rejection files it for revocation (see "Why a post-exchange rejection goes through `schedule_revocation`"). Revocation stays reserved for an explicit caller decision (account deletion, an aborted signup) and for tokens of authorizations nobody else holds. See "Why `sign_up_or_log_in` never revokes, and discards another user's token" above for the post-exchange token handling.

**Accepted risk: token independence.** Apple doesn't document whether revoking one refresh token also invalidates the other tokens of the same user and `client_id`; the question is [open and unanswered on Apple's forums](https://developer.apple.com/forums/thread/844628). Indirect evidence supports the "whole authorization" model above:

- The [revoke documentation](https://developer.apple.com/documentation/signinwithapplerestapi/revoke-tokens) says the call invalidates the tokens and the user authorizations associated with them.
- A [developer report](https://developer.apple.com/forums/profile/zangw/replies) says that after a successful revoke the app disappears from the user's "Apps Using Apple ID" list.
- A [DTS post](https://developer.apple.com/forums/thread/708415) treats a revoke as equivalent to a manual revocation, after which a `credentialRevokedNotification` or `consent-revoked` notification follows.
- After a [manual revocation](https://developer.apple.com/forums/thread/123909), validating the refresh token fails with a 400.

If the tokens are independent after all, the revoke at account deletion only invalidates the latest token, and the app may stay in the user's list. We accept that risk deliberately, to avoid storing an unbounded list of tokens. A related assumption is unverified too: that the Apple user id (`sub`) is stable across a revoke and re-authorization, which the host's token row is keyed on. A manual sandbox test with a real device checks both.

**Known limitation, unsolved here:** nothing in idunn prevents a caller's own `revoke_refresh_token` call from racing a concurrent `sign_up_or_log_in` for the same Apple user. Since revoke is authorization-scoped, such a race could revoke a token the concurrent sign-in is in the middle of minting. This is a property of `revoke_refresh_token`'s semantics; `sign_up_or_log_in` adds nothing to it. On the host side, the per-user serialization described in [The `AppleAccounts` contract](crate#the-appleaccounts-contract) (obligation 4), is the mitigation.

## Why revocations are coordinated by the host, through `AppleAccounts`

idunn has no persistence layer and no view of concurrent sign-ins or revocations — it sees one call at a time. Only the host, which stores the refresh tokens and can see every in-flight request, is in a position to coordinate them. `AppleAccounts::lookup` is the hook that carries this coordination: the obligations it places on the host are documented in [The `AppleAccounts` contract](crate#the-appleaccounts-contract); this section covers only why they belong there.

`AppleAccounts::lookup` is the only point in `sign_up_or_log_in` that runs with a verified Apple `sub` *before* the authorization code is spent. Knowing the `sub` this early is what makes a pending revocation for that `sub` cancellable in time, before any new token is minted. It also runs *after* the nonce check, so an unauthenticated request replaying a stolen identity token can't reach it and cancel a revocation it has no right to cancel.

Cancelling a pending revocation is correct for whichever legitimate sign-in by the same user happens to run next, because revoke is authorization-scoped: see "Why a refreshed token replaces the stored one and is never revoked" above. A revoke that later succeeded anyway would tear down the very session `lookup` just let through.

The obligations this implies — a durable outbox and per-user serialization — follow from two failure modes idunn itself cannot see. A revoke call can fail (an Apple-side outage) and must still be retried after a process restart, so the pending job has to survive on disk across that restart. And a revocation worker retrying that call can race a brand-new sign-in for the same user, which is exactly what the serialization requirement stops: a worker's revoke colliding with a concurrent `lookup`/exchange for the same `apple_user_id`.

## Why the nonce checker is `FnOnce(Option<String>) -> Fut`

`sign_up_or_log_in_with_nonce_checker`'s `nonce_checker` parameter looks like a natural fit for `AsyncFn(Option<&str>) -> Result<bool, A::Error>` — it's called, awaited, and nothing about its job looks like it needs an owned `String` or a named future type.

However, `AsyncFn` bounds desugar through an associated `CallRefFuture<'a>` GAT, parameterized by the closure's own self-borrow — `fn async_call(&self, args) -> Self::CallRefFuture<'_>` ties the returned future's type to however long that particular call borrows the closure. Proving `sign_up_or_log_in_with_nonce_checker`'s opaque future `Send` then needs `for<'a> F::CallRefFuture<'a>: Send` — a higher-ranked, unstable GAT bound that cannot be written on stable and that rustc will not discharge through the binder. This holds even with an owned `Option<String>` argument: switching only the argument off `&str` still produces the same "implementation of `Send` is not general enough" error, so the self-borrow is what needs removing. That error is a higher-ranked-region error, and it lands wherever `Send` is first *demanded*: nothing in idunn's own code requires `sign_up_or_log_in_with_nonce_checker`'s future to be `Send`, so a downstream caller with a `Send`-bound API (an axum route registered via `post(handler)`, a multi-threaded-runtime `tokio::spawn`) is typically the first place the obligation becomes visible, as an opaque error pointing at its own call site.

`FnOnce(Option<String>) -> Fut` with `Fut: Future<Output = Result<bool, A::Error>> + Send` removes the GAT and the binder entirely. `Send` becomes an ordinary where-clause obligation on the caller-supplied `Fut`, discharged locally when `sign_up_or_log_in_with_nonce_checker` is called — a non-`Send` checker fails at its own call site inside idunn. The cost: callers write `|candidate| async move { .. }`, and the claim arrives as an owned `Option<String>`, one clone out of `IdentityWithPendingNonce`.

Only `nonce_checker` keeps the `FnOnce` shape: `sign_up_or_log_in_with_nonce_checker` calls it at most once per sign-in attempt, and it depends on per-request state. The two storage hooks are `AppleAccounts` methods (see "Why the account hooks are one `AppleAccounts` trait"), whose `-> impl Future + Send` is declared in the trait. That `Send` is an item bound on the opaque future for every lifetime of `&self`, so there is no unbounded `CallRefFuture<'a>`-style GAT for `Send` to get stuck behind, and a non-`Send` implementation fails at the host's own `impl`.

## Why the exchanged nonce is compared against the identity token's

`nonce_checker` is `FnOnce`, called once against the identity token — see above. A checker that consumes a pending nonce (single-use, e.g. removing it from a store) would reject every sign-in if called a second time for the exchanged `id_token`, so `sign_up_or_log_in_with_nonce_checker` does not call it again. Instead it compares the exchanged token's `nonce` against the identity token's already-accepted one with `nonce_eq`.

This is sound because both tokens come from the same authorization: Apple's token endpoint returns the `id_token` for the very authorization the identity token also came from, so a legitimate exchange carries the same nonce. For any checker that decides `Ok(true)`/`Ok(false)` purely from the claim's value, equality with the value `nonce_checker` already accepted is at least as strict as running that same checker again — a checker that accepted the identity token's nonce cannot turn around and reject an identical value.

Under `NoncePolicy::Permissive`, the identity token's nonce may be `None`. Two absent nonces still match: neither token was expected to carry one. An absent identity-token nonce paired with a present exchanged-token nonce is a mismatch — nothing was accepted to compare it against.

## Why the email claims are one struct and the flags aren't optional

Apple's `id_token` carries `email_verified` and `is_private_email` alongside `email`
(<https://developer.apple.com/documentation/signinwithapplejs/authorizationi/id_token>), but neither
flag means anything without an address to qualify. `AppleIdentity::email` is therefore
`Option<AppleEmail>` — one optional struct gated on whether the token carried an `email` claim at
all. Three independently optional fields on `AppleIdentity` could be combined
into a nonsensical state (a `verified: true` with no address).

Inside `AppleEmail`, `verified` and `is_private` are plain `bool`s, despite both
source claims being optional on the wire:

- `verified` defaults to `false` when `email_verified` is absent. Apple's own docs already document
  the absent case as equivalent to a `false` value (Sign in with Apple at Work & School), so there is
  no distinct "unknown" state worth preserving — `Option<bool>` would just push a meaningless
  three-way match onto every caller.
- `is_private` defaults to checking whether the address ends with `@privaterelay.appleid.com` or
  `@private.icloud.com` when `is_private_email` is absent. Apple's private relay domains are known,
  stable strings, so this fallback gives callers a real answer when the claim wasn't sent (token
  issuers other than current Apple SDKs, or historical tokens). The claim, when present, always wins
  over the heuristic in both directions: an explicit `false` on a relay-looking address is trusted
  over the domain guess, and vice versa. The heuristic only fires on absence.

`real_user_status` (`ASUserDetectionStatus`) is modeled as `Option<RealUserStatus>`, an enum with
`Unsupported`/`Unknown`/`LikelyReal`. `None` is Apple
"didn't tell us this time" — it covers both an absent claim (the signal isn't sent for web-based apps
or below iOS 14 / macOS 11) and a value idunn doesn't recognize. Folding an unrecognized value into
`None` follows the same reasoning `AppleIdentity::real_user_status`'s own
doc gives for absence: an unrecognized fraud signal can't be interpreted, so the conservative read is
to treat it the same as no signal at all, since a surfaced value could be mistaken for one
of the three Apple currently documents.

## Why the JWKS refresh strategy is chosen at construction

A constructor that returned a usable client directly, with `keystore_refresh_loop`/`with_background_refresh` as an optional chained call, would make forgetting the refresh silent: `JwksStore::get_key` (`src/jwks_store.rs`) fetches lazily, so verification stays correct, but the cold-cache fetch and every subsequent `refresh_interval` land on whichever request happens to trigger it — a latency regression with no compiler or runtime signal. That shape makes the forgetful path the shortest one to write.

`AppleAuthClient::new`/`with_transport`/`with_nonce_requirement` return an `AppleSeed<T, N>` (`src/lib.rs`) — a client cannot be obtained without going through it. `AppleSeed` exposes none of `verify_identity_token`, `sign_up_or_log_in`/`sign_up_or_log_in_with_nonce_checker`, `exchange_authorization_code`, `revoke_refresh_token`, or `refresh_keystore`; an `AppleAuthClient` only exists after calling one of `AppleSeed::with_background_refresh` (`tokio-refresh` feature), `AppleSeed::with_refresh_loop` (any executor, via a caller-supplied `sleep`), or the explicitly named `AppleSeed::without_background_refresh` — that absence of any other client-shaped API is the compile-time enforcement. The opt-out exists, and naming it explicitly keeps the choice visible in a diff or code review; forgetting it is a compile error.

Rejected alternatives:
- **Returning `(AppleAuthClient, refresher)` from the constructor.** A caller who writes `let (client, _) = AppleAuthClient::new(...)?;` still silently discards the refresher — `#[must_use]` on the tuple element doesn't catch a `_` pattern binding it away.
- **Spawning implicitly from `new()` via `Handle::try_current()`.** Conflicts with the `Handle` paragraph below: idunn's constructors are plain, non-async functions precisely so they can run before any runtime exists (a `OnceLock` initializer, `lazy_static`, etc.) — an implicit spawn would either panic in exactly that case or silently do nothing, depending on how the `try_current()` failure is handled.
- **Making `new()`'s signature vary with the `tokio-refresh` feature.** Breaks feature additivity: enabling a feature should only add API surface, never change an existing signature depending on which other features happen to be enabled.

Two design choices fall out of the split between `AppleSeed`'s methods and the loop they share:

**The refresh task ends on its own.** The loop holds only a weak reference to the state every `AppleAuthClient` clone shares, so it returns on its next tick after the last clone is dropped. There is nothing for the caller to cancel.

**`AppleSeed::with_background_refresh` takes a `tokio::runtime::Handle` as a parameter; it never spawns implicitly during construction.** `tokio::spawn` panics outside a running runtime, but `AppleAuthClient::new`/`with_transport` stay plain, non-async functions — exactly the kind reasonably called from a `OnceLock` initializer, a `lazy_static`, or other setup that runs before any runtime is entered. Requiring a `Handle` puts that runtime requirement in the signature, where a caller sees it before it can panic at runtime. `Handle::spawn` also works from outside a runtime context, unlike the bare `tokio::spawn` free function, which needs a runtime already entered on the calling thread — passing the handle explicitly is strictly more flexible.

The loop never sleeps less than one second, so a zero `cooldown_period` and a persistent fetch failure cannot busy-loop against Apple's endpoint.

## Why the error enums are exhaustive

None of idunn's public error enums is `#[non_exhaustive]`. A new variant here is usually a new failure mode the host has to make a decision about: whether a live refresh token is left behind, which HTTP status it maps to, whether to alert on it. A mandatory wildcard arm would make that decision silently, with no one having looked at the new case. Without `#[non_exhaustive]`, a host can match exhaustively where the distinction matters, and a variant added later fails to compile there until someone classifies it. Where every value gets the same treatment, such as the `AppleErrorCode` inside `TokenExchangeFailed`, the host can still bind it whole. The price is that every added variant is a breaking change and bumps the version accordingly.

`SignInError::kind()` and `TokenRevocationError::kind()` signify what a new variant costs a host. idunn classifies every variant as an `ErrorKind` — `Rejected`, `Unavailable` or `Misconfigured` — so a host that only maps `kind()` keeps compiling when a variant is added; only a new kind breaks its `match`. That is a deliberate tradeoff, the same one `std::io::Error::kind` makes: for such a host, the classification of a new failure mode is idunn's judgment, taken on the host's behalf. A host that wants to review every new failure mode itself matches the variants and still gets the compile error described above. `ErrorKind` is exhaustive for the same reason as the error enums: a new kind is a new decision for the host. idunn's own classification has no wildcard either: each `kind()` and the private per-payload helpers behind it match exhaustively, so a variant can't be added without being classified.

Both operations share one `ErrorKind`, the way every `std::io` operation shares `io::ErrorKind`: on either path the kinds mean the same — Apple refused this request, Apple couldn't be reached, or this app's configuration is wrong — and so does an `AppleErrorCode`, which one private helper classifies for both. What differs is the consequence (an HTTP answer for sign-in, an alert or a retry for a revocation worker), so each `kind()` documents its own. `invalid_grant` is no exception: `revoke_refresh_token` reports it as `Ok(())` before any error exists, so on the revoke path its `Rejected` is never reached. The cost is coupling: a kind only one operation needs would still break a host's `match` on the other.

## Why sign-in returns the host's own error type

Boxing the hooks' errors would force every host to `map_err` into a box on the way in and `downcast` back out; `SignInError<LookupErr, NonceErr>` has no box but keeps the round trip. Every host's `From` would take `AccountLookupFailed(e)` / `NonceCheckFailed(e)` apart to rebuild its own error from errors that were its own to begin with, and a `kind()` over that enum would need a `Host` kind that classifies nothing idunn knows about.

The sqlx pattern (`Connection::transaction`, `E: From<sqlx::Error>`) avoids both: `sign_up_or_log_in` returns the host's `AppleAccounts::Error`. Hook errors pass through with a plain `?`; idunn's own failures are converted exactly once, by the host's `From<SignInError>`. `SignInError` has no type parameters. `nonce_checker` shares `A::Error` since the host's own type has room for both stores' failures.

The bound `From<SignInError> + std::error::Error + Send + Sync + 'static` sits on `AppleAccounts::Error` only, so a wrong type fails at the host's `impl`. `SignInError` itself must be `Send + Sync + 'static`, since hosts embed it.

Costs: the host writes the `From`; `anyhow::Error` and `Box<dyn Error>` need a wrapper because neither implements `std::error::Error`; and `SignInError` has to stay small, since every host's error embeds it. Rejected: keeping the generics and adding a `Host` kind (needs an `unreachable!` in the host); a two-level `SignInError` with an inner idunn-only enum (confusing naming, since all of it is the Apple sign-in).

## Why a post-exchange rejection goes through `schedule_revocation`

Carrying the live token in an ordinary error variant would make losing it the default — `?` or a catch-all arm drops it with no compile error and no log, breaking TN3194. Exhaustive enums don't help, since `?` matches nothing. The only safe host would be one that happened to match that variant first.

idunn hands the `PendingRevocation` to the host's `AppleAccounts::schedule_revocation` itself and awaits it before returning. `SignInError::RejectedAfterExchange` carries only the `PostExchangeRejection`, so there's no token left in the error to drop. Host error handling is ordinary: `?` plus a `match` over `SignInOutcome`. idunn never calls `revoke_refresh_token` here — `schedule_revocation` *files* the token; the host's worker revokes it under the serialization described in "Why revocations are coordinated by the host, through `AppleAccounts`".

Why `()`: the token has already moved into the hook by the time it could fail to be filed. Returning it in an error on failure would reintroduce the lost-token problem above, so the hook owns its own failure (log/alert).

Why the cause rides in both places: the hook needs it to record why a token was filed; the caller needs it to answer the request correctly (`SignInError::kind()` tells a JWKS outage, `TokenUnverified(CannotVerifyToken)`, apart from an actual token rejection). That's why `PostExchangeRejection`, `VerificationError` and `InvalidTokenCause` are `Clone` — the one clone happens only on this path.

Why `grace_period` is a fixed field: the host shouldn't have to reinvent "how long is safe to wait" — idunn already knows the answer that makes `AppleAccounts::lookup`'s cancellation window work ([The `AppleAccounts` contract](crate#the-appleaccounts-contract), obligation 3), so it hands it over as data (`PendingRevocation::grace_period`); prose documentation would rely on every host reading it. `REVOCATION_GRACE_PERIOD` (5 minutes) is not configurable.

Shape: `AppleAccounts::schedule_revocation`, a trait method next to `lookup` — see "Why the account hooks are one `AppleAccounts` trait".

Limits: the hook runs inside the caller's own future — if that future is dropped mid-hook (e.g. a framework cancelling a handler on client disconnect), the token can still be lost, as with any `.await` the host runs inline in its handler. `exchange_authorization_code`, the explicit low-level path with no hooks, is unaffected and still returns the token via `CodeExchangeError::ExchangedTokenUnverified`. Rejected alternative: a cause-less unit variant, which would lose the outage-vs-rejection distinction `SignInError::kind()` makes.

## Why the account hooks are one `AppleAccounts` trait

Both hooks are the host's storage and share one contract ([The `AppleAccounts` contract](crate#the-appleaccounts-contract)), so one named type holds both. One trait needs one type parameter where closures would need four (`L, LFut, Q, QFut`), lets implementors write `async fn`, and lets the host pass a long-lived `&accounts`; two closures would need a pool cloned into each on every request.

`nonce_checker` stays a closure: it depends on per-request state (the expected nonce). Rejected: a nonce method on the trait, which would force per-request state into a type meant to live as long as the application.

`AppleAccounts: Sync` and the `&A` parameter go together. `sign_up_or_log_in`'s future holds `&A` across awaits, so its `Send`-ness needs `A: Sync`; with the supertrait, a non-`Sync` implementation fails at its own `impl`; without the supertrait the error would surface at a downstream axum route. `lookup` takes `&AppleIdentity` because the trait method only reads it; an owned parameter would force a clone.

The trait is not dyn-compatible, because its methods return `impl Future` (RPITIT). That is accepted: idunn only needs a generic `A`, and a host that wants a trait object can wrap its own storage behind whatever it likes.

## Why exactly one crypto backend is enforced at compile time

`jsonwebtoken`'s `aws_lc_rs` and `rust_crypto` features are mutually exclusive `CryptoProvider` backends: with both enabled, or neither, `jsonwebtoken` has no way to pick one, and only notices at first use — verifying or signing a token panics with "Could not automatically determine the process-level CryptoProvider". `cargo check` and `cargo clippy` don't catch this, since compiling idunn's own code never calls into jsonwebtoken's provider lookup.

Two `#[cfg(...)] compile_error!` guards in `src/lib.rs` — one for `all(aws_lc_rs, rust_crypto)`, one for `not(any(aws_lc_rs, rust_crypto))` — turn a bad feature selection into a compile error naming the problem; without them it would be a runtime panic three layers removed from the flags that caused it. This also catches a mistake idunn's own build can't see: `features = ["rust_crypto"]` without `default-features = false` quietly keeps `aws_lc_rs` on too via idunn's own `default`, which otherwise only fails the first time a caller actually verifies or signs a token.

Rejected alternative: leave both-or-neither buildable, so a caller could supply their own provider via `jsonwebtoken::crypto::CryptoProvider::install_default()` from their own `main` before touching idunn — idunn itself never calls `install_default`, so nothing about idunn's own code depends on which backend wins. That setup works but is fragile; the guard forecloses it: there is no way to build idunn with neither backend feature enabled, bring-your-own-provider or not. If idunn ever needs to support that, the `not(any(...))` half of the guard is the one to loosen. The guard also only sees idunn's own feature unification: it can't catch another crate elsewhere in the dependency graph enabling `jsonwebtoken/rust_crypto` directly (bypassing idunn's own `rust_crypto` feature) alongside idunn's `aws_lc_rs` — that combination still compiles and still panics at runtime.
