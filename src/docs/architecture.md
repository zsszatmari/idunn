How idunn's parts fit together, how a sign-in runs, and why the API has the shape it has, with the alternatives that were rejected.

## Overview

idunn gives a server three Sign in with Apple operations:

- [`verify_identity_token`](crate::AppleAuthClient::verify_identity_token) checks an identity token's signature against Apple's published keys (JWKS), its `iss`, `aud` and `exp`, and whether it carries a `nonce`.
- [`exchange_authorization_code`](crate::AppleAuthClient::exchange_authorization_code) trades an authorization code for a refresh token and verifies the `id_token` Apple returns with it.
- [`revoke_refresh_token`](crate::AppleAuthClient::revoke_refresh_token) revokes a refresh token, for account deletion.

[`sign_up_or_log_in`](crate::AppleAuthClient::sign_up_or_log_in) composes the first two into a complete sign-in. idunn has no persistence: refresh tokens, accounts and pending revocations live in the host's storage, which idunn reaches through the [`AppleAccounts`](crate::AppleAccounts) trait. The only state idunn keeps is its cache of Apple's keys.

### Components

[`AppleAuthClient`](crate::AppleAuthClient) is a cheap handle over three parts: identity verification (`IdentityVerificationClient`, backed by the key cache `JwksStore`), the `Credentials` that sign Apple client secrets, and the HTTP transport. Its clones share one key cache. Every constructor returns an [`AppleSeed`](crate::AppleSeed), which becomes an [`AppleAuthClient`](crate::AppleAuthClient) once the host chooses how the key cache is refreshed.

- `lib.rs`: [`AppleAuthClient`](crate::AppleAuthClient), [`AppleSeed`](crate::AppleSeed), [`AppleAccounts`](crate::AppleAccounts) and the sign-in flow.
- `identity_verification.rs`: JWT verification and its result types, [`AppleIdentity`](crate::AppleIdentity) and [`IdentityWithPendingNonce`](crate::IdentityWithPendingNonce).
- `jwks_store.rs`: Apple's published keys, fetched one request at a time and rate-limited by a cooldown.
- `token_exchange.rs`: the exchange and revoke calls, client-secret signing, [`AppleTokenConfig`](crate::AppleTokenConfig) and [`RefreshToken`](crate::RefreshToken).
- `transport.rs`: [`HttpTransport`](crate::HttpTransport), which carries every HTTP call, and its default [`ReqwestTransport`](crate::ReqwestTransport).
- `config.rs`: [`VerificationConfig`](crate::VerificationConfig) (the key cache's timings) and the nonce-policy types.
- `error.rs`: the error types, [`ErrorKind`](crate::ErrorKind) and [`PendingRevocation`](crate::PendingRevocation).

### A sign-in, step by step

[`sign_up_or_log_in_with_nonce_checker`](crate::AppleAuthClient::sign_up_or_log_in_with_nonce_checker) runs these steps. [`sign_up_or_log_in`](crate::AppleAuthClient::sign_up_or_log_in) is the same with a checker that compares the nonce against one `expected_nonce`.

1. Verify the identity token from the app. Failure: [`IdentityTokenRejected`](crate::SignInError::IdentityTokenRejected).
2. Check its nonce with `nonce_checker`. Failure: [`NonceMismatch`](crate::SignInError::NonceMismatch).
3. [`accounts.lookup`](crate::AppleAccounts::lookup) reports whether a refresh token is stored for this Apple user: [`AlreadyOnFile`](crate::AccountState::AlreadyOnFile) for a known user, [`NotOnFile`](crate::AccountState::NotOnFile) for a new authorization.
4. Exchange the authorization code at Apple's token endpoint, on every sign-in. Failure: [`Exchange`](crate::SignInError::Exchange).
5. Verify the `id_token` the exchange returned, by the same rules as step 1. Failure: [`RejectedAfterExchange`](crate::SignInError::RejectedAfterExchange).
6. Check that both tokens name the same Apple user. Failure: [`SubjectMismatch`](crate::SignInError::SubjectMismatch).
7. Compare the exchanged token's nonce with the one step 2 accepted. Failure: [`RejectedAfterExchange`](crate::SignInError::RejectedAfterExchange).
8. Return [`SignedUp`](crate::SignInOutcome::SignedUp) for a new authorization or [`LoggedIn`](crate::SignInOutcome::LoggedIn) for a known user, each with the new refresh token.

Once step 4 succeeds, Apple has issued a live refresh token, and idunn never revokes it during a sign-in. After a failure at step 5 or 7, a new authorization's token goes to [`accounts.schedule_revocation`](crate::AppleAccounts::schedule_revocation) and a known user's is dropped. After step 6 the token belongs to a stranger and is discarded.

A known user still signs in when Apple can't issue or verify a new token for a reason that says nothing against the user: an [`Unavailable`](crate::ErrorKind::Unavailable) or [`Misconfigured`](crate::ErrorKind::Misconfigured) exchange failure at step 4, or Apple's keys being unreachable at step 5. idunn logs the failure and returns [`LoggedIn`](crate::SignInOutcome::LoggedIn) with the stored token.

The host's side of this flow is in [The `AppleAccounts` contract](crate#the-appleaccounts-contract).

### Two Apple rules

Most of the design follows from two rules of Apple's:

- **Revocation is mandatory.** An app that lets users create an account must let them delete it, and deleting it revokes their Sign in with Apple tokens ([TN3194](https://developer.apple.com/documentation/technotes/tn3194-handling-account-deletions-and-revoking-tokens-for-sign-in-with-apple), App Store Review Guideline 5.1.1(v)). So every client can revoke, and a new authorization's refresh token always reaches the host's storage or its revocation queue.
- **Revocation is authorization-scoped.** Apple describes `/auth/revoke` as invalidating the token and the user authorization it belongs to. idunn treats a revoke as ending every token of that authorization; Apple doesn't confirm this outright ([Revocation is authorization-scoped](#revocation-is-authorization-scoped) has the evidence). A revoke during a sign-in could then end the user's stored authorization or a concurrent sign-in, so idunn never revokes during a sign-in, and the host coordinates revocations.

One principle runs through the API: the developers made the correct use the shortest one to write. Where the compiler can rule a mistake out, it does (one constructor, [`AppleSeed`](crate::AppleSeed), the nonce policy as a type parameter). Where it can't, the obligation sits on the type the caller holds ([`IdentityWithPendingNonce`](crate::IdentityWithPendingNonce), [`PendingRevocation`](crate::PendingRevocation)).

## Constructing a client

### One client, one constructor

Verification needs only the app's [`client_id`](crate::AppleTokenConfig::client_id). The exchange and the revoke also sign a client secret with [`team_id`](crate::AppleTokenConfig::team_id), [`key_id`](crate::AppleTokenConfig::key_id) and Apple's `.p8` private key, and a revoke needs the refresh token the exchange returned. With separate client types, a host could wire up a sign-in that works and can never revoke a token, unable to meet Apple's revocation requirement. One [`AppleAuthClient`](crate::AppleAuthClient), with one constructor that takes every credential, makes that state unreachable.

Both operations take the same [`AppleTokenConfig::client_id`](crate::AppleTokenConfig::client_id). An identity token's `aud` is the developer's client ID, the value the client secret needs. A second identifier, say a `bundle_ids` slice, would duplicate it and could drift out of sync.

### JWKS refresh strategy

`JwksStore` fetches Apple's keys lazily. Without a background refresh, the cold-cache fetch and each fetch after [`refresh_interval`](crate::VerificationConfig::refresh_interval) land on whichever request triggers them, a latency cost that nothing signals. An optional refresh call would make forgetting it the shortest path.

So every constructor returns an [`AppleSeed`](crate::AppleSeed), which has none of the client's methods. One of three calls turns it into an [`AppleAuthClient`](crate::AppleAuthClient):

- [`with_background_refresh(handle)`](crate::AppleSeed::with_background_refresh) (feature `tokio-refresh`) spawns the refresh loop onto a Tokio runtime.
- [`with_refresh_loop(sleep)`](crate::AppleSeed::with_refresh_loop) returns the loop as a future for any executor. `sleep` is the caller's timer, so idunn depends on no runtime, and the Tokio convenience sits behind its own feature.
- [`without_background_refresh()`](crate::AppleSeed::without_background_refresh) opts out, visibly in a diff or a review.

The constructors are plain functions, callable before any runtime exists (in a `OnceLock` initializer, say). [`tokio::spawn`] panics on a thread outside a runtime, and [`Handle::spawn`](tokio::runtime::Handle::spawn) works on any thread, so [`with_background_refresh`](crate::AppleSeed::with_background_refresh) takes a [`Handle`](tokio::runtime::Handle), and the runtime requirement shows in its signature.

The loop holds only a weak reference to the clients' shared state, so it ends on its next tick after the last clone is dropped, and there is nothing to cancel. It never sleeps less than one second, so a zero [`cooldown_period`](crate::VerificationConfig::cooldown_period) and a persistent fetch failure can't busy-loop against Apple.

Rejected:

- Returning [`(AppleAuthClient, refresher)`](crate::AppleAuthClient) from the constructor. `let (client, _) = ...` discards the refresher, and `#[must_use]` doesn't catch a `_` binding.
- Spawning implicitly in [`new()`](crate::AppleAuthClient::new) through [`Handle::try_current()`](tokio::runtime::Handle::try_current). Outside a runtime it would panic or silently skip the refresh.
- A [`new()`](crate::AppleAuthClient::new) whose signature depends on the `tokio-refresh` feature. That breaks feature additivity.

### Clones share one cache

[`AppleAuthClient`](crate::AppleAuthClient) follows the [`reqwest::Client`] and `sqlx::Pool` convention: cloning is cheap, and every clone shares one JWKS cache and the mutex that makes fetches single-flight and rate-limited. With a cache per clone, N clones would make N independent fetches against Apple, and the [`VerificationConfig::cooldown_period`](crate::VerificationConfig::cooldown_period) floor, which protects Apple's endpoint from a flood of fetches, would apply per clone.

Rejected: a non-[`Clone`] client that callers wrap in [`Arc<AppleAuthClient>`](std::sync::Arc). Calling the constructor again would stay the cheap wrong path, and each call duplicates the cache and the rate limit.

## Verifying identity tokens

### Nonce checks

Apple's verification checklist includes comparing the token's `nonce` with the value the app generated for that sign-in. The caller may keep that value in a session row, a hashed lookup, an async store or an HMAC, so idunn can't compare it generically: [`verify_identity_token`](crate::AppleAuthClient::verify_identity_token) returns the claim and leaves the comparison to the caller.

The nonce is a top-level field of [`IdentityWithPendingNonce`](crate::IdentityWithPendingNonce) and [`SignInDetails`](crate::SignInDetails), documented with the obligation that remains. Inside [`AppleIdentity`](crate::AppleIdentity), among verified attributes such as [`email`](crate::AppleIdentity::email), it would let a caller mistake a successful verification for a complete one.

Rejected: an `expected_nonce: &str` parameter on [`verify_identity_token`](crate::AppleAuthClient::verify_identity_token). It would hard-code synchronous equality with a value in hand and rule out every other way of storing the nonce. [`sign_up_or_log_in`](crate::AppleAuthClient::sign_up_or_log_in) offers that comparison as one option.

idunn does enforce the nonce's presence, by the client's [`NoncePolicy`](crate::NoncePolicy):

- [`Strict`](crate::NoncePolicy::Strict), the default: a token without a `nonce` claim is [`InvalidToken`](crate::VerificationError::InvalidToken), whatever its `nonce_supported` claim says. This is stricter than Apple requires, chosen so that a claim idunn has no way to verify never turns replay protection off.
- [`Permissive`](crate::NoncePolicy::Permissive), Apple's suggested handling: a missing nonce passes ([`nonce`](crate::IdentityWithPendingNonce::nonce) is `None`) only when `nonce_supported` is `false` or absent.

Without a nonce, [`AppleIdentity::issued_at`](crate::AppleIdentity::issued_at) and [`expiration`](crate::AppleIdentity::expiration) let the caller build its own replay window.

### Nonce policy as a type parameter

[`sign_up_or_log_in`](crate::AppleAuthClient::sign_up_or_log_in) compares the nonce claim against one `expected_nonce`, and under [`Permissive`](crate::NoncePolicy::Permissive) a token may carry none. Neither answer is right then: a match would turn off replay protection for exactly the clients [`Permissive`](crate::NoncePolicy::Permissive) admits, and a mismatch would reject a token idunn accepted, as a misleading [`NonceMismatch`](crate::SignInError::NonceMismatch).

So the policy is a type parameter, [`AppleAuthClient<T, N: NonceRequirement = Strict>`](crate::AppleAuthClient), and [`sign_up_or_log_in`](crate::AppleAuthClient::sign_up_or_log_in) exists only on a [`Strict`](crate::Strict) client. On a [`Permissive`](crate::Permissive) client the call doesn't compile. `N` is a sealed marker type, and `NonceRequirement::POLICY` turns it into the runtime [`NoncePolicy`](crate::NoncePolicy). [`VerificationConfig`](crate::VerificationConfig) holds only the key cache's timings.

A [`Permissive`](crate::Permissive) client, built with [`AppleAuthClient::<T, Permissive>::with_nonce_requirement(...)`](crate::AppleAuthClient::with_nonce_requirement), signs in through [`sign_up_or_log_in_with_nonce_checker`](crate::AppleAuthClient::sign_up_or_log_in_with_nonce_checker) with its own handling of a missing nonce. Construction and revocation are the same for both policies.

### Email and real-user claims

Apple's `email_verified` and `is_private_email` claims mean nothing without an `email`, so [`AppleIdentity::email`](crate::AppleIdentity::email) is one [`Option<AppleEmail>`](crate::AppleEmail). Three independently optional fields could form a state such as `verified: true` with no address.

Both flags are optional on the wire and plain `bool`s in [`AppleEmail`](crate::AppleEmail):

- [`verified`](crate::AppleEmail::verified) is `false` when the claim is absent, which Apple documents as equivalent (Sign in with Apple at Work & School). An `Option<bool>` would push a meaningless three-way match onto every caller.
- [`is_private`](crate::AppleEmail::is_private) falls back to the address's domain, `@privaterelay.appleid.com` or `@private.icloud.com`, when the claim is absent. The relay domains are stable, so callers get a real answer. A present claim always wins.

[`real_user_status`](crate::AppleIdentity::real_user_status) is an [`Option<RealUserStatus>`](crate::RealUserStatus) ([`Unsupported`](crate::RealUserStatus::Unsupported), [`Unknown`](crate::RealUserStatus::Unknown), [`LikelyReal`](crate::RealUserStatus::LikelyReal)). `None` covers an absent claim (web apps, or below iOS 14 and macOS 11) and a value idunn doesn't recognize. An unrecognized fraud signal can't be interpreted, and a surfaced value could be mistaken for one of the three documented ones, so idunn treats it as no signal.

## Signing in

### Verifying the exchanged token

[`exchange_authorization_code`](crate::AppleAuthClient::exchange_authorization_code) verifies the `id_token` Apple returns with the refresh token, by the same checks as [`verify_identity_token`](crate::AppleAuthClient::verify_identity_token), and returns [`SignInDetails`](crate::SignInDetails) with no raw `id_token`. An unverified JWT would invite a caller to read claims nobody checked. `access_token` and `expires_in` are dropped, since idunn never uses the access token.

The same [`NoncePolicy`](crate::NoncePolicy) applies, so a flow that sends no `nonce` in its authorize request fails every exchange under [`Strict`](crate::NoncePolicy::Strict) and needs [`Permissive`](crate::NoncePolicy::Permissive). Rejected: exempting the exchange, on the grounds that its `id_token` comes straight from Apple over TLS. The developers chose one rule for what "verified" means, at the cost of failing nonce-less flows under [`Strict`](crate::NoncePolicy::Strict).

If the exchange succeeds and verification fails, Apple has issued a live refresh token against a spent code. [`CodeExchangeError::ExchangedTokenUnverified`](crate::CodeExchangeError::ExchangedTokenUnverified) carries it, so the caller of the low-level [`exchange_authorization_code`](crate::AppleAuthClient::exchange_authorization_code) can revoke a new authorization's token or drop a known user's. [`sign_up_or_log_in`](crate::AppleAuthClient::sign_up_or_log_in) does this itself, as [Tokens rejected after the exchange](#tokens-rejected-after-the-exchange) describes.

### Every sign-in exchanges the code

Every sign-in spends the authorization code, and [`lookup`](crate::AppleAccounts::lookup)'s answer gives the exchange its meaning: a refresh of the stored token, or a new authorization.

The case that requires this: a user revokes the app in their Apple ID settings and signs in again. The stored token is dead, and idunn can't ask Apple whether a token is alive without spending something. Skipping the exchange for a known user would let the new code expire unspent, and account deletion would later revoke the dead token and leave the live authorization (TN3194, App Store Review Guideline 5.1.1(v)). Exchanging every time keeps the stored token on the user's latest authorization. The exchange is also a single-use check: a replayed identity token fails once its code is spent.

**Fallback for a known user.** A [`Rejected`](crate::ErrorKind::Rejected) failure (Apple refused the code, or the exchanged `id_token` was invalid) fails the sign-in, since signing in with the stored token would accept a code Apple calls bad. [`Unavailable`](crate::ErrorKind::Unavailable) and [`Misconfigured`](crate::ErrorKind::Misconfigured) say nothing against the user: the verified, nonce-checked identity token already authenticates them, and an Apple outage or a configuration mistake shouldn't lock every known user out. [`LoggedIn`](crate::SignInOutcome::LoggedIn) then carries the stored token, so the host has one code path for a known user: write [`refresh_token`](crate::SignInOutcome::LoggedIn::refresh_token) next to the user.

**Residual risk.** The fallback spends nothing, so `nonce_checker` is that sign-in's only replay defense and must be effectively single-use. This matters most for a [`Permissive`](crate::Permissive) client with a lax checker.

Rejected:

- A storage hook idunn calls to write the token. The host may want to do more in the same transaction, such as saving the user, which idunn can't see.
- A separate variant for "nothing new was issued". It would split a case the host handles one way.

### Checks after the exchange

After a successful exchange, [`sign_up_or_log_in`](crate::AppleAuthClient::sign_up_or_log_in) checks the subject, then the nonce. The subject check catches a stranger's authorization code paired with this identity token, possibly a stolen code presented with someone else's stolen identity token. It comes first because a stolen code carries the thief's own nonce: the nonce check would report an ordinary [`NonceMismatch`](crate::SignInError::NonceMismatch) and send the stranger's token to revocation.

The exchanged nonce is compared with the identity token's accepted nonce by `nonce_eq`, and `nonce_checker` runs only once. A checker that consumes a pending nonce from a store would reject every sign-in on a second call. Both tokens come from the same authorization and carry the same nonce, and for a checker that answers from the value alone, equality with the value it accepted is at least as strict as a second call.

Under [`Permissive`](crate::NoncePolicy::Permissive), two absent nonces match, since neither token was expected to carry one. An absent identity-token nonce with a present exchanged nonce is a mismatch: nothing was accepted to compare it against.

### The nonce checker's signature

`nonce_checker` is `FnOnce(Option<String>) -> Fut` with `Fut: Future<Output = Result<bool, A::Error>> + Send`. `AsyncFn(Option<&str>) -> Result<bool, A::Error>` looks more natural and breaks [`Send`]. Its future type, `CallRefFuture<'a>`, is tied to each call's borrow of the closure, and proving the sign-in future [`Send`] then needs `for<'a> F::CallRefFuture<'a>: Send`, a bound stable Rust can't write. An owned argument doesn't help, since the self-borrow is the cause. The error, "implementation of `Send` is not general enough", would surface where `Send` is first required, typically at a downstream axum route or [`tokio::spawn`].

With `FnOnce` and a named `Fut`, [`Send`] is an ordinary bound, checked at the call to [`sign_up_or_log_in_with_nonce_checker`](crate::AppleAuthClient::sign_up_or_log_in_with_nonce_checker). The cost: callers write `|candidate| async move { .. }` and receive an owned `Option<String>`, one clone.

The [`AppleAccounts`](crate::AppleAccounts) hooks don't have this problem: their `impl Future + Send` is declared in the trait and holds for every lifetime of `&self`.

## Refresh tokens and revocation

### Revocation is authorization-scoped

Apple's [revoke documentation](https://developer.apple.com/documentation/signinwithapplerestapi/revoke-tokens) describes a revoke as invalidating the tokens and the user authorizations they belong to. A stored token and the one a refresh issues normally belong to the same authorization, so revoking either would end both, and the user's sign-in to the app at Apple with them. For a known user, the host therefore keeps one token, overwriting the stored one with the refreshed one, and never revokes a token it failed to write.

A new authorization's token is the only handle on an authorization the host failed to record, so a failed store or a post-exchange rejection files it for revocation. Apart from that, only an explicit host decision revokes, such as account deletion or an aborted signup.

**Accepted risk: token independence.** Apple doesn't document whether revoking one refresh token invalidates the other tokens of the same user and `client_id`; the question is [open and unanswered on Apple's forums](https://developer.apple.com/forums/thread/844628). Besides the revoke documentation, indirect evidence supports the authorization-scoped model:

- A [developer report](https://developer.apple.com/forums/profile/zangw/replies) says that after a successful revoke the app disappears from the user's "Apps Using Apple ID" list.
- A [DTS post](https://developer.apple.com/forums/thread/708415) treats a revoke as equivalent to a manual revocation, after which a `credentialRevokedNotification` or `consent-revoked` notification follows.
- After a [manual revocation](https://developer.apple.com/forums/thread/123909), validating the refresh token fails with a 400.

If the tokens are independent after all, the revoke at account deletion invalidates only the latest token, and the app may stay in the user's list. The developers accepted that risk to avoid storing an unbounded list of tokens. A related assumption is unverified too: that the Apple user ID (`sub`), which keys the host's token row, is stable across a revoke and re-authorization. A manual sandbox test with a real device checks both.

### Tokens rejected after the exchange

Once the code is exchanged, a rejection leaves a live refresh token the caller can't use. idunn never revokes it: a revoke is authorization-scoped and could end a concurrent sign-in of the same user ([Host-coordinated revocation](#host-coordinated-revocation)). A known user's new token is dropped, since revoking it would end the stored authorization.

A stranger's token ([`SubjectMismatch`](crate::SignInError::SubjectMismatch)) is discarded. It is never stored, so nobody can recover it, and the host has no relationship with its user, so TN3194 asks nothing for it. Revoking it would end that user's authorization of the app on the strength of a code the attacker couldn't redeem with their own client secret.

A new authorization's token, after a [`PostExchangeRejection`](crate::PostExchangeRejection) (the exchanged `id_token` fails verification, or its nonce mismatches), goes to the host's [`schedule_revocation`](crate::AppleAccounts::schedule_revocation) as a [`PendingRevocation`](crate::PendingRevocation). idunn awaits the hook, then returns [`SignInError::RejectedAfterExchange(cause)`](crate::SignInError::RejectedAfterExchange). A live token in an error variant would make losing it the default: `?` or a catch-all arm drops it with no compile error and no log, and exhaustive enums don't help, since `?` matches nothing. With the hook, the error carries only the cause, and host error handling stays `?` plus a `match` on [`SignInOutcome`](crate::SignInOutcome).

The hook returns `()`. The token has already moved into it, and handing it back in an error would bring the lost-token problem back, so the hook owns its failure.

The cause goes to both. The hook records why a token was filed. The caller answers the request by [`SignInError::kind()`](crate::SignInError::kind), which tells a JWKS outage ([`TokenUnverified(CannotVerifyToken)`](crate::PostExchangeRejection::TokenUnverified)) apart from a rejection. That one clone is why [`PostExchangeRejection`](crate::PostExchangeRejection), [`VerificationError`](crate::VerificationError) and [`InvalidTokenCause`](crate::InvalidTokenCause) are [`Clone`]. Rejected: a cause-less variant, which would lose the distinction.

[`PendingRevocation::identity`](crate::PendingRevocation::identity) comes from the caller's own identity token and keys the filed job ([`apple_user_id`](crate::AppleIdentity::apple_user_id) is the `sub`). A job retried after a restart needs a key, and an opaque token has none. Under [`TokenUnverified`](crate::PostExchangeRejection::TokenUnverified) the exchanged token's owner can't be verified, in practice because Apple's keys were unreachable, so idunn treats the token as the caller's own: an accepted residual risk.

[`PendingRevocation::grace_period`](crate::PendingRevocation::grace_period) is a fixed 5 minutes, the wait that makes [`lookup`](crate::AppleAccounts::lookup)'s cancellation window work ([The `AppleAccounts` contract](crate#the-appleaccounts-contract), obligation 3). As data it reaches every host; as prose it would rely on each host reading it.

Limits: the hook runs inside the caller's future, so a future dropped mid-hook, such as a handler cancelled on client disconnect, can still lose the token, as with any `.await` in the handler.

### Host-coordinated revocation

idunn has no persistence and sees one call at a time. The host stores the tokens and sees every in-flight request, so coordinating sign-ins and revocations is the host's job, with the obligations in [The `AppleAccounts` contract](crate#the-appleaccounts-contract).

[`lookup`](crate::AppleAccounts::lookup) is the only point in a sign-in with a verified Apple `sub` before the code is spent: early enough for the host to cancel a pending revocation for that user before a new token is minted. It runs after the nonce check, so a replayed identity token can't reach it to cancel a revocation. Cancelling is right for whichever legitimate sign-in runs next, because a revoke is authorization-scoped and would end the session [`lookup`](crate::AppleAccounts::lookup) just let through.

Two failure modes idunn can't see give the host its obligations. A revoke can fail during an Apple outage and must be retried after a restart, so the pending job is durable, an outbox. A worker retrying the revoke can race a new sign-in of the same user, so the worker, [`lookup`](crate::AppleAccounts::lookup)'s cancellation and the host's own revocations serialize per user.

**Known limitation.** Nothing in idunn stops a host's own [`revoke_refresh_token`](crate::AppleAuthClient::revoke_refresh_token) call from racing a concurrent sign-in of the same user and revoking the token it is minting. The per-user serialization (obligation 4) is the mitigation.

[`revoke_refresh_token`](crate::AppleAuthClient::revoke_refresh_token) treats Apple's `invalid_grant` answer as success. Apple considers the token unusable, which is what a revoke guarantees, so a retried revoke eventually succeeds. The case is defensive: Apple documents a 200 with an empty body even for a token that is already invalid. So `Ok(())` means the token is unusable, whether or not this call revoked it.

## The host interface

### One `AppleAccounts` trait

Both storage hooks belong to the host's storage and share one contract, so one trait holds both. It needs one type parameter, lets implementors write `async fn`, and lets the host pass a long-lived `&accounts`. Rejected: two closures, which would need four type parameters (`L, LFut, Q, QFut`) and a pool cloned into each on every request.

`nonce_checker` stays a closure, because it depends on per-request state. Rejected: a nonce method on the trait, which would force per-request state into a type that lives as long as the application.

The sign-in future holds `&A` across awaits, so it is [`Send`] only if [`A: Sync`](Sync). The [`Sync`] supertrait makes a non-`Sync` implementation fail at its own `impl`; without it, the error would surface at a downstream axum route. The trait isn't dyn-compatible, because its methods return `impl Future`, and idunn needs only a generic `A`. A host that needs dynamic dispatch implements [`AppleAccounts`](crate::AppleAccounts) on a wrapper around its own dyn-compatible trait.

### The host's own error type

[`sign_up_or_log_in`](crate::AppleAuthClient::sign_up_or_log_in) returns the host's [`AppleAccounts::Error`](crate::AppleAccounts::Error), the pattern of sqlx's `Connection::transaction` with `E: From<sqlx::Error>`. Hook errors pass through with a plain `?`, and idunn's failures are converted once, by the host's [`From<SignInError>`](From). `nonce_checker` shares [`A::Error`](crate::AppleAccounts::Error). The bound `From<SignInError> + std::error::Error + Send + Sync + 'static` sits on [`AppleAccounts::Error`](crate::AppleAccounts::Error), so a wrong type fails at the host's `impl`.

Rejected:

- Boxing the hooks' errors. Every host would `map_err` into a box and `downcast` back out.
- `SignInError<LookupErr, NonceErr>`. Every host's [`From`] would take `AccountLookupFailed(e)` and `NonceCheckFailed(e)` apart to rebuild its own errors, and [`kind()`](crate::SignInError::kind) would need a `Host` kind that classifies nothing idunn knows about, with an `unreachable!` in the host.
- A two-level [`SignInError`](crate::SignInError) with an inner idunn-only enum. The naming would confuse, since all of it is the Apple sign-in.

Costs: the host writes the [`From`]; `anyhow::Error` and `Box<dyn Error>` need a wrapper, because neither implements [`std::error::Error`]; and [`SignInError`](crate::SignInError) has to stay small and `Send + Sync + 'static`, since every host's error embeds it.

### Exhaustive error enums

None of idunn's public error enums is `#[non_exhaustive]`. A new variant is usually a new failure mode the host has to make a call on: whether a live token is left behind, which HTTP status it maps to, whether to alert. A mandatory wildcard arm would handle it before anyone looked. Without the attribute, a host matches exhaustively where the distinction matters, and a variant added later fails to compile there until someone classifies it. The price: every new variant is a breaking change.

[`SignInError::kind()`](crate::SignInError::kind) and [`TokenRevocationError::kind()`](crate::TokenRevocationError::kind) classify every variant as [`Rejected`](crate::ErrorKind::Rejected), [`Unavailable`](crate::ErrorKind::Unavailable) or [`Misconfigured`](crate::ErrorKind::Misconfigured). A host that maps only [`kind()`](crate::SignInError::kind) keeps compiling when a variant is added and lets idunn classify it, the trade [`std::io::Error::kind`] makes. A host that wants to review every new failure mode matches the variants. [`ErrorKind`](crate::ErrorKind) is exhaustive for the same reason, and idunn's own classification has no wildcard either.

Both operations share one [`ErrorKind`](crate::ErrorKind), as [`std::io`] operations share [`io::ErrorKind`](std::io::ErrorKind): on either path a kind means Apple refused the request, Apple couldn't be reached, or the app's configuration is wrong. The consequences differ, an HTTP answer for a sign-in and an alert or a retry for a revocation worker, so each `kind()` documents its own. The cost is coupling: a kind only one operation needs would still break a host's `match` on the other.

## Secrets

[`AppleTokenConfig::private_key_pem`](crate::AppleTokenConfig::private_key_pem) holds Apple's `.p8` signing key, a long-lived credential. `#[derive(ZeroizeOnDrop)]` wipes the config on drop, as jsonwebtoken 11 does for the `EncodingKey` idunn derives from it. The non-secret identifiers are wiped too, which costs less than a `#[zeroize(skip)]` each. The field's docs state the limits: copies the caller keeps, such as a retained clone or the PEM in an environment variable, are out of reach, and `Vec` zeroization can't reach bytes an earlier reallocation left on the heap.

The hand-written `Debug` replaces the key with `<N redacted bytes>`, so the key can't leak into a log line or a panic message. A later `#[derive(Debug)]` would conflict with it and fail to compile.

Every refresh token idunn hands back, on success or in an error, is a [`RefreshToken`](crate::RefreshToken). Errors get `{:?}`-printed into logs, `anyhow` chains and `unwrap()` panics, and a `String` would print the live credential there. [`RefreshToken`](crate::RefreshToken) has a redacting `Debug` and no `Display`. Its constructor is public so a host can rebuild a stored token for [`AccountState::AlreadyOnFile`](crate::AccountState::AlreadyOnFile).

## HTTP transport

Every network call idunn makes goes through the [`HttpTransport`](crate::HttpTransport) trait, with [`ReqwestTransport`](crate::ReqwestTransport) as the default. The developers made it injectable so a host can use its own HTTP stack (a proxy, custom TLS) without forking the crate, and so [`exchange_authorization_code`](crate::AppleAuthClient::exchange_authorization_code) and `JwksStore` are unit-testable with an in-memory fake.

[`get`](crate::HttpGet::get) and [`post_form`](crate::HttpPost::post_form) return a generic [`TransportError`](crate::TransportError), a network failure or an HTTP status with the raw body, so implementors need no knowledge of Apple's errors. The Apple-aware callers convert it and parse Apple's error body: the JWKS fetch into [`VerificationError::CannotVerifyToken`](crate::VerificationError::CannotVerifyToken), the exchange into [`TokenExchangeError`](crate::TokenExchangeError), the revoke into [`TokenRevocationError`](crate::TokenRevocationError). [`TransportError::Network`](crate::TransportError::Network) boxes a `dyn Error`, so any implementation can report its own error type.

The transport traits, [`TransportError`](crate::TransportError), [`VerificationConfig`](crate::VerificationConfig) and [`NoncePolicy`](crate::NoncePolicy) are re-exported from the crate root. A downstream crate that stores an [`AppleAuthClient<T>`](crate::AppleAuthClient) in a struct field must name a concrete `T`, since `impl Trait` isn't allowed there and the traits aren't dyn-compatible, and [`with_transport`](crate::AppleAuthClient::with_transport) takes a [`VerificationConfig`](crate::VerificationConfig).

## Crypto backend

`jsonwebtoken`'s `aws_lc_rs` and `rust_crypto` features are mutually exclusive `CryptoProvider` backends. With both or neither enabled, `jsonwebtoken` can't pick one, and the first verification or signing panics with "Could not automatically determine the process-level CryptoProvider". `cargo check` and `cargo clippy` don't catch it.

Two `compile_error!` guards in `src/lib.rs`, for both features and for neither, turn a bad selection into a compile error that names the problem. They also catch `features = ["rust_crypto"]` without `default-features = false`, which keeps `aws_lc_rs` on through idunn's `default`.

Rejected: leaving both-or-neither buildable, so a caller could install their own provider with `CryptoProvider::install_default()`. That setup works and is fragile. Supporting it would mean loosening the `not(any(...))` half of the guard.

The guard sees only idunn's features. Another crate that enables `jsonwebtoken/rust_crypto` directly, next to idunn's `aws_lc_rs`, still compiles and panics at runtime.
