# Using idunn

idunn verifies Sign in with Apple identity tokens, and exchanges and revokes refresh tokens against Apple's REST API. It has no persistence layer: anything that needs a view of stored or concurrently-changing state — persisted refresh tokens, in-flight sign-ins, pending revocations — is the host's responsibility. For the design rationale behind these boundaries, see docs/architecture.md.

## Constructing a client

Every constructor (`AppleAuthClient::new`, `with_transport`, `with_nonce_requirement`) returns an `AppleSeed`; pick a JWKS refresh strategy to turn it into an `AppleAuthClient`. See docs/architecture.md, "Why the JWKS refresh strategy is chosen at construction", for why.

With the `tokio-refresh` feature, spawn onto a `Handle`:

```ignore
let client = AppleAuthClient::new(token_config)?
    .with_background_refresh(tokio::runtime::Handle::current());
```

On any other executor, drive the returned future yourself:

```ignore
let (client, refresh) = AppleAuthClient::new(token_config)?
    .with_refresh_loop(smol::Timer::after);
smol::spawn(refresh).detach();
```

To opt out entirely — JWKS keys are then fetched lazily inside verification, with the cold-cache fetch and every subsequent refresh paid by whichever request triggers it, unless you drive `AppleAuthClient::refresh_keystore` yourself:

```ignore
let client = AppleAuthClient::new(token_config)?.without_background_refresh();
```

## Signing in: `sign_up_or_log_in`

`sign_up_or_log_in` checks the identity token's nonce against your `expected_nonce` (a `Strict` client only); `sign_up_or_log_in_with_nonce_checker` takes your own `nonce_checker` instead (a `Permissive` client, or a single-use nonce store); both run the same flow.

Each call runs, in order: verify the identity token, check the nonce, call `accounts.lookup`, then exchange the authorization code — on **every** sign-in, so a user who revoked the app in their Apple ID settings and signed in again gets the new authorization's token, replacing the dead one — check the exchanged token's subject against the identity token's, and compare the exchanged token's nonce against the identity token's already-accepted nonce. `nonce_checker` itself is called once, for the identity token only. What `lookup` reported decides what a failure after the code is spent means. For a new authorization (`AccountState::NotOnFile`), a rejection after the exchange for any reason other than the subject check makes idunn hand the live token to `accounts.schedule_revocation`, await it, then return `RejectedAfterExchange`. For a known user (`AccountState::AlreadyOnFile`), the new token is dropped and never revoked: revoking is authorization-scoped and would end the stored authorization too. The subject check discards the token in both cases and never calls the hook. A known user whose exchange fails because Apple is unreachable or this app is misconfigured (`ErrorKind::Unavailable`, `ErrorKind::Misconfigured`) is signed in with the stored token, and idunn logs why; Apple refusing the code (`ErrorKind::Rejected`) fails the sign-in.

`Err` carries your own `AppleAccounts::Error`: your hooks' failures as-is, idunn's as a `SignInError` converted through your `From<SignInError>` (see below).

| Outcome | What the host does |
|---|---|
| `Ok(SignInOutcome::LoggedIn { refresh_token, .. })` | A known user. `refresh_token` is the freshly exchanged one, or the stored one handed back because Apple couldn't issue a new one. Update the stored token with it; it is the same case for you either way. If no token is stored any more (an account deletion or a revocation completed meanwhile), do not recreate one: the token may be dead, so drop it. If writing fails, drop it — **never** schedule it for revocation, because that would end the stored authorization too. |
| `Ok(SignInOutcome::SignedUp { refresh_token, .. })` | Persist `refresh_token`, keyed by `identity.apple_user_id`. A new authorization. This is the token account deletion later revokes (TN3194). If storing fails, hand it to your own `accounts.schedule_revocation`, or the authorization outlives the user's chance to delete it. |
| `Err(e)` from your own `accounts.lookup` or `nonce_checker` | Returned exactly as your hook produced it; idunn never inspects it. Nothing was spent at Apple. |
| `SignInError::IdentityTokenRejected`, `SignInError::NonceMismatch`, `SignInError::Exchange(_)` | Nothing was left live at Apple, so the host has no revocation obligation. The sign-in can be retried. `Exchange` may mean the code was already spent even though the call failed. (For a known user only a `Rejected` exchange failure fails the sign-in; the other kinds sign in with the stored token.) |
| `SignInError::SubjectMismatch` | Nothing to do — the token belongs to another Apple user and was discarded, never persisted. Worth logging as a security event. `accounts.schedule_revocation` is not called. |
| `SignInError::RejectedAfterExchange(cause)` | For a new authorization, a refresh token was left live at Apple; idunn already handed it to your `accounts.schedule_revocation` and awaited it before returning. For a known user, idunn dropped the new token instead (never revoked). Either way nothing is left to do — answer it as a rejected sign-in. cause says why. |

`SignInError::kind()` classifies every failure as an `ErrorKind`, so a host can map it to a response without matching each variant: `Rejected` (the sign-in was refused; answer e.g. 401), `Unavailable` (Apple or its key set couldn't be reached or gave an uninterpretable answer; answer e.g. 503 — the same request can be resent only while the authorization code is unspent, so after `RejectedAfterExchange` or an `Exchange` failure the client needs a fresh Apple authorization) and `Misconfigured` (Apple refused this app's own credentials or configuration; answer e.g. 500 and alert). idunn classifies every variant, including ones a later version adds, so a `match` on `kind()` only stops compiling when a new kind appears. `TokenRevocationError::kind()` returns the same `ErrorKind` — see obligation 5.

`SignInError` and `ErrorKind` are both exhaustive: where you need finer detail than the kind — logging `SubjectMismatch` as a security event, say — match the variants without a wildcard, so that a failure mode added in a later idunn version fails to compile in your code. Payloads you treat uniformly, such as the `AppleErrorCode` inside `Exchange(TokenExchangeFailed(code))`, can be bound whole. See docs/architecture.md, "Why the error enums are exhaustive".

`sign_up_or_log_in` returns your own error type, `AppleAccounts::Error`, the way sqlx's `Connection::transaction` returns the caller's `E: From<sqlx::Error>`. Your `lookup`'s `Err(e)` and your `nonce_checker`'s — its future returns `Result<bool, AppleAccounts::Error>` — come back exactly as you produced them, so there is nothing to box, downcast or unwrap again. idunn's own failures reach that type through the `From<SignInError>` the trait requires; that impl is where you call `kind()`. The type must also be `std::error::Error + Send + Sync + 'static`, so `anyhow::Error` or a `Box<dyn Error>` needs a wrapper of your own. See docs/architecture.md, "Why sign-in returns the host's own error type".

**Replay:** exchanging the authorization code is a de-facto single-use check, since a replayed identity token fails once its code is spent. The exception is the fallback, where a known user is signed in with the stored token because Apple couldn't issue a new one: there the nonce check is the only replay defense, so it must be effectively single-use. Details are in the `sign_up_or_log_in_with_nonce_checker` rustdoc and docs/architecture.md, "Why every sign-in exchanges the authorization code".

## The `AppleAccounts` contract

Implement `AppleAccounts` on your storage type and pass `&accounts`; obligations 1-4 are about `lookup`, 5 about `schedule_revocation`.

1. **What `lookup` receives and when.** It gets the verified `AppleIdentity`, *after* the identity-token and nonce checks and *before* the authorization code is spent. It is called at most once per sign-in attempt. A call reaching it is already authenticated — an unauthenticated request can never trigger it.

2. **Return value.** Return `AlreadyOnFile { refresh_token }` with the stored token iff one is stored for `identity.apple_user_id`; it need not be live, because idunn refreshes it on every sign-in. Return `NotOnFile` otherwise. Return `Err` only when the lookup itself failed — `Err` is not a verdict that the account doesn't exist.

3. **Cancelling pending revocations.** If a pending revocation exists for this `apple_user_id` (see obligation 5 below), delete it inside `lookup` and discard the pending token *without revoking it*, whatever `AccountState` the lookup returns. Apple's `/auth/revoke` is authorization-scoped, and the user signing in right now is the latest intent — revoking would end the authorization this very sign-in belongs to.

4. **Per-user serialization.** The cancellation in `lookup`, the revocation worker, and the host's own explicit revocations (account deletion, an aborted signup) must not race each other for the same `apple_user_id`. The exact mechanism is a storage choice — what matters is that all three paths serialize through one point per user, so the worker's read-then-`revoke_refresh_token` sequence can check the pending job still exists immediately before it acts, with nothing able to cancel it in the gap. Give a worker's claim on a job an expiry: once it lapses, another worker can pick the job back up, which keeps a crashed worker from stalling the queue indefinitely.

5. **Filing a pending revocation via `schedule_revocation`.** idunn calls it with a `PendingRevocation` `p` when it rejects a *new authorization* after the exchange; a known user's refresh never reaches it (the new token is dropped). Store it durably, outbox-style: `p.identity.apple_user_id`, `p.refresh_token` (encrypted at rest), `p.cause`, and `p.grace_period` — for example as `NOW() + p.grace_period` for the earliest revoke time — and do not revoke inline (see obligation 3). idunn awaits the hook before returning, so return once the job is stored. It returns `()`: if storing fails, log it — idunn cannot take the token back. A worker retries `revoke_refresh_token` with backoff no sooner than that earliest time. Refresh tokens don't expire on a timer, so a revoke that succeeds days later still works.
   - Retrying is safe: idunn reports Apple's `invalid_grant` answer as `Ok(())` — already invalid.
   - `TokenRevocationError::kind()` classifies every failure: `Unavailable` is transient (a network failure, or an Apple answer idunn couldn't interpret — idunn doesn't expose the HTTP status, so a 5xx with an unparseable body lands here), and the retry handles it. `Misconfigured` (Apple refused this app's credentials or configuration, or the client secret couldn't be signed) is permanent until fixed, and `Rejected` (Apple refused the request itself, `invalid_request`) won't succeed by retrying the same token either: alert on both.
   - Also alert if a revoke keeps failing for days.

**If you handle Apple's `consent-revoked` server-to-server notification** (optional: idunn neither needs nor calls it, and it is outside `AppleAccounts`), make the handler idempotent. Ignore an event whose `event_time` is earlier than the latest authorization for that `apple_user_id`; otherwise an event arriving late from an earlier revoke could delete a freshly re-registered account. Without such a handler, a user who revokes access in their Apple ID settings keeps a dead stored token until their next sign-in replaces it (docs/architecture.md, "Why every sign-in exchanges the authorization code").

**Residual risk.** The lock taken by `lookup` ends before the exchange. If the worker revokes first and the sign-in waiting on the lock then exchanges a code minted before the revoke, Apple doesn't document the result — it may fail with `invalid_grant` or `invalid_request`. The user then has to sign in again.
