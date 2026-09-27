# Using idunn

idunn verifies Sign in with Apple identity tokens, and exchanges and revokes refresh tokens against Apple's REST API. It has no persistence layer: anything that needs a view of stored or concurrently-changing state — persisted refresh tokens, in-flight sign-ins, pending revocations — is the host's responsibility. For the design rationale behind these boundaries, see docs/architecture.md.

## Constructing a client

Every constructor (`AppleAuthClient::new`, `with_transport`, `with_nonce_requirement`) returns an `AppleSeed`, not a usable client: pick a JWKS refresh strategy to get an `AppleAuthClient`. See docs/architecture.md, "Why the JWKS refresh strategy is chosen at construction", for why.

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

Each call runs, in order: verify the identity token, call `nonce_checker`, call `account_lookup`, and — only when `account_lookup` reports `AccountState::NeedsExchange` — exchange the authorization code, check the exchanged token's subject against the identity token's, then compare the exchanged token's nonce against the identity token's already-accepted nonce. `nonce_checker` itself is called once, for the identity token only.

| Outcome | What the host does |
|---|---|
| `Ok(SignInOutcome::LoggedIn { .. })` | No code was spent and no new token issued. Keep using the refresh token already on file. |
| `Ok(SignInOutcome::SignedUp { refresh_token, .. })` | Persist `refresh_token`, keyed by `identity.apple_user_id`. This is the token account deletion later revokes (TN3194). If a stale token was already stored, overwrite it — do not revoke it. |
| `Err(SignInError::IdentityTokenRejected)`, `Err(SignInError::NonceMismatch)`, `Err(SignInError::NonceCheckFailed)`, `Err(SignInError::AccountLookupFailed)`, `Err(SignInError::Exchange(_))` | Nothing was left live at Apple, so the host has no revocation obligation. The sign-in can be retried. `Exchange` may mean the code was already spent even though the call failed. |
| `Err(SignInError::SubjectMismatch)` | Nothing to do — the token belongs to another Apple user and was discarded, never persisted. Worth logging as a security event. |
| `Err(SignInError::RevocationRequired(pending))` | A refresh token is live at Apple. File a pending revocation — see "The `account_lookup` contract" below. |

`SignInError` is exhaustive: match its variants without a wildcard, so that a failure mode added in a later idunn version fails to compile in your code rather than falling into a default branch. Payloads you treat uniformly, such as the `AppleErrorCode` inside `Exchange(TokenExchangeFailed(code))`, can be bound whole. See docs/architecture.md, "Why the error enums are exhaustive".

**Replay caveat on the `LoggedIn` branch:** no code is spent, so `nonce_checker` must be effectively single-use — it is the only replay defense left on that branch. Details are in the `sign_up_or_log_in` rustdoc and docs/architecture.md, "Why `sign_up_or_log_in` may skip the exchange, and what it costs".

## The `account_lookup` contract

1. **What it receives and when.** It gets the verified `AppleIdentity`, *after* the identity-token and nonce checks and *before* the authorization code is spent. It is called at most once per sign-in attempt. A call reaching it is already authenticated — an unauthenticated request can never trigger it.

2. **Return value.** Return `AlreadyOnFile` only when a refresh token is stored for `identity.apple_user_id` and it is still usable. Return `NeedsExchange` otherwise, whether the user is new or the stored token is stale. Return `Err` only when the lookup itself failed — `Err` is not a verdict that the account doesn't exist.

3. **Cancelling pending revocations.** If a pending revocation exists for this `apple_user_id` (see obligation 5 below), delete it inside `account_lookup` and discard the pending token *without revoking it*, whatever `AccountState` the lookup returns. Apple's `/auth/revoke` is authorization-scoped, and the user signing in right now is the latest intent — revoking would end the authorization this very sign-in belongs to.

4. **Per-user serialization.** The cancellation in `account_lookup`, the revocation worker, and the host's own explicit revocations (account deletion, an aborted signup) must not race each other for the same `apple_user_id`. The exact mechanism is a storage choice — what matters is that all three paths serialize through one point per user, so the worker's read-then-`revoke_refresh_token` sequence can check the pending job still exists immediately before it acts, with nothing able to cancel it in the gap. Give a worker's claim on a job an expiry: once it lapses, another worker can pick the job back up, which keeps a crashed worker from stalling the queue indefinitely.

5. **Filing a `RevocationRequired` token.** Store it durably, outbox-style: `p.identity.apple_user_id`, the token (encrypted at rest), `p.cause`, and a timestamp. A worker retries `revoke_refresh_token` with backoff. Refresh tokens don't expire on a timer, so a revoke that succeeds days later still works.
   - Retrying is safe: idunn reports Apple's `invalid_grant` answer as `Ok(())` — already invalid.
   - Transient-looking failures: `TokenRevocationError::NetworkError`, and `TokenRevocationFailed(AppleErrorCode::UnknownError(_))`. idunn doesn't expose the HTTP status, so a 5xx with an unparseable body arrives here.
   - Configuration errors, permanent until fixed: `TokenRevocationFailed(AppleErrorCode::InvalidClient)` and `ClientSecretSigningFailed`. Alert on these — retrying won't help.
   - Also alert if a revoke keeps failing for days.

6. **Idempotent `consent-revoked` server-to-server handler.** Ignore an event whose `event_time` is earlier than the latest authorization for that `apple_user_id`. Otherwise an event arriving late from an earlier revoke could delete a freshly re-registered account.

**Residual risk.** The lock taken by `account_lookup` ends before the exchange. If the worker revokes first and the sign-in waiting on the lock then exchanges a code minted before the revoke, Apple doesn't document the result — it may fail with `invalid_grant` or `invalid_request`. The user then has to sign in again.
