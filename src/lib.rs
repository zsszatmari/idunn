#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
#![doc = include_str!("../docs/usage.md")]
// https://developer.apple.com/documentation/technotes/tn3194-handling-account-deletions-and-revoking-tokens-for-sign-in-with-apple
// https://developer.apple.com/documentation/signinwithapplerestapi/revoke-tokens
// https://developer.apple.com/support/offering-account-deletion-in-your-app/

// jsonwebtoken can't auto-select a CryptoProvider when both backends are enabled, and has
// none to use when neither is: either case panics at first use rather than failing to build.
// See "Why exactly one crypto backend is enforced at compile time" in docs/architecture.md.
#[cfg(all(feature = "aws_lc_rs", feature = "rust_crypto"))]
compile_error!(
    "features \"aws_lc_rs\" and \"rust_crypto\" are mutually exclusive: enable exactly one \
     (to use rust_crypto, set default-features = false)"
);
#[cfg(not(any(feature = "aws_lc_rs", feature = "rust_crypto")))]
compile_error!("one of the \"aws_lc_rs\" or \"rust_crypto\" features must be enabled");

mod config;
mod error;
mod identity_verification;
mod jwks_store;
mod token_exchange;
mod transport;

pub use config::{NoncePolicy, NonceRequirement, Permissive, Strict, VerificationConfig};
pub use error::{
    AppleErrorCode, ClientSecretError, CodeExchangeError, ErrorKind, InvalidPrivateKeyError,
    InvalidTokenCause, PendingRevocation, PostExchangeRejection, SignInError, TokenExchangeError,
    TokenRevocationError, VerificationError,
};
pub use identity_verification::{
    AppleEmail, AppleIdentity, IdentityWithPendingNonce, RealUserStatus,
};
pub use token_exchange::{AppleTokenConfig, RefreshToken};
pub use transport::{HttpGet, HttpPost, HttpTransport, TransportError};

#[cfg(feature = "reqwest")]
pub use transport::ReqwestTransport;

/// Test-only fixtures: a throwaway EC P-256 key and a matching `AppleTokenConfig`.
/// Never enable this feature for a production build — the "private key" here is
/// committed to this repository and grants nothing.
#[cfg(feature = "test-fixtures")]
pub use token_exchange::test_fixtures;

use jsonwebtoken::EncodingKey;
use std::marker::PhantomData;
use std::sync::{Arc, Weak};
use std::time::Duration;
use subtle::ConstantTimeEq;

/// Floor on how long `keystore_refresh_loop` will ever sleep between ticks,
/// regardless of what `refresh_keystore()` suggests. `refresh_keystore()`
/// passes through caller-supplied `VerificationConfig` durations verbatim —
/// `refresh_interval` on success, `cooldown_period` on failure or
/// cooldown-skip — either of which may be `Duration::ZERO`. On the manual
/// `refresh_keystore` path that's the caller's own problem; here the loop owns
/// the task, so a `ZERO` config combined with a persistent fetch failure would
/// otherwise spin tight and hammer Apple with no rate limit to stop it.
const MIN_REFRESH_DELAY: Duration = Duration::from_secs(1);

/// The minimum time a host must wait before revoking a token handed to
/// `schedule_revocation` — see `PendingRevocation::grace_period`. Matches
/// pergamen-server's own independently-chosen 5-minute practice
/// (`enqueue_apple_revocation`); fixed here so every host gets the same
/// answer instead of picking its own number.
const REVOCATION_GRACE_PERIOD: Duration = Duration::from_secs(300);

/// ASCII-case-insensitive and constant-time: case-insensitivity handles clients
/// that hex-encode in upper case, constant time protects a server-side-secret
/// `expected_nonce` from a timing side channel — see docs/architecture.md for
/// the limits of that protection. Used by `sign_up_or_log_in`, and internally
/// by `sign_up_or_log_in_with_nonce_checker` to compare the exchanged
/// `id_token`'s nonce against the identity token's already-accepted nonce.
fn nonce_eq(candidate: Option<&str>, expected: &str) -> bool {
    let Some(candidate) = candidate else {
        return false;
    };
    let candidate = candidate.to_ascii_lowercase();
    let expected = expected.to_ascii_lowercase();
    candidate.as_bytes().ct_eq(expected.as_bytes()).into()
}

/// What `AppleAuthClient::exchange_authorization_code` carries back: the
/// refresh token from the exchange plus the identity from the `id_token` Apple
/// returned alongside it, whose signature, `iss`, `aud` and `exp` idunn
/// verified against Apple's published keys and whose nonce *presence* it
/// enforced per the configured `NoncePolicy`.
///
/// Only constructible through `AppleAuthClient::exchange_authorization_code`.
#[derive(Debug, Clone)]
pub struct SignInDetails {
    /// The `id_token`'s `nonce` claim, verbatim — **not** compared against
    /// anything. Comparing it against the value you generated for this
    /// authentication attempt is the one verification step left to you; see
    /// [`IdentityWithPendingNonce::nonce`] for why idunn cannot do it and what
    /// `None` means.
    pub nonce: Option<String>,
    /// Apple's refresh token. Store it: revoking it is how an app satisfies
    /// Apple's mandatory account-deletion requirement (TN3194).
    pub refresh_token: RefreshToken,
    /// The identity from the exchange's `id_token`, already verified.
    pub identity: AppleIdentity,
}

/// What the caller found when looking up this Apple user. Every sign-in
/// exchanges the authorization code; this decides what the exchange means —
/// a refresh of the stored token or a new authorization — and what idunn can
/// fall back to when Apple can't issue a new token. See docs/architecture.md,
/// "Why every sign-in exchanges the authorization code".
#[derive(Debug, Clone)]
pub enum AccountState {
    /// A refresh token is stored for this Apple user. This sign-in refreshes
    /// it, and hands this one back in `SignInOutcome::LoggedIn` if Apple can't
    /// issue a new one. It need not be live: a user who revoked the app in
    /// their Apple ID settings is refreshed by the next sign-in.
    AlreadyOnFile { refresh_token: RefreshToken },
    /// No refresh token is stored (a new user, or the host already discarded
    /// it): this sign-in is a new authorization.
    NotOnFile,
}

/// What `sign_up_or_log_in` produced. Either way the host has a refresh token
/// to store; the variants differ in what to do when storing fails.
#[derive(Debug, Clone)]
pub enum SignInOutcome {
    /// A known user. `refresh_token` is the freshly exchanged one, or the
    /// stored one handed back because Apple couldn't issue a new one
    /// (`Unavailable` or `Misconfigured`, already logged by idunn). Write it
    /// next to the user; if writing fails, drop it and never revoke it: a
    /// revocation is authorization-scoped and would end the stored
    /// authorization too, signing the user out of the app at Apple.
    LoggedIn {
        identity: AppleIdentity,
        refresh_token: RefreshToken,
    },
    /// A new authorization. Store `refresh_token`; if storing fails, schedule
    /// it for revocation (docs/usage.md, obligation 5), or the authorization
    /// outlives the user's chance to delete it.
    SignedUp {
        identity: AppleIdentity,
        refresh_token: RefreshToken,
    },
}

impl SignInOutcome {
    /// The verified identity either way. **Provenance differs by variant:**
    /// `LoggedIn` carries the identity from the caller's own identity token,
    /// also when the exchange succeeded (the subjects are checked equal);
    /// `SignedUp` carries the identity from the exchanged `id_token`.
    pub fn identity(&self) -> &AppleIdentity {
        match self {
            SignInOutcome::LoggedIn { identity, .. } => identity,
            SignInOutcome::SignedUp { identity, .. } => identity,
        }
    }
}

/// The host's account storage, as `sign_up_or_log_in` sees it: both storage
/// hooks of a sign-in, on one type. The obligations are in docs/usage.md,
/// "The `AppleAccounts` contract"; the reasoning in docs/architecture.md,
/// "Why the account hooks are one `AppleAccounts` trait" and "Why sign-in
/// returns the host's own error type". Implement it with `async fn`.
pub trait AppleAccounts: Sync {
    /// Your own error type, and what `sign_up_or_log_in` returns: `lookup`'s
    /// and `nonce_checker`'s errors come back exactly as you returned them, and
    /// idunn's own failures arrive converted through `From<SignInError>` —
    /// where [`SignInError::kind`] says how to answer them. The same shape as
    /// sqlx's `Connection::transaction`.
    type Error: From<SignInError> + std::error::Error + Send + Sync + 'static;

    /// The refresh token stored for `identity`, if any. Called at most once,
    /// after the identity token and its nonce are verified and before the
    /// authorization code is spent (contract obligations 1-4).
    fn lookup(
        &self,
        identity: &AppleIdentity,
    ) -> impl Future<Output = Result<AccountState, Self::Error>> + Send;

    /// Files a live refresh token from a new authorization that idunn rejected
    /// after the exchange, for revocation no sooner than `pending.grace_period`
    /// from now (obligation 5). Awaited before `sign_up_or_log_in` fails with
    /// `SignInError::RejectedAfterExchange` (converted into `Self::Error`); a
    /// failure to file is the implementation's own to log. Never called for a
    /// known user's refresh: that token is dropped, because revoking it would
    /// end the stored authorization too.
    fn schedule_revocation(&self, pending: PendingRevocation) -> impl Future<Output = ()> + Send;
}

/// The credential material for signing client secrets: the config and the
/// `EncodingKey` derived from its `.p8` key. Grouped behind one `Arc` so
/// `AppleAuthClient::clone` never re-allocates or copies the private key
/// (`axum`'s `State` clones per request); they belong together anyway, the
/// key being derived from `token_config.private_key_pem`.
struct Credentials {
    token_config: AppleTokenConfig,
    signing_key: EncodingKey,
}

/// Verifies Apple identity tokens and exchanges authorization codes for refresh
/// tokens, for a single app identified by `AppleTokenConfig::client_id`.
///
/// One client with one constructor, covering both identity verification and token
/// exchange even though they touch mostly-disjoint code (see `identity.rs` /
/// `token.rs`): see docs/architecture.md for why they're bundled together.
/// Clonable by design.
///
/// `N: NonceRequirement` (default `Strict`) fixes the `NoncePolicy`
/// identity-token verification enforces, and whether
/// `sign_up_or_log_in` exists on this client — see
/// [`NonceRequirement`] and docs/architecture.md ("Why the nonce policy is a
/// type parameter").
#[derive(Clone)]
pub struct AppleAuthClient<T: HttpTransport, N: NonceRequirement = Strict> {
    identity_verification: Arc<identity_verification::IdentityVerificationClient<T>>,
    credentials: Arc<Credentials>,
    transport: T,
    // `fn() -> N` rather than `N`: keeps this field `Send + Sync + Clone + Copy`
    // unconditionally, so `#[derive(Clone)]` above never demands `N: Clone` — `N`
    // is a zero-sized marker type (`Strict`/`Permissive`), never a stored value.
    _nonce_requirement: PhantomData<fn() -> N>,
}

impl<T: HttpTransport, N: NonceRequirement> AppleAuthClient<T, N> {
    // `N` only appears here as `N::POLICY`, with no argument to infer it from,
    // so an unannotated call to a `pub` function under this name would leave
    // `N` ambiguous. `with_transport`/`new` below are `pub`, one per concrete
    // `N`, and delegate here; `with_nonce_requirement` also delegates here for
    // a caller who names `N` explicitly via turbofish.
    fn build(
        token_config: AppleTokenConfig,
        config: VerificationConfig,
        transport: T,
    ) -> Result<Self, InvalidPrivateKeyError> {
        let signing_key = EncodingKey::from_ec_pem(&token_config.private_key_pem)
            .map_err(InvalidPrivateKeyError::from)?;
        let identity_verification =
            Arc::new(identity_verification::IdentityVerificationClient::new(
                &token_config.client_id,
                config,
                N::POLICY,
                transport.clone(),
            ));
        Ok(Self {
            identity_verification,
            credentials: Arc::new(Credentials {
                token_config,
                signing_key,
            }),
            transport,
            _nonce_requirement: PhantomData,
        })
    }

    /// Constructs a client for an explicit `N`, e.g.
    /// `AppleAuthClient::<_, Permissive>::with_nonce_requirement(...)`.
    /// `with_transport`/`new` cover the default `Strict` case without naming
    /// `N` at all.
    pub fn with_nonce_requirement(
        token_config: AppleTokenConfig,
        config: VerificationConfig,
        transport: T,
    ) -> Result<AppleSeed<T, N>, InvalidPrivateKeyError> {
        Self::build(token_config, config, transport).map(|client| AppleSeed { client })
    }

    /// Returns how long the caller should wait before calling again — see
    /// `JwksStore::refresh_keystore` for what that duration means and when a
    /// call is skipped for arriving too early.
    ///
    /// Most callers don't need to drive this by hand:
    /// `AppleSeed::with_refresh_loop` (or, with the `tokio-refresh` feature,
    /// `AppleSeed::with_background_refresh`) does it automatically.
    pub async fn refresh_keystore(&self) -> std::time::Duration {
        self.identity_verification.refresh_keystore().await
    }

    /// Returns a future that keeps the JWKS cache warm by calling
    /// `refresh_keystore()` in a loop, sleeping between calls with the
    /// caller-supplied `sleep`. The first tick runs immediately, before any
    /// sleep, so awaiting this future (or spawning it) warms a cold cache
    /// right away instead of leaving the first `get_key()` to pay the fetch
    /// latency. The loop never sleeps for less than one second, even if the
    /// configured `VerificationConfig` would otherwise suggest less — see
    /// `MIN_REFRESH_DELAY`.
    ///
    /// The `use<T, N, S, Fut>` is load-bearing, not decorative: edition 2024
    /// return-position `impl Trait` captures every type/lifetime parameter in
    /// scope by default, including `&self`'s anonymous lifetime. Without
    /// naming the precise capture set here, the returned future would be tied
    /// to `&self`'s lifetime and could not be spawned onto an executor
    /// (`tokio::spawn` requires `'static`). Listing every type parameter
    /// (`N` included, even though the future stores nothing of type `N`) but
    /// no lifetime is what opts the borrow of `self` back out — that's the
    /// whole point of writing it out explicitly instead of just adding
    /// `+ 'static`, which would conflict with the implicitly-captured
    /// `&self` lifetime instead of removing it.
    fn keystore_refresh_loop<S, Fut>(
        &self,
        sleep: S,
    ) -> impl Future<Output = ()> + Send + use<T, N, S, Fut>
    where
        S: Fn(Duration) -> Fut + Send + 'static,
        Fut: Future + Send,
    {
        let weak: Weak<identity_verification::IdentityVerificationClient<T>> =
            Arc::downgrade(&self.identity_verification);
        async move {
            loop {
                let Some(verification) = weak.upgrade() else {
                    return;
                };
                let delay = verification.refresh_keystore().await;
                // Dropped before sleeping: holding a strong reference across
                // the sleep would mean the last live clone being dropped
                // during that sleep goes unnoticed until the *next* tick's
                // `upgrade()` — delaying, not preventing, task exit, but
                // needlessly.
                drop(verification);
                let _ = sleep(delay.max(MIN_REFRESH_DELAY)).await;
            }
        }
    }

    /// `sign_up_or_log_in` with a nonce check of your own. A `Strict` client that
    /// compares the nonce against one expected value should call
    /// `sign_up_or_log_in`; this method is for a `Permissive` client or a
    /// single-use nonce store.
    ///
    /// Verifies an identity token, looks the Apple user up through
    /// `accounts.lookup`, exchanges the authorization code and checks that both
    /// tokens agree on the nonce and the Apple user — the full, safe path for a
    /// typical Sign in with Apple flow. The code is exchanged on **every**
    /// sign-in, so a user who revoked the app in their Apple ID settings and
    /// signed in again gets the new authorization's token instead of keeping a
    /// dead one.
    ///
    /// `nonce_checker` gets the token's `nonce` claim verbatim (`None` only
    /// under `NoncePolicy::Permissive`), called exactly once, for
    /// `identity_token`. `Ok(false)` is a mismatch (`SignInError::NonceMismatch`);
    /// `Err(e)` means the check itself failed (e.g. a database lookup) and is
    /// returned as-is — it is already your `A::Error` — rather than reported as
    /// a false mismatch. After the exchange, this method compares the
    /// exchanged `id_token`'s nonce against the identity token's
    /// already-accepted nonce with `nonce_eq` — see docs/architecture.md, "Why
    /// the exchanged nonce is compared against the identity token's".
    ///
    /// `accounts.lookup` runs after the identity token and its nonce are
    /// verified, but before anything is spent at Apple. Its `AccountState`
    /// decides the outcome and what happens when Apple can't issue a new token:
    ///
    /// - `NotOnFile` is a new authorization: `SignInOutcome::SignedUp` carries
    ///   the new token, and every failure fails the sign-in.
    /// - `AlreadyOnFile { refresh_token }` is a refresh: `SignInOutcome::LoggedIn`
    ///   carries the new token. If Apple can't issue one — the exchange fails
    ///   with `ErrorKind::Unavailable` or `ErrorKind::Misconfigured`, or the
    ///   exchanged `id_token` can't be verified for such a reason — idunn logs
    ///   the error (`warn` and `error` level) and signs the user in with the
    ///   stored token handed back. Apple *refusing* the code
    ///   (`ErrorKind::Rejected`) fails the sign-in; so does a nonce mismatch.
    ///
    /// `Err(e)` from `lookup` is returned as-is — a lookup failure, not a verdict
    /// that the account doesn't exist.
    ///
    /// **Errors.** The error type is your own `A::Error`
    /// (`AppleAccounts::Error`): your hooks' errors pass through unchanged, and
    /// idunn's own failures are a [`SignInError`] converted through the
    /// `From<SignInError>` the trait requires — "returns `SignInError::…`"
    /// below means exactly that. [`SignInError::kind`] classifies them for your
    /// response.
    ///
    /// **Replay.** Exchanging the authorization code is a de-facto single-use
    /// check: replaying a captured identity token fails because the code can't
    /// be spent twice. The one exception is the fallback above, where a known
    /// user is signed in without a new token; there `nonce_checker` is the only
    /// replay defense, so it must be effectively single-use.
    ///
    /// A post-exchange rejection where the exchanged `id_token` names a
    /// different Apple user than the caller's identity token returns
    /// `SignInError::SubjectMismatch`: the token is simply discarded, and
    /// `accounts.schedule_revocation` is never called. Every other post-exchange
    /// rejection (`PostExchangeRejection`: the exchanged `id_token` fails
    /// verification, or its nonce doesn't match) returns
    /// `SignInError::RejectedAfterExchange(cause)`. For a new authorization it
    /// first hands a [`PendingRevocation`] — the token, the verified identity,
    /// the cause, and a fixed `grace_period` — to `accounts.schedule_revocation`
    /// and awaits it. The hook must file the token durably rather than revoke it
    /// inline, per docs/usage.md, "The `AppleAccounts` contract"; it returns
    /// `()` — a failure to file is the hook's own to log. For a refresh the new
    /// token is dropped, never revoked: revoking is authorization-scoped and
    /// would end the stored authorization too. The reasoning is in
    /// docs/architecture.md, "Why `sign_up_or_log_in` never revokes, and
    /// discards another user's token", "Why a post-exchange rejection goes
    /// through `schedule_revocation`" and "Why a refreshed token replaces the
    /// stored one and is never revoked".
    // See docs/architecture.md: "Why the nonce checker is
    // `FnOnce(Option<String>) -> Fut`, not `AsyncFn`" — only `nonce_checker`
    // follows that reasoning. The two storage hooks are `AppleAccounts`
    // methods, see "Why the account hooks are one `AppleAccounts` trait".
    pub async fn sign_up_or_log_in_with_nonce_checker<F, Fut, A>(
        &self,
        identity_token: &str,
        authorization_code: &str,
        nonce_checker: F,
        accounts: &A,
    ) -> Result<SignInOutcome, A::Error>
    where
        F: FnOnce(Option<String>) -> Fut,
        Fut: Future<Output = Result<bool, A::Error>> + Send,
        A: AppleAccounts,
    {
        let verified = self
            .verify_identity_token(identity_token)
            .await
            .map_err(SignInError::IdentityTokenRejected)?;
        if !nonce_checker(verified.nonce.clone()).await? {
            return Err(SignInError::NonceMismatch.into());
        }

        let state = accounts.lookup(&verified.identity).await?;

        let details = match self.exchange_authorization_code(authorization_code).await {
            Ok(details) => details,
            Err(CodeExchangeError::Exchange(err)) => {
                let err = SignInError::Exchange(err);
                return match state {
                    AccountState::AlreadyOnFile { refresh_token } if can_fall_back(&err) => Ok(
                        logged_in_with_stored_token(verified.identity, refresh_token, &err),
                    ),
                    AccountState::AlreadyOnFile { .. } | AccountState::NotOnFile => Err(err.into()),
                };
            }
            Err(CodeExchangeError::ExchangedTokenUnverified {
                refresh_token,
                cause,
            }) => {
                let rejection = PostExchangeRejection::TokenUnverified(cause);
                return match state {
                    AccountState::NotOnFile => Err(reject_after_exchange(
                        accounts,
                        refresh_token,
                        verified.identity,
                        rejection,
                    )
                    .await
                    .into()),
                    // The new token is dropped, never revoked.
                    AccountState::AlreadyOnFile {
                        refresh_token: stored,
                    } => {
                        let err = SignInError::RejectedAfterExchange(rejection);
                        if can_fall_back(&err) {
                            Ok(logged_in_with_stored_token(verified.identity, stored, &err))
                        } else {
                            Err(err.into())
                        }
                    }
                };
            }
        };

        // Checked before the nonce: a stolen authorization code paired with the
        // caller's identity token carries the *thief's* own nonce, which would
        // otherwise be classified as an ordinary `NonceMismatch` and hand a
        // stranger's token back for revocation. See docs/architecture.md.
        if details.identity.apple_user_id != verified.identity.apple_user_id {
            return Err(SignInError::SubjectMismatch.into());
        }

        // See docs/architecture.md, "Why the exchanged nonce is compared
        // against the identity token's".
        let nonces_match = match (verified.nonce.as_deref(), details.nonce.as_deref()) {
            (Some(expected), candidate) => nonce_eq(candidate, expected),
            (None, None) => true,
            (None, Some(_)) => false,
        };
        if !nonces_match {
            return Err(match state {
                AccountState::NotOnFile => {
                    reject_after_exchange(
                        accounts,
                        details.refresh_token,
                        verified.identity,
                        PostExchangeRejection::NonceMismatch,
                    )
                    .await
                }
                // The new token is dropped, never revoked.
                AccountState::AlreadyOnFile { .. } => {
                    SignInError::RejectedAfterExchange(PostExchangeRejection::NonceMismatch)
                }
            }
            .into());
        }

        Ok(match state {
            AccountState::NotOnFile => SignInOutcome::SignedUp {
                identity: details.identity,
                refresh_token: details.refresh_token,
            },
            AccountState::AlreadyOnFile { .. } => SignInOutcome::LoggedIn {
                identity: verified.identity,
                refresh_token: details.refresh_token,
            },
        })
    }

    /// Verify and decode an Apple identity JWT: its signature (against Apple's
    /// published JWKS), `iss`, `aud` and `exp` are all checked, and its nonce
    /// *presence* is enforced per the configured `NoncePolicy`. The nonce
    /// *value* is **not** compared against anything — that step is left to the
    /// caller; see [`IdentityWithPendingNonce::nonce`].
    pub async fn verify_identity_token(
        &self,
        identity_token: &str,
    ) -> Result<IdentityWithPendingNonce, VerificationError> {
        self.identity_verification
            .verify_identity_token(identity_token)
            .await
    }

    /// Exchange an authorization code (from `ASAuthorizationAppleIDCredential`)
    /// for Apple's refresh token, and verify the `id_token` returned alongside
    /// it the same way `verify_identity_token` does — this call also performs a
    /// JWKS fetch (served from the shared cache after the first), so it can
    /// fail with `CannotVerifyToken` in addition to the token-exchange errors.
    /// As with `verify_identity_token`, the `id_token`'s nonce *value* is still
    /// the caller's to check: it is surfaced as `SignInDetails::nonce`.
    ///
    /// If the exchange succeeds but verification fails, Apple has already
    /// issued a live refresh token against a now-consumed authorization code;
    /// the returned `CodeExchangeError::ExchangedTokenUnverified` carries that
    /// token so the caller can revoke it (`revoke_refresh_token`) instead of
    /// losing track of it.
    pub async fn exchange_authorization_code(
        &self,
        authorization_code: &str,
    ) -> Result<SignInDetails, CodeExchangeError> {
        let tokens = token_exchange::exchange_authorization_code(
            &self.transport,
            &self.credentials.token_config,
            &self.credentials.signing_key,
            authorization_code,
        )
        .await?;
        match self.verify_identity_token(&tokens.id_token).await {
            Ok(IdentityWithPendingNonce { nonce, identity }) => Ok(SignInDetails {
                nonce,
                refresh_token: tokens.refresh_token,
                identity,
            }),
            Err(cause) => Err(CodeExchangeError::ExchangedTokenUnverified {
                refresh_token: tokens.refresh_token,
                cause,
            }),
        }
    }

    /// Revoke a refresh token previously issued by Apple (e.g. on sign-out or account
    /// deletion) so it can no longer be used. `Ok(())` means the token is not
    /// usable any more — either because this call revoked it, or because Apple
    /// already considered it invalid (`invalid_grant`, logged at `warn` level).
    /// A failure's [`TokenRevocationError::kind`] says how to treat it.
    pub async fn revoke_refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<(), TokenRevocationError> {
        token_exchange::revoke_refresh_token(
            &self.transport,
            &self.credentials.token_config,
            &self.credentials.signing_key,
            refresh_token,
        )
        .await
    }
}

/// Whether a known user's refresh failing with `err` may still sign the user in
/// with the stored token: Apple being unreachable or this app being
/// misconfigured says nothing against the user, Apple refusing the sign-in does.
fn can_fall_back(err: &SignInError) -> bool {
    err.kind() != ErrorKind::Rejected
}

/// Signs a known user in with the stored token because Apple couldn't issue a
/// new one, logging why. Never logs a token.
fn logged_in_with_stored_token(
    identity: AppleIdentity,
    stored: RefreshToken,
    cause: &SignInError,
) -> SignInOutcome {
    match cause.kind() {
        ErrorKind::Misconfigured => tracing::error!(
            error = %cause,
            "Apple could not issue a new refresh token because this app is \
             misconfigured; signing the user in with the stored one"
        ),
        ErrorKind::Unavailable | ErrorKind::Rejected => tracing::warn!(
            error = %cause,
            "Apple could not issue a new refresh token; signing the user in \
             with the stored one"
        ),
    }
    SignInOutcome::LoggedIn {
        identity,
        refresh_token: stored,
    }
}

/// Only for a new authorization: the refresh token is live at Apple and
/// deliberately left unrevoked by idunn — revoking is authorization-scoped and
/// could tear down a concurrent sign-in for the same Apple user
/// (docs/architecture.md, "Why revocations are coordinated by the host,
/// through `AppleAccounts`"). It goes to the host's
/// `AppleAccounts::schedule_revocation` instead, awaited before the error is
/// returned, so the error itself carries no token to lose — see "Why a
/// post-exchange rejection goes through `schedule_revocation`". A refresh's
/// token is dropped instead.
async fn reject_after_exchange<A: AppleAccounts>(
    accounts: &A,
    refresh_token: RefreshToken,
    identity: AppleIdentity,
    cause: PostExchangeRejection,
) -> SignInError {
    accounts
        .schedule_revocation(PendingRevocation {
            refresh_token,
            identity,
            cause: cause.clone(),
            grace_period: REVOCATION_GRACE_PERIOD,
        })
        .await;
    SignInError::RejectedAfterExchange(cause)
}

/// Constructs a `NoncePolicy::Strict` client — `AppleAuthClient`'s default `N`
/// — so `with_transport`/`new` need no type annotation. The only impl naming
/// `with_transport`/`new`: a second impl under those names, pinned to a
/// different `N`, would make an unannotated call ambiguous. A `Permissive`
/// client is built with `with_nonce_requirement` instead.
impl<T: HttpTransport> AppleAuthClient<T, Strict> {
    pub fn with_transport(
        token_config: AppleTokenConfig,
        config: VerificationConfig,
        transport: T,
    ) -> Result<AppleSeed<T, Strict>, InvalidPrivateKeyError> {
        Self::build(token_config, config, transport).map(|client| AppleSeed { client })
    }
}

#[cfg(feature = "reqwest")]
impl AppleAuthClient<transport::ReqwestTransport, Strict> {
    #[expect(
        clippy::new_ret_no_self,
        reason = "new() hands back an AppleSeed so the refresh strategy must be chosen before use"
    )]
    pub fn new(
        token_config: AppleTokenConfig,
    ) -> Result<AppleSeed<transport::ReqwestTransport, Strict>, InvalidPrivateKeyError> {
        Self::with_transport(
            token_config,
            VerificationConfig::default(),
            transport::ReqwestTransport::default(),
        )
    }
}

/// An `AppleAuthClient` that has been built but not yet given a JWKS refresh
/// strategy: it exposes none of `verify_identity_token`,
/// `sign_up_or_log_in`/`sign_up_or_log_in_with_nonce_checker`,
/// `exchange_authorization_code`, `revoke_refresh_token` or
/// `refresh_keystore`, so it cannot be used before one is chosen. Call
/// `AppleSeed::with_background_refresh` (`tokio-refresh` feature),
/// [`AppleSeed::with_refresh_loop`], or — as an explicit, greppable opt-out —
/// [`AppleSeed::without_background_refresh`] to get an `AppleAuthClient`.
///
/// Named after the apples that keep the gods young in Norse myth (see
/// README, "Why \"idunn\"?"): a seed has to be planted before it grows into
/// a client. See docs/architecture.md, "Why the JWKS refresh strategy is
/// chosen at construction".
#[must_use = "an AppleSeed becomes an AppleAuthClient only via with_background_refresh, with_refresh_loop or without_background_refresh"]
pub struct AppleSeed<T: HttpTransport, N: NonceRequirement = Strict> {
    client: AppleAuthClient<T, N>,
}

impl<T: HttpTransport, N: NonceRequirement> AppleSeed<T, N> {
    /// Returns an `AppleAuthClient` paired with a future that keeps its JWKS
    /// cache warm by calling `refresh_keystore()` in a loop, sleeping between
    /// calls with the caller-supplied `sleep`. The first tick runs
    /// immediately, before any sleep: awaiting or spawning the future warms
    /// a cold cache right away, so the first verification never pays the
    /// fetch latency itself. The loop never sleeps for less than one second,
    /// even if the configured `VerificationConfig` would otherwise suggest
    /// less — see `MIN_REFRESH_DELAY`.
    ///
    /// `idunn` has no runtime dependency of its own: `sleep` is how the
    /// caller supplies its own timer (e.g. `tokio::time::sleep`, or an
    /// `async-io`/`smol` equivalent) without idunn depending on any one
    /// runtime. See docs/architecture.md ("Why the JWKS refresh strategy is
    /// chosen at construction") for `with_background_refresh`, a thin
    /// `tokio-refresh`-gated convenience layer built on top of this method.
    ///
    /// The returned future holds only a `Weak` reference to the returned
    /// client's shared state. It does not keep the client alive, and it
    /// exits (at the latest, on its next tick) once every clone of the
    /// client has been dropped. This is what makes it safe to spawn onto an
    /// executor and forget — the task cannot outlive the client and keep
    /// polling Apple forever.
    ///
    /// ```ignore
    /// let (client, refresh) = AppleAuthClient::new(token_config)?
    ///     .with_refresh_loop(smol::Timer::after);
    /// smol::spawn(refresh).detach();
    /// ```
    #[must_use = "the returned future must be spawned or awaited, or the JWKS cache is never kept warm"]
    pub fn with_refresh_loop<S, Fut>(
        self,
        sleep: S,
    ) -> (
        AppleAuthClient<T, N>,
        impl Future<Output = ()> + Send + use<T, N, S, Fut>,
    )
    where
        S: Fn(Duration) -> Fut + Send + 'static,
        Fut: Future + Send,
    {
        let refresh = self.client.keystore_refresh_loop(sleep);
        (self.client, refresh)
    }

    /// Explicit opt-out: no background refresh is started. JWKS keys are
    /// then fetched lazily inside verification — the cold-cache fetch, and
    /// every subsequent `refresh_interval`, are paid by whichever request
    /// happens to trigger them — unless the caller drives
    /// `AppleAuthClient::refresh_keystore` on its own schedule.
    pub fn without_background_refresh(self) -> AppleAuthClient<T, N> {
        self.client
    }
}

/// Background JWKS-refresh convenience built on `AppleSeed::with_refresh_loop`.
/// See docs/architecture.md ("Why the JWKS refresh strategy is chosen at
/// construction") for why this takes a `Handle` as an explicit parameter,
/// and why it sits behind the optional `tokio-refresh` feature. (`N:
/// NonceRequirement` already implies `N: 'static`, which `handle.spawn`
/// needs — see `NonceRequirement`'s doc in `config.rs`.)
#[cfg(feature = "tokio-refresh")]
impl<T: HttpTransport, N: NonceRequirement> AppleSeed<T, N> {
    /// Spawns a background task that keeps the JWKS cache warm for as long as
    /// any clone of the returned client is alive, then returns the client so
    /// this can be chained straight onto a constructor:
    ///
    /// ```ignore
    /// let client = AppleAuthClient::new(token_config)?
    ///     .with_background_refresh(tokio::runtime::Handle::current());
    /// ```
    ///
    /// `handle` must belong to a runtime with its time driver enabled — the
    /// `#[tokio::main]` macro and `tokio::runtime::Runtime::new()` both do
    /// this already; a hand-built `tokio::runtime::Builder` needs an explicit
    /// `.enable_time()` (or `.enable_all()`), or the spawned task panics the
    /// first time it calls `tokio::time::sleep`.
    #[must_use = "with_background_refresh returns the client for chaining; dropping the result discards it"]
    pub fn with_background_refresh(self, handle: tokio::runtime::Handle) -> AppleAuthClient<T, N> {
        let (client, refresh) = self.with_refresh_loop(tokio::time::sleep);
        handle.spawn(refresh);
        client
    }
}

/// `sign_up_or_log_in` exists only here, on a `Strict` client — see
/// [`NonceRequirement`] and docs/architecture.md ("Why the nonce policy is a
/// type parameter").
impl<T: HttpTransport> AppleAuthClient<T, Strict> {
    /// `sign_up_or_log_in_with_nonce_checker` with a checker that compares the
    /// claim directly against `expected_nonce` — constant-time and ASCII-case-insensitive,
    /// see `nonce_eq`. A missing nonce (`None`) is a rejection, though under
    /// `Strict` that's moot: `verify_identity_token` already rejects a missing
    /// nonce as `IdentityTokenRejected` before the checker runs.
    ///
    /// A `Permissive` client needs `sign_up_or_log_in_with_nonce_checker`
    /// directly, with a checker that decides what a missing nonce means for
    /// its flow (e.g. a replay-detection window from
    /// `AppleIdentity::issued_at`/`expiration`, per `NoncePolicy`):
    ///
    /// ```ignore
    /// client.sign_up_or_log_in_with_nonce_checker(identity_token, code, |candidate| async move {
    ///     match candidate {
    ///         Some(nonce) => Ok(nonce == expected_nonce),
    ///         // Fails with your own AppleAccounts::Error, like lookup does.
    ///         None => my_replay_store.check_and_record(identity_token).await,
    ///     }
    /// }, &accounts).await
    /// ```
    pub async fn sign_up_or_log_in<A: AppleAccounts>(
        &self,
        identity_token: &str,
        authorization_code: &str,
        expected_nonce: &str,
        accounts: &A,
    ) -> Result<SignInOutcome, A::Error> {
        self.sign_up_or_log_in_with_nonce_checker(
            identity_token,
            authorization_code,
            move |candidate| async move {
                Ok::<_, A::Error>(nonce_eq(candidate.as_deref(), expected_nonce))
            },
            accounts,
        )
        .await
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::identity_verification::test_fixtures::{
        TEST_KID, TEST_RSA_PRIVATE_KEY_PEM, jwks_body_including,
    };
    use crate::token_exchange::test_fixtures::{TEST_PUBLIC_KEY_PEM, test_token_config};
    use crate::transport::{HttpGet, HttpPost, TransportError};
    use serde::Deserialize;
    use std::sync::Mutex as StdMutex;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    #[test]
    fn constructs_client_from_token_config() {
        let _client = AppleAuthClient::new(test_token_config())
            .expect("valid test key should construct client");
    }

    #[test]
    fn rejects_malformed_private_key() {
        let mut config = test_token_config();
        config.private_key_pem = b"not a key".to_vec();

        let result = AppleAuthClient::new(config);

        assert!(matches!(result, Err(InvalidPrivateKeyError(_))));
    }

    /// Builds the error a failing POST returns; `TransportError` isn't `Clone`.
    type PostFailure = fn() -> TransportError;

    /// Fake transport serving both verbs `AppleAuthClient` needs: JWKS fetches
    /// (`get`, counted) and Apple's token/revoke endpoints (`post_form`, recorded
    /// with their URL and body so tests can inspect exactly what was sent).
    /// `Clone` shares `get_calls`, `posts` and the failure switches through their
    /// `Arc`s, so calls made through any clone are observed here and a switch
    /// flipped on the transport a test keeps reaches the client's copy.
    #[derive(Clone)]
    struct FakeAppleTransport {
        get_calls: Arc<StdMutex<usize>>,
        posts: Arc<StdMutex<Vec<(String, String)>>>,
        post_failure: Arc<StdMutex<Option<PostFailure>>>,
        /// JWKS fetches after this many calls fail.
        get_failures_after: Arc<StdMutex<Option<usize>>>,
        jwks_body: String,
        post_response: String,
    }

    impl FakeAppleTransport {
        fn new(jwks_body: impl Into<String>, post_response: impl Into<String>) -> Self {
            Self {
                get_calls: Arc::default(),
                posts: Arc::default(),
                post_failure: Arc::default(),
                get_failures_after: Arc::default(),
                jwks_body: jwks_body.into(),
                post_response: post_response.into(),
            }
        }

        fn get_calls(&self) -> usize {
            *self.get_calls.lock().unwrap()
        }

        fn posts(&self) -> Vec<(String, String)> {
            self.posts.lock().unwrap().clone()
        }

        /// Every POST (still recorded) fails with the error `failure` builds.
        fn fail_posts_with(&self, failure: PostFailure) {
            *self.post_failure.lock().unwrap() = Some(failure);
        }

        /// The first `successful_calls` JWKS fetches succeed, later ones fail.
        fn fail_gets_after(&self, successful_calls: usize) {
            *self.get_failures_after.lock().unwrap() = Some(successful_calls);
        }
    }

    impl HttpGet for FakeAppleTransport {
        async fn get(
            &self,
            _url: &str,
            _headers: &[(&str, &str)],
            _timeout: Duration,
        ) -> Result<String, TransportError> {
            let call = {
                let mut calls = self.get_calls.lock().unwrap();
                *calls += 1;
                *calls
            };
            match *self.get_failures_after.lock().unwrap() {
                Some(successful_calls) if call > successful_calls => Err(TransportError::Http {
                    status: 500,
                    body: "jwks unavailable".to_string(),
                }),
                _ => Ok(self.jwks_body.clone()),
            }
        }
    }

    impl HttpPost for FakeAppleTransport {
        async fn post_form(
            &self,
            url: &str,
            _headers: &[(&str, &str)],
            body: &str,
            _timeout: Duration,
        ) -> Result<String, TransportError> {
            self.posts
                .lock()
                .unwrap()
                .push((url.to_string(), body.to_string()));
            if let Some(failure) = *self.post_failure.lock().unwrap() {
                return Err(failure());
            }
            Ok(self.post_response.clone())
        }
    }

    /// A clone must share the JWKS cache **and** the fetch rate limiter, not get
    /// its own. With shared state the 60s default `cooldown_period` suppresses
    /// the clone's refresh and the transport sees exactly one fetch; if a clone
    /// duplicated the state it would be two. This assertion is what pins the
    /// per-field `Arc` design against an accidental un-`Arc` of a field.
    #[tokio::test]
    async fn clone_shares_jwks_cache_and_rate_limiter() {
        let transport = FakeAppleTransport::new(jwks_body_including(TEST_KID), "");
        let client = AppleAuthClient::with_transport(
            test_token_config(),
            VerificationConfig::default(),
            transport.clone(),
        )
        .expect("valid test key should construct client")
        .without_background_refresh();

        client.refresh_keystore().await;
        client.clone().refresh_keystore().await;

        assert_eq!(transport.get_calls(), 1);
    }

    /// Signs an RS256 identity token, playing Apple, with `aud` as its audience,
    /// `sub` as the Apple user id, and a fixed `nonce` of `"expected-nonce"` —
    /// the rest of the claims are fixed. Returns the token plus its `iat`/`exp`
    /// so callers can assert `AppleIdentity::issued_at`/`expiration` exactly.
    fn signed_identity_token(aud: &str, sub: &str) -> (String, u64, u64) {
        signed_identity_token_with_nonce(aud, sub, "expected-nonce")
    }

    /// As `signed_identity_token`, with the `nonce` claim also given explicitly —
    /// for tests that need a token whose nonce does *not* match what the client
    /// expects.
    fn signed_identity_token_with_nonce(aud: &str, sub: &str, nonce: &str) -> (String, u64, u64) {
        signed_identity_token_with_optional_nonce(aud, sub, Some(nonce))
    }

    /// As `signed_identity_token_with_nonce`, but `nonce` may be absent — for
    /// tests exercising `NoncePolicy::Permissive`. `None` serializes as a JSON
    /// `null`, which `ApplePayload.nonce: Option<String>` reads as `None`.
    fn signed_identity_token_with_optional_nonce(
        aud: &str,
        sub: &str,
        nonce: Option<&str>,
    ) -> (String, u64, u64) {
        signed_identity_token_with_kid(aud, sub, nonce, TEST_KID)
    }

    /// As `signed_identity_token_with_optional_nonce`, with the header `kid`
    /// given explicitly — for tests needing a token whose key the fake JWKS does
    /// not publish.
    fn signed_identity_token_with_kid(
        aud: &str,
        sub: &str,
        nonce: Option<&str>,
        kid: &str,
    ) -> (String, u64, u64) {
        let iat = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let exp = iat + 3600;
        let claims = serde_json::json!({
            "sub": sub,
            "email": "user@example.com",
            "nonce": nonce,
            "iss": "https://appleid.apple.com",
            "aud": aud,
            "iat": iat,
            "exp": exp,
        });
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some(kid.to_string());
        let key =
            jsonwebtoken::EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_KEY_PEM.as_bytes()).unwrap();
        let token = jsonwebtoken::encode(&header, &claims, &key).unwrap();
        (token, iat, exp)
    }

    /// Looks up a single `key`'s value in a `application/x-www-form-urlencoded` body.
    fn form_field(body: &str, key: &str) -> Option<String> {
        url::form_urlencoded::parse(body.as_bytes())
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.into_owned())
    }

    /// Verifies a client secret the way Apple would: valid ES256 signature under
    /// the test key pair, and `iss`/`sub` matching `test_token_config()` — i.e.
    /// that `AppleAuthClient` signed with *its own* credentials, not some other
    /// key or config.
    fn assert_client_secret_matches_config(client_secret: &str) {
        #[derive(Deserialize)]
        struct Claims {
            iss: String,
            sub: String,
        }

        let header = jsonwebtoken::decode_header(client_secret).unwrap();
        assert_eq!(header.kid.as_deref(), Some("KEY7890"));

        let decoding_key =
            jsonwebtoken::DecodingKey::from_ec_pem(TEST_PUBLIC_KEY_PEM.as_bytes()).unwrap();
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
        validation.set_audience(&["https://appleid.apple.com"]);
        validation.set_required_spec_claims(&["iss", "iat", "exp", "aud", "sub"]);
        let claims = jsonwebtoken::decode::<Claims>(client_secret, &decoding_key, &validation)
            .unwrap()
            .claims;

        assert_eq!(claims.iss, "TEAM123456");
        assert_eq!(claims.sub, "com.example.myapp");
    }

    #[tokio::test]
    async fn verify_identity_token_returns_the_identity_from_a_token_signed_by_apple() {
        let config = test_token_config();
        let (token, iat, exp) = signed_identity_token(&config.client_id, "apple-user-1");
        let transport = FakeAppleTransport::new(jwks_body_including(TEST_KID), "");
        let client =
            AppleAuthClient::with_transport(config, VerificationConfig::default(), transport)
                .expect("valid test key should construct client")
                .without_background_refresh();

        let IdentityWithPendingNonce { nonce, identity } =
            client.verify_identity_token(&token).await.unwrap();

        assert_eq!(nonce.as_deref(), Some("expected-nonce"));
        assert_eq!(identity.apple_user_id, "apple-user-1");
        assert_eq!(
            identity.email.as_ref().map(|email| email.address.as_str()),
            Some("user@example.com")
        );
        assert_eq!(identity.issued_at, UNIX_EPOCH + Duration::from_secs(iat));
        assert_eq!(identity.expiration, UNIX_EPOCH + Duration::from_secs(exp));
    }

    /// Pins that the audience checked against a token is `AppleAuthClient`'s own
    /// `token_config.client_id`, not some other value: the token here is signed
    /// for the config's original `client_id`, but the client is built from a
    /// config whose `client_id` was changed afterwards, so verification must fail.
    #[tokio::test]
    async fn verify_identity_token_validates_audience_against_the_configured_client_id() {
        let original_config = test_token_config();
        let (token, _, _) = signed_identity_token(&original_config.client_id, "apple-user-1");
        let mut config = original_config;
        config.client_id = "com.example.other".to_string();
        let transport = FakeAppleTransport::new(jwks_body_including(TEST_KID), "");
        let client =
            AppleAuthClient::with_transport(config, VerificationConfig::default(), transport)
                .expect("valid test key should construct client")
                .without_background_refresh();

        let result = client.verify_identity_token(&token).await;

        assert!(matches!(
            result,
            Err(VerificationError::InvalidToken(
                InvalidTokenCause::Rejected(_)
            ))
        ));
    }

    #[tokio::test]
    async fn exchange_authorization_code_posts_a_signed_client_secret_and_returns_the_tokens() {
        let config = test_token_config();
        let (id_token, _, _) = signed_identity_token(&config.client_id, "apple-user-1");
        let transport = FakeAppleTransport::new(
            jwks_body_including(TEST_KID),
            format!(
                r#"{{"access_token":"at","refresh_token":"rt","id_token":"{id_token}","expires_in":3600}}"#
            ),
        );
        let client = AppleAuthClient::with_transport(
            config,
            VerificationConfig::default(),
            transport.clone(),
        )
        .expect("valid test key should construct client")
        .without_background_refresh();

        let response = client
            .exchange_authorization_code("auth-code")
            .await
            .unwrap();

        assert_eq!(response.nonce.as_deref(), Some("expected-nonce"));
        assert_eq!(response.refresh_token.as_str(), "rt");
        assert_eq!(response.identity.apple_user_id, "apple-user-1");

        let posts = transport.posts();
        assert_eq!(posts.len(), 1);
        let (url, body) = &posts[0];
        assert_eq!(url, "https://appleid.apple.com/auth/token");
        assert_eq!(
            form_field(body, "grant_type").as_deref(),
            Some("authorization_code")
        );
        assert_eq!(form_field(body, "code").as_deref(), Some("auth-code"));
        assert_eq!(
            form_field(body, "client_id").as_deref(),
            Some("com.example.myapp")
        );
        assert_client_secret_matches_config(&form_field(body, "client_secret").unwrap());
    }

    /// A successfully exchanged but unverifiable `id_token` must not silently
    /// drop the refresh token Apple already issued: the error variant is the
    /// only place left to hand it back so the caller can revoke it.
    #[tokio::test]
    async fn exchange_authorization_code_carries_the_refresh_token_when_verification_fails() {
        let transport = FakeAppleTransport::new(
            jwks_body_including(TEST_KID),
            r#"{"access_token":"at","refresh_token":"rt","id_token":"it","expires_in":3600}"#,
        );
        let client = AppleAuthClient::with_transport(
            test_token_config(),
            VerificationConfig::default(),
            transport,
        )
        .expect("valid test key should construct client")
        .without_background_refresh();

        let result = client.exchange_authorization_code("auth-code").await;

        match result {
            Err(CodeExchangeError::ExchangedTokenUnverified {
                refresh_token,
                cause,
            }) => {
                assert_eq!(refresh_token.as_str(), "rt");
                assert!(matches!(cause, VerificationError::InvalidToken(_)));
            }
            other => panic!("expected ExchangedTokenUnverified, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn revoke_refresh_token_posts_a_signed_client_secret_to_the_revoke_endpoint() {
        let transport = FakeAppleTransport::new("", "");
        let client = AppleAuthClient::with_transport(
            test_token_config(),
            VerificationConfig::default(),
            transport.clone(),
        )
        .expect("valid test key should construct client")
        .without_background_refresh();

        let result = client.revoke_refresh_token("refresh-token").await;

        assert!(result.is_ok());

        let posts = transport.posts();
        assert_eq!(posts.len(), 1);
        let (url, body) = &posts[0];
        assert_eq!(url, "https://appleid.apple.com/auth/revoke");
        assert_eq!(form_field(body, "token").as_deref(), Some("refresh-token"));
        assert_eq!(
            form_field(body, "token_type_hint").as_deref(),
            Some("refresh_token")
        );
        assert_eq!(
            form_field(body, "client_id").as_deref(),
            Some("com.example.myapp")
        );
        assert_client_secret_matches_config(&form_field(body, "client_secret").unwrap());
    }

    /// Builds a client and an exchange response whose `id_token` is itself a
    /// freshly signed, valid identity token for `sub` — the shape every
    /// `sign_up_or_log_in`/`sign_up_or_log_in_with_nonce_checker` test starts
    /// from, since it lets each test tweak exactly one thing (a nonce, a `sub`)
    /// and still get a well-formed exchange otherwise. Returns the client, the
    /// caller's identity token, and the transport (so posts can be inspected).
    fn client_for_sign_up_or_log_in(
        exchanged_nonce: &str,
        exchanged_sub: &str,
    ) -> (
        AppleAuthClient<FakeAppleTransport>,
        String,
        FakeAppleTransport,
    ) {
        let config = test_token_config();
        let (identity_token, _, _) = signed_identity_token(&config.client_id, "apple-user-1");
        let (exchanged_id_token, _, _) =
            signed_identity_token_with_nonce(&config.client_id, exchanged_sub, exchanged_nonce);
        let transport = FakeAppleTransport::new(
            jwks_body_including(TEST_KID),
            format!(
                r#"{{"access_token":"at","refresh_token":"rt","id_token":"{exchanged_id_token}","expires_in":3600}}"#
            ),
        );
        let client = AppleAuthClient::with_transport(
            config,
            VerificationConfig::default(),
            transport.clone(),
        )
        .expect("valid test key should construct client")
        .without_background_refresh();
        (client, identity_token, transport)
    }

    /// As `client_for_sign_up_or_log_in`, but builds a `Permissive` client and
    /// lets both the identity token's and the exchanged token's nonce be
    /// `None`, for tests exercising `NoncePolicy::Permissive`.
    fn permissive_client_for_sign_up_or_log_in(
        identity_nonce: Option<&str>,
        exchanged_nonce: Option<&str>,
        exchanged_sub: &str,
    ) -> (
        AppleAuthClient<FakeAppleTransport, Permissive>,
        String,
        FakeAppleTransport,
    ) {
        let config = test_token_config();
        let (identity_token, _, _) = signed_identity_token_with_optional_nonce(
            &config.client_id,
            "apple-user-1",
            identity_nonce,
        );
        let (exchanged_id_token, _, _) = signed_identity_token_with_optional_nonce(
            &config.client_id,
            exchanged_sub,
            exchanged_nonce,
        );
        let transport = FakeAppleTransport::new(
            jwks_body_including(TEST_KID),
            format!(
                r#"{{"access_token":"at","refresh_token":"rt","id_token":"{exchanged_id_token}","expires_in":3600}}"#
            ),
        );
        let client = AppleAuthClient::<FakeAppleTransport, Permissive>::with_nonce_requirement(
            config,
            VerificationConfig::default(),
            transport.clone(),
        )
        .expect("valid test key should construct client")
        .without_background_refresh();
        (client, identity_token, transport)
    }

    /// Stand-ins for a host's own `lookup` / `nonce_checker` failures, which
    /// `TestError` wraps. Distinct types, so an assertion that mixes up which hook
    /// failed can't match.
    #[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
    #[error("{0}")]
    struct LookupFailure(&'static str);
    #[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
    #[error("{0}")]
    struct NonceStoreFailure(&'static str);

    /// A host's own error type, shaped the way `AppleAccounts::Error` is meant
    /// to be: idunn's `SignInError` arrives through `From` (so idunn's `?`
    /// lands here), next to the host's own hook failures, which idunn returns
    /// untouched. Not `Clone` (`SignInError` isn't), which is why `TestAccounts`
    /// stores a `LookupFailure` and converts it on each call.
    #[derive(Debug, thiserror::Error)]
    enum TestError {
        #[error(transparent)]
        SignIn(#[from] SignInError),
        #[error("account lookup failed: {0}")]
        Lookup(#[from] LookupFailure),
        #[error("nonce check failed: {0}")]
        NonceStore(#[from] NonceStoreFailure),
    }

    /// Test double for a host's `AppleAccounts`. `lookup` answers with a fixed
    /// result. Scheduling panics unless `recording_revocations()` enabled it, so
    /// a regression that schedules where it shouldn't fails loudly. Both methods
    /// yield once before acting: a test inspecting `scheduled()` after the call
    /// proves idunn awaited the hook, and the futures hold `&self` across an
    /// await, which is the case the `*_future_is_send` guards need to cover.
    struct TestAccounts {
        lookup: Result<AccountState, LookupFailure>,
        scheduled: Option<StdMutex<Vec<PendingRevocation>>>,
    }

    impl TestAccounts {
        /// A new Apple user: this sign-in is a new authorization.
        fn not_on_file() -> Self {
            Self::with_lookup(Ok(AccountState::NotOnFile))
        }

        /// A known Apple user whose stored refresh token is `"stored-rt"`.
        fn already_on_file() -> Self {
            Self::with_lookup(Ok(AccountState::AlreadyOnFile {
                refresh_token: RefreshToken::new("stored-rt".to_string()),
            }))
        }

        fn with_lookup(lookup: Result<AccountState, LookupFailure>) -> Self {
            Self {
                lookup,
                scheduled: None,
            }
        }

        fn recording_revocations(self) -> Self {
            Self {
                scheduled: Some(StdMutex::default()),
                ..self
            }
        }

        fn scheduled(&self) -> Vec<PendingRevocation> {
            let scheduled = self
                .scheduled
                .as_ref()
                .expect("recording_revocations() not enabled");
            std::mem::take(&mut *scheduled.lock().unwrap())
        }
    }

    impl AppleAccounts for TestAccounts {
        type Error = TestError;

        async fn lookup(&self, _identity: &AppleIdentity) -> Result<AccountState, TestError> {
            tokio::task::yield_now().await;
            Ok(self.lookup.clone()?)
        }

        async fn schedule_revocation(&self, pending: PendingRevocation) {
            tokio::task::yield_now().await;
            match &self.scheduled {
                Some(scheduled) => scheduled.lock().unwrap().push(pending),
                None => panic!("unexpected schedule_revocation call: {:?}", pending.cause),
            }
        }
    }

    fn assert_send<T: Send>(_: T) {}

    /// `Send`-bound callers (e.g. axum handlers) need these futures to be `Send`.
    /// Nothing here is awaited, so `client_for_sign_up_or_log_in`'s arguments don't matter.
    #[test]
    fn verification_and_exchange_futures_are_send() {
        let (client, identity_token, _transport) =
            client_for_sign_up_or_log_in("nonce", "apple-user-1");
        assert_send(client.verify_identity_token(&identity_token));
        assert_send(client.exchange_authorization_code("auth-code"));
        assert_send(client.revoke_refresh_token("refresh-token"));
    }

    /// Guards that `sign_up_or_log_in`'s future stays `Send`, as
    /// required by `Send`-bound callers such as axum handlers.
    #[test]
    fn sign_up_or_log_in_future_is_send() {
        let (client, identity_token, _transport) = client_for_sign_up_or_log_in("nonce", "apple-user-1");
        let accounts = TestAccounts::not_on_file();
        assert_send(client.sign_up_or_log_in(
            &identity_token,
            "auth-code",
            "nonce",
            &accounts,
        ));
    }

    /// Guards that `sign_up_or_log_in_with_nonce_checker`'s future stays `Send`
    /// for any checker closure that itself returns a `Send` future, as required
    /// by `Send`-bound callers such as axum handlers. `TestAccounts` implements
    /// `AppleAccounts` with `async fn`s that hold `&self` across an await, so
    /// this guard also covers the `AppleAccounts` futures' contribution to the
    /// overall future's `Send`-ness.
    #[test]
    fn sign_up_or_log_in_with_nonce_checker_future_is_send() {
        let (client, identity_token, _transport) =
            client_for_sign_up_or_log_in("nonce", "apple-user-1");
        let expected = String::from("nonce");
        let accounts = TestAccounts::not_on_file();
        assert_send(client.sign_up_or_log_in_with_nonce_checker(
            &identity_token,
            "auth-code",
            move |candidate| {
                let expected = expected.clone();
                async move {
                    Ok::<bool, TestError>(candidate.as_deref() == Some(expected.as_str()))
                }
            },
            &accounts,
        ));
    }

    /// Every host's `AppleAccounts::Error` embeds `SignInError` (it must be
    /// `From<SignInError>`), and `sign_up_or_log_in` returns that type from every
    /// frame on the success path too — so `SignInError` must stay under clippy's
    /// 128-byte `result_large_err` budget or it inflates every host's error.
    /// `RejectedAfterExchange` carries `PostExchangeRejection` unboxed — the live
    /// token and its `grace_period` go to `schedule_revocation`, not into the
    /// error, so nothing large rides along.
    #[test]
    fn sign_in_error_stays_small() {
        assert!(std::mem::size_of::<SignInError>() <= 128);
    }

    #[tokio::test]
    async fn sign_up_or_log_in_returns_the_identity_when_both_tokens_verify() {
        let (client, identity_token, transport) =
            client_for_sign_up_or_log_in("expected-nonce", "apple-user-1");

        let outcome = client
            .sign_up_or_log_in(
                &identity_token,
                "auth-code",
                "expected-nonce",
                &TestAccounts::not_on_file(),
            )
            .await
            .unwrap();

        match outcome {
            SignInOutcome::SignedUp {
                identity,
                refresh_token,
            } => {
                assert_eq!(refresh_token.as_str(), "rt");
                assert_eq!(identity.apple_user_id, "apple-user-1");
            }
            other => panic!("expected SignedUp, got {other:?}"),
        }
        assert_eq!(transport.posts().len(), 1);
        assert_eq!(
            transport.posts()[0].0,
            "https://appleid.apple.com/auth/token"
        );
    }

    /// A checker that consumes a pending nonce (single-use, e.g. removing it
    /// from a store) must only ever be called once. Regression test for the
    /// bug where the exchanged token's nonce was passed back through
    /// `nonce_checker` a second time, which made a single-use checker reject
    /// every sign-up.
    #[tokio::test]
    async fn sign_up_or_log_in_signs_up_with_a_single_use_nonce_checker() {
        let (client, identity_token, _transport) =
            client_for_sign_up_or_log_in("expected-nonce", "apple-user-1");
        let pending = Arc::new(StdMutex::new(std::collections::HashSet::from([
            "expected-nonce".to_string(),
        ])));

        let outcome = client
            .sign_up_or_log_in_with_nonce_checker(
                &identity_token,
                "auth-code",
                move |candidate| {
                    let pending = pending.clone();
                    async move {
                        let removed = candidate
                            .map(|nonce| pending.lock().unwrap().remove(&nonce))
                            .unwrap_or(false);
                        Ok::<bool, TestError>(removed)
                    }
                },
                &TestAccounts::not_on_file(),
            )
            .await
            .unwrap();

        assert!(matches!(outcome, SignInOutcome::SignedUp { .. }));
    }

    /// Under `NoncePolicy::Permissive`, an identity token and its exchanged
    /// `id_token` may both legitimately carry no `nonce` claim.
    #[tokio::test]
    async fn permissive_sign_up_or_log_in_signs_up_when_neither_token_carries_a_nonce() {
        let (client, identity_token, _transport) =
            permissive_client_for_sign_up_or_log_in(None, None, "apple-user-1");

        let outcome = client
            .sign_up_or_log_in_with_nonce_checker(
                &identity_token,
                "auth-code",
                |_candidate| async move { Ok::<bool, TestError>(true) },
                &TestAccounts::not_on_file(),
            )
            .await
            .unwrap();

        assert!(matches!(outcome, SignInOutcome::SignedUp { .. }));
    }

    /// An exchanged `id_token` carrying a nonce the identity token lacked is a
    /// mismatch, not a silent pass — nothing was accepted to compare it
    /// against.
    #[tokio::test]
    async fn permissive_sign_up_or_log_in_rejects_an_exchanged_nonce_the_identity_token_lacked() {
        let (client, identity_token, _transport) =
            permissive_client_for_sign_up_or_log_in(None, Some("some-nonce"), "apple-user-1");
        let accounts = TestAccounts::not_on_file().recording_revocations();

        let result = client
            .sign_up_or_log_in_with_nonce_checker(
                &identity_token,
                "auth-code",
                |_candidate| async move { Ok::<bool, TestError>(true) },
                &accounts,
            )
            .await;

        assert!(matches!(
            result,
            Err(TestError::SignIn(SignInError::RejectedAfterExchange(
                PostExchangeRejection::NonceMismatch
            )))
        ));
        let jobs = accounts.scheduled();
        assert_eq!(jobs.len(), 1);
        assert!(matches!(jobs[0].cause, PostExchangeRejection::NonceMismatch));
    }

    /// A mismatched identity-token nonce is rejected before the authorization
    /// code is ever exchanged — pins that `sign_up_or_log_in` checks the free
    /// thing first.
    #[tokio::test]
    async fn sign_up_or_log_in_rejects_a_mismatched_identity_token_nonce_without_spending_the_code()
    {
        let (client, identity_token, transport) =
            client_for_sign_up_or_log_in("expected-nonce", "apple-user-1");

        let result = client
            .sign_up_or_log_in(
                &identity_token,
                "auth-code",
                "wrong-nonce",
                &TestAccounts::not_on_file(),
            )
            .await;

        assert!(matches!(
            result,
            Err(TestError::SignIn(SignInError::NonceMismatch))
        ));
        assert!(transport.posts().is_empty());
    }

    /// An unverifiable exchanged `id_token` leaves a live refresh token behind
    /// that `sign_up_or_log_in` hands to `schedule_revocation`, and awaits,
    /// before returning — no revoke attempt — for the host to revoke after
    /// the call returns. See docs/architecture.md, "Why revocations are
    /// coordinated by the host, through `AppleAccounts`".
    #[tokio::test]
    async fn sign_up_or_log_in_schedules_revocation_for_an_unverifiable_exchanged_token() {
        let config = test_token_config();
        let (identity_token, _, _) = signed_identity_token(&config.client_id, "apple-user-1");
        let transport = FakeAppleTransport::new(
            jwks_body_including(TEST_KID),
            r#"{"access_token":"at","refresh_token":"rt","id_token":"not-a-jwt","expires_in":3600}"#,
        );
        let client = AppleAuthClient::with_transport(config, VerificationConfig::default(), transport.clone())
            .expect("valid test key should construct client")
            .without_background_refresh();
        let accounts = TestAccounts::not_on_file().recording_revocations();

        let result = client
            .sign_up_or_log_in(
                &identity_token,
                "auth-code",
                "expected-nonce",
                &accounts,
            )
            .await;

        assert!(matches!(
            result,
            Err(TestError::SignIn(SignInError::RejectedAfterExchange(
                PostExchangeRejection::TokenUnverified(_)
            )))
        ));
        let jobs = accounts.scheduled();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].refresh_token.as_str(), "rt");
        assert_eq!(jobs[0].identity.apple_user_id, "apple-user-1");
        assert!(matches!(jobs[0].cause, PostExchangeRejection::TokenUnverified(_)));
        assert_eq!(jobs[0].grace_period, REVOCATION_GRACE_PERIOD);
        let posts = transport.posts();
        assert_eq!(posts.len(), 1);
        assert_eq!(posts[0].0, "https://appleid.apple.com/auth/token");
    }

    #[tokio::test]
    async fn sign_up_or_log_in_schedules_revocation_when_the_exchanged_nonce_does_not_match() {
        let (client, identity_token, transport) =
            client_for_sign_up_or_log_in("a-different-nonce", "apple-user-1");
        let accounts = TestAccounts::not_on_file().recording_revocations();

        let result = client
            .sign_up_or_log_in(
                &identity_token,
                "auth-code",
                "expected-nonce",
                &accounts,
            )
            .await;

        assert!(matches!(
            result,
            Err(TestError::SignIn(SignInError::RejectedAfterExchange(
                PostExchangeRejection::NonceMismatch
            )))
        ));
        let jobs = accounts.scheduled();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].refresh_token.as_str(), "rt");
        assert!(matches!(jobs[0].cause, PostExchangeRejection::NonceMismatch));
        assert_eq!(jobs[0].grace_period, REVOCATION_GRACE_PERIOD);
        let posts = transport.posts();
        assert_eq!(posts.len(), 1);
        assert_eq!(posts[0].0, "https://appleid.apple.com/auth/token");
    }

    /// Regression test for the identity-confusion gap this crate's
    /// `sign_up_or_log_in` closes: pairing one Apple user's identity token
    /// with an authorization code that resolves to a different Apple user.
    /// The token is simply discarded: see docs/architecture.md, "Why
    /// `sign_up_or_log_in` never revokes, and discards another user's token".
    /// Also pins that `SubjectMismatch` never calls `schedule_revocation`.
    #[tokio::test]
    async fn sign_up_or_log_in_discards_the_token_when_the_exchanged_id_token_is_for_another_user()
    {
        let (client, identity_token, transport) =
            client_for_sign_up_or_log_in("expected-nonce", "apple-user-2");

        let result = client
            .sign_up_or_log_in(
                &identity_token,
                "auth-code",
                "expected-nonce",
                &TestAccounts::not_on_file(),
            )
            .await;

        assert!(matches!(
            result,
            Err(TestError::SignIn(SignInError::SubjectMismatch))
        ));
        let posts = transport.posts();
        assert_eq!(posts.len(), 1);
        assert_eq!(posts[0].0, "https://appleid.apple.com/auth/token");
    }

    /// A foreign authorization code carries the thief's own nonce, not the
    /// caller's — pins that the subject check runs before the nonce check, so
    /// it's always classified as `SubjectMismatch`, never `RejectedAfterExchange`,
    /// and nothing is scheduled.
    #[tokio::test]
    async fn sign_up_or_log_in_checks_the_subject_before_the_exchanged_nonce() {
        let (client, identity_token, _transport) =
            client_for_sign_up_or_log_in("a-different-nonce", "apple-user-2");

        let result = client
            .sign_up_or_log_in(
                &identity_token,
                "auth-code",
                "expected-nonce",
                &TestAccounts::not_on_file(),
            )
            .await;

        assert!(matches!(
            result,
            Err(TestError::SignIn(SignInError::SubjectMismatch))
        ));
    }

    /// A nonce lookup that fails outright (e.g. a database error) must not be
    /// reported the same way as a nonce the caller actually rejected — it comes
    /// back as the checker's own error, untouched.
    #[tokio::test]
    async fn sign_up_or_log_in_reports_a_failed_nonce_lookup_separately_from_a_mismatch() {
        let (client, identity_token, transport) =
            client_for_sign_up_or_log_in("expected-nonce", "apple-user-1");

        let result = client
            .sign_up_or_log_in_with_nonce_checker(
                &identity_token,
                "auth-code",
                |_candidate| async move {
                    Err::<bool, TestError>(NonceStoreFailure("session store unavailable").into())
                },
                &TestAccounts::not_on_file(),
            )
            .await;

        assert!(matches!(
            result,
            Err(TestError::NonceStore(NonceStoreFailure(
                "session store unavailable"
            )))
        ));
        assert!(transport.posts().is_empty());
    }

    #[tokio::test]
    async fn sign_up_or_log_in_matches_the_nonce_case_insensitively() {
        let (client, identity_token, _transport) =
            client_for_sign_up_or_log_in("Expected-Nonce", "apple-user-1");

        let result = client
            .sign_up_or_log_in(
                &identity_token,
                "auth-code",
                "EXPECTED-NONCE",
                &TestAccounts::not_on_file(),
            )
            .await;

        assert!(result.is_ok());
    }

    /// The `LoggedIn` a known user gets: its identity's Apple user id and the
    /// refresh token the host is to write.
    fn expect_logged_in(outcome: SignInOutcome) -> (String, String) {
        match outcome {
            SignInOutcome::LoggedIn {
                identity,
                refresh_token,
            } => (identity.apple_user_id, refresh_token.into_inner()),
            other => panic!("expected LoggedIn, got {other:?}"),
        }
    }

    /// Every sign-in spends the code, so a known user whose stored token went
    /// dead (the app revoked in Apple ID settings) gets the new authorization's
    /// token instead of keeping the dead one.
    #[tokio::test]
    async fn logs_in_with_a_refreshed_token_when_one_is_on_file() {
        let (client, identity_token, transport) =
            client_for_sign_up_or_log_in("expected-nonce", "apple-user-1");

        let outcome = client
            .sign_up_or_log_in(
                &identity_token,
                "auth-code",
                "expected-nonce",
                &TestAccounts::already_on_file(),
            )
            .await
            .unwrap();

        let (apple_user_id, refresh_token) = expect_logged_in(outcome);
        assert_eq!(apple_user_id, "apple-user-1");
        assert_eq!(refresh_token, "rt");
        let posts = transport.posts();
        assert_eq!(posts.len(), 1);
        assert_eq!(posts[0].0, "https://appleid.apple.com/auth/token");
    }

    /// Apple being unreachable must not lock a known user out: the stored token
    /// is handed back for the host to keep.
    #[tokio::test]
    async fn logs_in_with_the_stored_token_when_the_exchange_cannot_reach_apple() {
        let (client, identity_token, transport) =
            client_for_sign_up_or_log_in("expected-nonce", "apple-user-1");
        transport.fail_posts_with(|| TransportError::Network("connection reset".into()));

        let outcome = client
            .sign_up_or_log_in(
                &identity_token,
                "auth-code",
                "expected-nonce",
                &TestAccounts::already_on_file(),
            )
            .await
            .unwrap();

        let (apple_user_id, refresh_token) = expect_logged_in(outcome);
        assert_eq!(apple_user_id, "apple-user-1");
        assert_eq!(refresh_token, "stored-rt");
    }

    /// Our own misconfiguration is no reason to fail a known user's login either;
    /// it is logged at error level instead.
    #[tokio::test]
    async fn logs_in_with_the_stored_token_when_the_exchange_is_misconfigured() {
        let (client, identity_token, transport) =
            client_for_sign_up_or_log_in("expected-nonce", "apple-user-1");
        transport.fail_posts_with(|| TransportError::Http {
            status: 400,
            body: r#"{"error":"invalid_client"}"#.to_string(),
        });

        let outcome = client
            .sign_up_or_log_in(
                &identity_token,
                "auth-code",
                "expected-nonce",
                &TestAccounts::already_on_file(),
            )
            .await
            .unwrap();

        let (apple_user_id, refresh_token) = expect_logged_in(outcome);
        assert_eq!(apple_user_id, "apple-user-1");
        assert_eq!(refresh_token, "stored-rt");
    }

    /// Apple refusing the code itself is a verdict on this sign-in, not an
    /// outage: falling back to the stored token would log in with a code Apple
    /// says is bad.
    #[tokio::test]
    async fn fails_a_known_users_sign_in_when_apple_rejects_the_code() {
        let (client, identity_token, transport) =
            client_for_sign_up_or_log_in("expected-nonce", "apple-user-1");
        transport.fail_posts_with(|| TransportError::Http {
            status: 400,
            body: r#"{"error":"invalid_grant"}"#.to_string(),
        });

        let result = client
            .sign_up_or_log_in(
                &identity_token,
                "auth-code",
                "expected-nonce",
                &TestAccounts::already_on_file(),
            )
            .await;

        assert!(matches!(
            result,
            Err(TestError::SignIn(SignInError::Exchange(
                TokenExchangeError::TokenExchangeFailed(AppleErrorCode::InvalidGrant)
            )))
        ));
    }

    /// With no stored token to fall back on, an exchange failure fails the
    /// sign-in whatever its kind.
    #[tokio::test]
    async fn fails_a_new_users_sign_up_when_the_exchange_cannot_reach_apple() {
        let (client, identity_token, transport) =
            client_for_sign_up_or_log_in("expected-nonce", "apple-user-1");
        transport.fail_posts_with(|| TransportError::Network("connection reset".into()));

        let result = client
            .sign_up_or_log_in(
                &identity_token,
                "auth-code",
                "expected-nonce",
                &TestAccounts::not_on_file(),
            )
            .await;

        assert!(matches!(
            result,
            Err(TestError::SignIn(SignInError::Exchange(
                TokenExchangeError::NetworkError(_)
            )))
        ));
    }

    /// A refresh is never revoked, so a post-exchange rejection on a known user
    /// drops the new token: `TestAccounts` panics on `schedule_revocation`.
    #[tokio::test]
    async fn drops_the_new_token_when_the_exchanged_nonce_does_not_match_a_known_user() {
        let (client, identity_token, _transport) =
            client_for_sign_up_or_log_in("a-different-nonce", "apple-user-1");

        let result = client
            .sign_up_or_log_in(
                &identity_token,
                "auth-code",
                "expected-nonce",
                &TestAccounts::already_on_file(),
            )
            .await;

        assert!(matches!(
            result,
            Err(TestError::SignIn(SignInError::RejectedAfterExchange(
                PostExchangeRejection::NonceMismatch
            )))
        ));
    }

    #[tokio::test]
    async fn drops_the_new_token_when_the_exchanged_id_token_is_rejected_for_a_known_user() {
        let config = test_token_config();
        let (identity_token, _, _) = signed_identity_token(&config.client_id, "apple-user-1");
        let transport = FakeAppleTransport::new(
            jwks_body_including(TEST_KID),
            r#"{"access_token":"at","refresh_token":"rt","id_token":"not-a-jwt","expires_in":3600}"#,
        );
        let client = AppleAuthClient::with_transport(
            config,
            VerificationConfig::default(),
            transport.clone(),
        )
        .expect("valid test key should construct client")
        .without_background_refresh();

        let result = client
            .sign_up_or_log_in(
                &identity_token,
                "auth-code",
                "expected-nonce",
                &TestAccounts::already_on_file(),
            )
            .await;

        assert!(matches!(
            result,
            Err(TestError::SignIn(SignInError::RejectedAfterExchange(
                PostExchangeRejection::TokenUnverified(_)
            )))
        ));
        assert_eq!(transport.posts().len(), 1);
    }

    /// The exchanged `id_token` couldn't be checked (Apple's keys unreachable),
    /// which says nothing against the user: log in with the stored token and drop
    /// the new one.
    #[tokio::test]
    async fn logs_in_with_the_stored_token_when_the_exchanged_id_token_cannot_be_verified() {
        let config = test_token_config();
        let (identity_token, _, _) = signed_identity_token(&config.client_id, "apple-user-1");
        let (exchanged_id_token, _, _) = signed_identity_token_with_kid(
            &config.client_id,
            "apple-user-1",
            Some("expected-nonce"),
            "unpublished-kid",
        );
        let transport = FakeAppleTransport::new(
            jwks_body_including(TEST_KID),
            format!(
                r#"{{"access_token":"at","refresh_token":"rt","id_token":"{exchanged_id_token}","expires_in":3600}}"#
            ),
        );
        // Every snapshot is instantly due for a refresh and nothing rate-limits
        // it, so the exchanged token's unknown `kid` forces a fetch, which fails.
        let verification_config = VerificationConfig {
            refresh_interval: Duration::ZERO,
            cooldown_period: Duration::ZERO,
            stale_key_grace_period: Duration::ZERO,
            max_key_age: Duration::from_secs(3600),
        };
        let client =
            AppleAuthClient::with_transport(config, verification_config, transport.clone())
                .expect("valid test key should construct client")
                .without_background_refresh();
        transport.fail_gets_after(1);

        let outcome = client
            .sign_up_or_log_in(
                &identity_token,
                "auth-code",
                "expected-nonce",
                &TestAccounts::already_on_file(),
            )
            .await
            .unwrap();

        let (apple_user_id, refresh_token) = expect_logged_in(outcome);
        assert_eq!(apple_user_id, "apple-user-1");
        assert_eq!(refresh_token, "stored-rt");
        assert_eq!(transport.posts().len(), 1);
    }

    #[tokio::test]
    async fn reports_a_failed_account_lookup_separately() {
        let (client, identity_token, transport) =
            client_for_sign_up_or_log_in("expected-nonce", "apple-user-1");

        let result = client
            .sign_up_or_log_in(
                &identity_token,
                "auth-code",
                "expected-nonce",
                &TestAccounts::with_lookup(Err(LookupFailure("account store unavailable"))),
            )
            .await;

        assert!(matches!(
            result,
            Err(TestError::Lookup(LookupFailure(
                "account store unavailable"
            )))
        ));
        assert!(transport.posts().is_empty());
    }

    /// Tests for `keystore_refresh_loop`. None of these use `tokio::time`'s
    /// paused/mocked clock (`start_paused`/`pause()`): `JwksStore` measures
    /// freshness with `std::time::Instant::elapsed()` (see `jwks_store.rs`),
    /// which a paused tokio clock has no effect on, so pausing here would
    /// desync the loop's notion of elapsed time from the sleeps it awaits —
    /// exactly the kind of busy-loop trap `MIN_REFRESH_DELAY` exists to catch
    /// in production. Tests 1-3 below run on `#[tokio::test]` (they need *an*
    /// executor to await a future at all) but drive `keystore_refresh_loop`
    /// with a plain non-tokio sleep closure — proof the loop itself has no
    /// tokio dependency.
    mod keystore_refresh_loop_tests {
        use super::*;

        /// Wires `client` up to a fake, immediately-resolving `sleep` that
        /// records every requested duration into `recorded` and, once
        /// `iterations` durations have been recorded, drops `client` — its
        /// last strong reference, since `client` is moved in here rather than
        /// cloned — so the loop's next `Weak::upgrade()` fails and it
        /// returns. This is what lets a test await the returned future to
        /// completion instead of needing to time out or abort a task.
        fn recording_loop<T: HttpTransport, N: NonceRequirement>(
            client: AppleAuthClient<T, N>,
            iterations: usize,
            recorded: Arc<StdMutex<Vec<Duration>>>,
        ) -> impl Future<Output = ()> + Send + 'static {
            let holder = Arc::new(StdMutex::new(Some(client)));
            let guard = holder.lock().unwrap();
            let holder_for_stop = holder.clone();
            let future = guard
                .as_ref()
                .unwrap()
                .keystore_refresh_loop(move |d: Duration| {
                    let count = {
                        let mut recorded = recorded.lock().unwrap();
                        recorded.push(d);
                        recorded.len()
                    };
                    if count >= iterations {
                        *holder_for_stop.lock().unwrap() = None;
                    }
                    std::future::ready(())
                });
            drop(guard);
            future
        }

        #[tokio::test]
        async fn first_tick_runs_immediately_before_any_sleep() {
            let transport = FakeAppleTransport::new(jwks_body_including(TEST_KID), "");
            let client = AppleAuthClient::with_transport(
                test_token_config(),
                VerificationConfig::default(),
                transport.clone(),
            )
            .expect("valid test key should construct client")
            .without_background_refresh();

            // A sleep that never resolves: proves the fetch that produced
            // `get_calls() == 1` happened *before* the loop ever reached its
            // first sleep, not concurrently with it.
            let task = tokio::spawn(
                client.keystore_refresh_loop(|_: Duration| std::future::pending::<()>()),
            );

            for _ in 0..20 {
                tokio::task::yield_now().await;
            }

            assert_eq!(transport.get_calls(), 1);
            task.abort();
        }

        #[tokio::test]
        async fn too_early_ticks_never_refetch_and_stay_near_refresh_interval() {
            let transport = FakeAppleTransport::new(jwks_body_including(TEST_KID), "");
            let config = VerificationConfig::default(); // 6h refresh_interval
            let client =
                AppleAuthClient::with_transport(test_token_config(), config, transport.clone())
                    .expect("valid test key should construct client")
                    .without_background_refresh();

            let recorded = Arc::new(StdMutex::new(Vec::new()));
            recording_loop(client, 5, recorded.clone()).await;

            assert_eq!(transport.get_calls(), 1);
            let recorded = recorded.lock().unwrap();
            assert_eq!(recorded.len(), 5);
            for wait in recorded.iter() {
                assert!(*wait <= config.refresh_interval);
                assert!(*wait > config.refresh_interval - Duration::from_secs(1));
            }
        }

        #[tokio::test]
        async fn min_refresh_delay_floors_a_zero_configured_cadence() {
            let transport = FakeAppleTransport::new(jwks_body_including(TEST_KID), "");
            let config = VerificationConfig {
                refresh_interval: Duration::ZERO,
                cooldown_period: Duration::ZERO,
                stale_key_grace_period: Duration::ZERO,
                max_key_age: Duration::from_secs(3600),
            };
            let client =
                AppleAuthClient::with_transport(test_token_config(), config, transport.clone())
                    .expect("valid test key should construct client")
                    .without_background_refresh();

            // With refresh_interval and cooldown_period both zero, every tick
            // refetches (no early-return, no cooldown skip) — without the
            // MIN_REFRESH_DELAY floor this would be a busy loop hammering
            // Apple. `get_calls()` is deliberately not asserted here: with a
            // zero-cadence config it grows on every iteration by design, and
            // the floor is what this test is pinning, not the fetch count.
            let recorded = Arc::new(StdMutex::new(Vec::new()));
            recording_loop(client, 5, recorded.clone()).await;

            let recorded = recorded.lock().unwrap();
            assert_eq!(recorded.len(), 5);
            for wait in recorded.iter() {
                assert!(
                    *wait >= MIN_REFRESH_DELAY,
                    "expected every recorded sleep to be floored at {MIN_REFRESH_DELAY:?}, got {wait:?}"
                );
            }
        }

        #[tokio::test]
        async fn loop_exits_once_every_clone_is_dropped_and_stops_fetching() {
            let transport = FakeAppleTransport::new(jwks_body_including(TEST_KID), "");
            let config = VerificationConfig {
                refresh_interval: Duration::from_millis(20),
                cooldown_period: Duration::from_millis(20),
                stale_key_grace_period: Duration::ZERO,
                max_key_age: Duration::from_secs(3600),
            };
            let client =
                AppleAuthClient::with_transport(test_token_config(), config, transport.clone())
                    .expect("valid test key should construct client")
                    .without_background_refresh();

            // Real tokio::time::sleep and real time throughout: this test is
            // measuring that the task actually stops running, which a fake,
            // immediately-resolving sleep can't demonstrate.
            tokio::spawn(client.keystore_refresh_loop(tokio::time::sleep));

            // Let the first (immediate) tick land.
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert_eq!(
                transport.get_calls(),
                1,
                "expected exactly one fetch from the immediate first tick"
            );

            drop(client);

            // The loop is now asleep for MIN_REFRESH_DELAY (1s, far longer
            // than the 20ms refresh_interval/cooldown_period configured
            // above) before its next `Weak::upgrade()`. Wait past that
            // floor so the task has woken up, found the client gone, and
            // returned without fetching again.
            tokio::time::sleep(Duration::from_millis(1200)).await;

            assert_eq!(
                transport.get_calls(),
                1,
                "task kept fetching after every client clone was dropped"
            );
        }

        #[tokio::test]
        async fn with_refresh_loop_returns_a_future_that_warms_the_cache() {
            let transport = FakeAppleTransport::new(jwks_body_including(TEST_KID), "");
            let seed = AppleAuthClient::with_transport(
                test_token_config(),
                VerificationConfig::default(),
                transport.clone(),
            )
            .expect("valid test key should construct client");

            let (_client, refresh) =
                seed.with_refresh_loop(|_: Duration| std::future::pending::<()>());
            let task = tokio::spawn(refresh);

            for _ in 0..20 {
                tokio::task::yield_now().await;
            }

            assert_eq!(transport.get_calls(), 1);
            task.abort();
        }

        #[tokio::test]
        async fn with_background_refresh_spawns_a_loop_that_warms_the_cache() {
            let transport = FakeAppleTransport::new(jwks_body_including(TEST_KID), "");
            let seed = AppleAuthClient::with_transport(
                test_token_config(),
                VerificationConfig::default(),
                transport.clone(),
            )
            .expect("valid test key should construct client");

            let _client = seed.with_background_refresh(tokio::runtime::Handle::current());

            for _ in 0..20 {
                tokio::task::yield_now().await;
            }

            assert_eq!(transport.get_calls(), 1);
        }

        #[tokio::test]
        async fn without_background_refresh_fetches_nothing_up_front() {
            let transport = FakeAppleTransport::new(jwks_body_including(TEST_KID), "");
            let _client = AppleAuthClient::with_transport(
                test_token_config(),
                VerificationConfig::default(),
                transport.clone(),
            )
            .expect("valid test key should construct client")
            .without_background_refresh();

            for _ in 0..20 {
                tokio::task::yield_now().await;
            }

            assert_eq!(transport.get_calls(), 0);
        }
    }
}
