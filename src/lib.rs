#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
#![doc = include_str!("../docs/usage.md")]
// https://developer.apple.com/documentation/technotes/tn3194-handling-account-deletions-and-revoking-tokens-for-sign-in-with-apple
// https://developer.apple.com/documentation/signinwithapplerestapi/revoke-tokens
// https://developer.apple.com/support/offering-account-deletion-in-your-app/

mod config;
mod error;
mod identity_verification;
mod jwks_store;
mod token_exchange;
mod transport;

pub use config::{NoncePolicy, NonceRequirement, Permissive, Strict, VerificationConfig};
pub use error::{
    AppleErrorCode, ClientSecretError, CodeExchangeError, InvalidPrivateKeyError,
    InvalidTokenCause, PendingRevocation, PostExchangeRejection, SignInError, TokenExchangeError,
    TokenRevocationError, VerificationError,
};
pub use identity_verification::{AppleEmail, AppleIdentity, IdentityWithPendingNonce, RealUserStatus};
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

/// ASCII-case-insensitive and constant-time: case-insensitivity handles clients
/// that hex-encode in upper case, constant time protects a server-side-secret
/// `expected_nonce` from a timing side channel — see docs/architecture.md for
/// the limits of that protection. Used by `sign_up_or_log_in_with_nonce`, and
/// internally by `sign_up_or_log_in` to compare the exchanged `id_token`'s
/// nonce against the identity token's already-accepted nonce.
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

/// What the caller found when looking up this Apple user before spending the
/// authorization code. `NeedsExchange` covers both a genuinely new user and a
/// user on file whose stored refresh token is no longer usable — idunn treats
/// both the same way (exchange the code), so nothing is gained by asking the
/// caller to distinguish them here. See docs/architecture.md for why a stale
/// token is discarded rather than revoked.
#[derive(Debug, Clone)]
pub enum AccountState {
    /// No refresh token on file that this sign-in can reuse: exchange the code.
    NeedsExchange,
    /// A refresh token already on file for this Apple user is still good:
    /// skip the exchange, the authorization code stays unspent.
    AlreadyOnFile,
}

/// What `sign_up_or_log_in` produced: a login against an already-known
/// account (no code spent) or a full sign-up (code exchanged for a new
/// refresh token).
#[derive(Debug, Clone)]
pub enum SignInOutcome {
    LoggedIn {
        identity: AppleIdentity,
    },
    SignedUp {
        identity: AppleIdentity,
        refresh_token: RefreshToken,
    },
}

impl SignInOutcome {
    /// The verified identity either way. **Provenance differs by variant:**
    /// `LoggedIn` carries the identity from the caller's own identity token;
    /// `SignedUp` carries the identity from the exchanged `id_token`.
    pub fn identity(&self) -> &AppleIdentity {
        match self {
            SignInOutcome::LoggedIn { identity } => identity,
            SignInOutcome::SignedUp { identity, .. } => identity,
        }
    }
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
/// `sign_up_or_log_in_with_nonce` exists on this client — see
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
    ) -> Result<Self, InvalidPrivateKeyError> {
        Self::build(token_config, config, transport)
    }

    /// Returns how long the caller should wait before calling again — see
    /// `JwksStore::refresh_keystore` for what that duration means and when a
    /// call is skipped for arriving too early.
    ///
    /// Most callers don't need to drive this by hand: `keystore_refresh_loop`
    /// (or, with the `tokio-refresh` feature, `with_background_refresh`) does
    /// it automatically.
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
    /// `idunn` has no runtime dependency of its own: `sleep` is how the
    /// caller supplies its own timer (e.g. `tokio::time::sleep`, or an
    /// `async-io`/`smol` equivalent) without idunn depending on any one
    /// runtime. See docs/architecture.md ("Why background refresh is opt-in
    /// and takes a `Handle`") for the `tokio-refresh` feature, a thin
    /// convenience layer built on top of this method.
    ///
    /// The returned future holds only a `Weak` reference to this client's
    /// shared state, not a strong one: it does not keep the client alive, and
    /// it exits (at the latest, on its next tick) once every clone of this
    /// `AppleAuthClient` has been dropped. This is what makes it safe to
    /// spawn onto an executor and forget — the task cannot outlive the client
    /// and keep polling Apple forever.
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
    pub fn keystore_refresh_loop<S, Fut>(
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

    /// Verifies an identity token, checks the caller's `account_lookup` for
    /// whether this Apple user already has a usable refresh token on file,
    /// and either returns a login (no authorization code spent) or exchanges
    /// the code and checks that both tokens agree on the nonce and the Apple
    /// user — the full, safe path for a typical Sign in with Apple flow.
    ///
    /// `nonce_checker` gets the token's `nonce` claim verbatim (`None` only
    /// under `NoncePolicy::Permissive`), called exactly once, for
    /// `identity_token`. `Ok(false)` is a mismatch; `Err(_)` means the check
    /// itself failed (e.g. a database lookup), reported as
    /// `SignInError::NonceCheckFailed` rather than a false mismatch. When the
    /// code is exchanged, `sign_up_or_log_in` compares the exchanged
    /// `id_token`'s nonce against the identity token's already-accepted
    /// nonce with `nonce_eq` — see docs/architecture.md, "Why the exchanged
    /// nonce is compared against the identity token's".
    ///
    /// `account_lookup` runs after the identity token and its nonce are
    /// verified, but before anything is spent at Apple — it decides whether
    /// `sign_up_or_log_in` exchanges the authorization code at all.
    /// `AccountState::AlreadyOnFile` returns `SignInOutcome::LoggedIn`
    /// immediately, leaving the code unspent; `AccountState::NeedsExchange`
    /// falls through to the exchange. `Err(_)` is
    /// `SignInError::AccountLookupFailed` — a lookup failure, not a verdict
    /// that the account doesn't exist.
    ///
    /// **Replay caveat for the login branch:** ordinarily, exchanging the
    /// authorization code is a de-facto single-use check — replaying a
    /// captured identity token fails because the code can't be spent twice.
    /// On the `LoggedIn` branch nothing is spent, so `nonce_checker` is the
    /// *only* replay defense left. For a `Permissive` client whose checker is
    /// lax, this is a real reduction — `nonce_checker` must be effectively
    /// single-use for the login branch to stay replay-safe.
    ///
    /// A post-exchange rejection where the exchanged `id_token` names a
    /// different Apple user than the caller's identity token returns
    /// `SignInError::SubjectMismatch`: the token is simply discarded. Every
    /// other post-exchange rejection (`PostExchangeRejection`: the exchanged
    /// `id_token` fails verification, or its nonce doesn't match) returns
    /// `SignInError::RevocationRequired` (carrying a boxed
    /// [`PendingRevocation`] with the token and the verified identity): the
    /// host revokes it after this call returns, per the contract in
    /// docs/usage.md, "The `account_lookup` contract". The reasoning is in
    /// docs/architecture.md, "Why `sign_up_or_log_in` never revokes, and
    /// discards another user's token"; why a stale/unusable token reported by
    /// `account_lookup` is simply discarded is covered separately in
    /// docs/architecture.md, "Why a stale refresh token is discarded, not
    /// revoked".
    // See docs/architecture.md: "Why sign_up_or_log_in's nonce checker is
    // `FnOnce(Option<String>) -> Fut`, not `AsyncFn`" — `account_lookup`
    // follows the same reasoning; both are `FnOnce` since each is called at
    // most once.
    pub async fn sign_up_or_log_in<F, Fut, L, LFut>(
        &self,
        identity_token: &str,
        authorization_code: &str,
        nonce_checker: F,
        account_lookup: L,
    ) -> Result<SignInOutcome, SignInError>
    where
        F: FnOnce(Option<String>) -> Fut,
        Fut: Future<Output = Result<bool, Box<dyn std::error::Error + Send + Sync>>> + Send,
        L: FnOnce(AppleIdentity) -> LFut,
        LFut: Future<Output = Result<AccountState, Box<dyn std::error::Error + Send + Sync>>> + Send,
    {
        let verified = self.verify_identity_token(identity_token).await?;
        match nonce_checker(verified.nonce.clone()).await {
            Ok(true) => {}
            Ok(false) => return Err(SignInError::NonceMismatch),
            Err(cause) => return Err(SignInError::NonceCheckFailed(cause)),
        }

        match account_lookup(verified.identity.clone()).await {
            Ok(AccountState::AlreadyOnFile) => {
                return Ok(SignInOutcome::LoggedIn {
                    identity: verified.identity,
                });
            }
            Ok(AccountState::NeedsExchange) => {}
            Err(cause) => return Err(SignInError::AccountLookupFailed(cause)),
        }

        let details = match self.exchange_authorization_code(authorization_code).await {
            Ok(details) => details,
            Err(CodeExchangeError::Exchange(err)) => return Err(err.into()),
            Err(CodeExchangeError::ExchangedTokenUnverified {
                refresh_token,
                cause,
            }) => {
                return Err(revocation_required(
                    refresh_token,
                    verified.identity,
                    PostExchangeRejection::TokenUnverified(cause),
                ));
            }
        };

        // Checked before the nonce: a stolen authorization code paired with the
        // caller's identity token carries the *thief's* own nonce, which would
        // otherwise be classified as an ordinary `NonceMismatch` and hand a
        // stranger's token back for revocation. See docs/architecture.md.
        if details.identity.apple_user_id != verified.identity.apple_user_id {
            return Err(SignInError::SubjectMismatch);
        }

        // See docs/architecture.md, "Why the exchanged nonce is compared
        // against the identity token's".
        let nonces_match = match (verified.nonce.as_deref(), details.nonce.as_deref()) {
            (Some(expected), candidate) => nonce_eq(candidate, expected),
            (None, None) => true,
            (None, Some(_)) => false,
        };
        if !nonces_match {
            return Err(revocation_required(
                details.refresh_token,
                verified.identity,
                PostExchangeRejection::NonceMismatch,
            ));
        }

        Ok(SignInOutcome::SignedUp {
            identity: details.identity,
            refresh_token: details.refresh_token,
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

/// The refresh token is live at Apple and deliberately left unrevoked —
/// revoking is authorization-scoped and could tear down a concurrent sign-in
/// for the same Apple user. See docs/architecture.md, "Why revocations are
/// coordinated by the host, through `account_lookup`".
fn revocation_required(
    refresh_token: RefreshToken,
    identity: AppleIdentity,
    cause: PostExchangeRejection,
) -> SignInError {
    SignInError::RevocationRequired(Box::new(PendingRevocation {
        refresh_token,
        identity,
        cause,
    }))
}

/// Background JWKS-refresh convenience built on `keystore_refresh_loop`. See
/// docs/architecture.md ("Why background refresh is opt-in and takes a
/// `Handle`") for why this takes a `Handle` rather than spawning from inside
/// a constructor, and why it's gated behind the `tokio-refresh` feature
/// rather than being unconditional. (`N: NonceRequirement` already implies
/// `N: 'static`, which `handle.spawn` needs — see `NonceRequirement`'s doc in
/// `config.rs`.)
#[cfg(feature = "tokio-refresh")]
impl<T: HttpTransport, N: NonceRequirement> AppleAuthClient<T, N> {
    /// Spawns a background task that keeps the JWKS cache warm for as long as
    /// any clone of this client is alive, then returns `self` unchanged so
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
    #[must_use = "with_background_refresh returns `self` for chaining; dropping the result discards the client"]
    pub fn with_background_refresh(self, handle: tokio::runtime::Handle) -> Self {
        handle.spawn(self.keystore_refresh_loop(tokio::time::sleep));
        self
    }
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
    ) -> Result<Self, InvalidPrivateKeyError> {
        Self::build(token_config, config, transport)
    }
}

#[cfg(feature = "reqwest")]
impl AppleAuthClient<transport::ReqwestTransport, Strict> {
    pub fn new(token_config: AppleTokenConfig) -> Result<Self, InvalidPrivateKeyError> {
        Self::with_transport(
            token_config,
            VerificationConfig::default(),
            transport::ReqwestTransport::default(),
        )
    }
}

/// `sign_up_or_log_in_with_nonce` exists only here, on a `Strict` client — see
/// [`NonceRequirement`] and docs/architecture.md ("Why the nonce policy is a
/// type parameter").
impl<T: HttpTransport> AppleAuthClient<T, Strict> {
    /// `sign_up_or_log_in` with a checker that compares the claim directly
    /// against `expected_nonce` — constant-time and ASCII-case-insensitive,
    /// see `nonce_eq`. A missing nonce (`None`) is a rejection, though under
    /// `Strict` that's moot: `verify_identity_token` already rejects a missing
    /// nonce as `IdentityTokenRejected` before the checker runs.
    ///
    /// A `Permissive` client needs `sign_up_or_log_in` directly, with a
    /// checker that decides what a missing nonce means for its flow (e.g. a
    /// replay-detection window from `AppleIdentity::issued_at`/`expiration`,
    /// per `NoncePolicy`):
    ///
    /// ```ignore
    /// client.sign_up_or_log_in(identity_token, code, |candidate| async move {
    ///     match candidate {
    ///         Some(nonce) => Ok(nonce == expected_nonce),
    ///         None => Ok(my_replay_store.check_and_record(identity_token).await),
    ///     }
    /// }, account_lookup).await
    /// ```
    pub async fn sign_up_or_log_in_with_nonce<L, LFut>(
        &self,
        identity_token: &str,
        authorization_code: &str,
        expected_nonce: &str,
        account_lookup: L,
    ) -> Result<SignInOutcome, SignInError>
    where
        L: FnOnce(AppleIdentity) -> LFut,
        LFut: Future<Output = Result<AccountState, Box<dyn std::error::Error + Send + Sync>>> + Send,
    {
        self.sign_up_or_log_in(
            identity_token,
            authorization_code,
            move |candidate| async move { Ok(nonce_eq(candidate.as_deref(), expected_nonce)) },
            account_lookup,
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

    /// Fake transport serving both verbs `AppleAuthClient` needs: JWKS fetches
    /// (`get`, counted) and Apple's token/revoke endpoints (`post_form`, recorded
    /// with their URL and body so tests can inspect exactly what was sent).
    /// `Clone` shares `get_calls` and `posts` through their `Arc`s, so calls made
    /// through any clone are observed here.
    #[derive(Clone)]
    struct FakeAppleTransport {
        get_calls: Arc<StdMutex<usize>>,
        posts: Arc<StdMutex<Vec<(String, String)>>>,
        jwks_body: String,
        post_response: String,
    }

    impl FakeAppleTransport {
        fn new(jwks_body: impl Into<String>, post_response: impl Into<String>) -> Self {
            Self {
                get_calls: Arc::default(),
                posts: Arc::default(),
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
    }

    impl HttpGet for FakeAppleTransport {
        async fn get(
            &self,
            _url: &str,
            _headers: &[(&str, &str)],
            _timeout: Duration,
        ) -> Result<String, TransportError> {
            *self.get_calls.lock().unwrap() += 1;
            Ok(self.jwks_body.clone())
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
        .expect("valid test key should construct client");

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
        header.kid = Some(TEST_KID.to_string());
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
        let client = AppleAuthClient::with_transport(
            config,
            VerificationConfig::default(),
            transport,
        )
        .expect("valid test key should construct client");

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
        let client = AppleAuthClient::with_transport(
            config,
            VerificationConfig::default(),
            transport,
        )
        .expect("valid test key should construct client");

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
        .expect("valid test key should construct client");

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
        .expect("valid test key should construct client");

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
        .expect("valid test key should construct client");

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
    /// `sign_up_or_log_in`/`sign_up_or_log_in_with_nonce` test starts from,
    /// since it lets each test tweak exactly one thing (a nonce, a `sub`) and
    /// still get a well-formed exchange otherwise. Returns the client, the
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
        let client = AppleAuthClient::with_transport(config, VerificationConfig::default(), transport.clone())
            .expect("valid test key should construct client");
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
        .expect("valid test key should construct client");
        (client, identity_token, transport)
    }

    /// Lookup that always reports no usable account on file, so a test exercises
    /// the full exchange path — the behaviour the pre-lookup `sign_in` always had.
    fn needs_exchange()
    -> impl FnOnce(AppleIdentity) -> std::future::Ready<Result<AccountState, Box<dyn std::error::Error + Send + Sync>>>
    {
        // Explicit turbofish needed: nothing else pins the error type here, same
        // as the existing `Err::<bool, Box<dyn ...>>` annotation further below.
        |_identity| {
            std::future::ready(Ok::<_, Box<dyn std::error::Error + Send + Sync>>(
                AccountState::NeedsExchange,
            ))
        }
    }

    fn assert_send<T: Send>(_: T) {}

    /// `Send`-bound callers (e.g. axum handlers) need these futures to be `Send`.
    /// Nothing here is awaited, so `client_for_sign_up_or_log_in`'s arguments don't matter.
    #[test]
    fn verification_and_exchange_futures_are_send() {
        let (client, identity_token, _transport) = client_for_sign_up_or_log_in("nonce", "apple-user-1");
        assert_send(client.verify_identity_token(&identity_token));
        assert_send(client.exchange_authorization_code("auth-code"));
        assert_send(client.revoke_refresh_token("refresh-token"));
    }

    /// Guards that `sign_up_or_log_in_with_nonce`'s future stays `Send`, as
    /// required by `Send`-bound callers such as axum handlers.
    #[test]
    fn sign_up_or_log_in_with_nonce_future_is_send() {
        let (client, identity_token, _transport) = client_for_sign_up_or_log_in("nonce", "apple-user-1");
        assert_send(client.sign_up_or_log_in_with_nonce(
            &identity_token,
            "auth-code",
            "nonce",
            needs_exchange(),
        ));
    }

    /// Guards that `sign_up_or_log_in`'s future stays `Send` for any checker
    /// closure that itself returns a `Send` future, as required by `Send`-bound
    /// callers such as axum handlers.
    #[test]
    fn sign_up_or_log_in_future_is_send() {
        let (client, identity_token, _transport) = client_for_sign_up_or_log_in("nonce", "apple-user-1");
        let expected = String::from("nonce");
        assert_send(client.sign_up_or_log_in(
            &identity_token,
            "auth-code",
            move |candidate| {
                let expected = expected.clone();
                async move { Ok(candidate.as_deref() == Some(expected.as_str())) }
            },
            needs_exchange(),
        ));
    }

    /// `sign_up_or_log_in` returns `Result<_, SignInError>` from every frame on
    /// the success path too, so the error stays under clippy's 128-byte
    /// `result_large_err` budget: `RevocationRequired`'s payload is boxed to
    /// keep it there.
    #[test]
    fn sign_in_error_stays_small() {
        assert!(std::mem::size_of::<SignInError>() <= 128);
    }

    #[tokio::test]
    async fn sign_up_or_log_in_returns_the_identity_when_both_tokens_verify() {
        let (client, identity_token, transport) =
            client_for_sign_up_or_log_in("expected-nonce", "apple-user-1");

        let outcome = client
            .sign_up_or_log_in_with_nonce(
                &identity_token,
                "auth-code",
                "expected-nonce",
                needs_exchange(),
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
        assert_eq!(transport.posts()[0].0, "https://appleid.apple.com/auth/token");
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
            .sign_up_or_log_in(
                &identity_token,
                "auth-code",
                move |candidate| {
                    let pending = pending.clone();
                    async move {
                        let removed = candidate
                            .map(|nonce| pending.lock().unwrap().remove(&nonce))
                            .unwrap_or(false);
                        Ok::<bool, Box<dyn std::error::Error + Send + Sync>>(removed)
                    }
                },
                needs_exchange(),
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
            .sign_up_or_log_in(
                &identity_token,
                "auth-code",
                |_candidate| async move { Ok::<bool, Box<dyn std::error::Error + Send + Sync>>(true) },
                needs_exchange(),
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

        let result = client
            .sign_up_or_log_in(
                &identity_token,
                "auth-code",
                |_candidate| async move { Ok::<bool, Box<dyn std::error::Error + Send + Sync>>(true) },
                needs_exchange(),
            )
            .await;

        assert!(matches!(
            result,
            Err(SignInError::RevocationRequired(pending))
                if matches!(pending.cause, PostExchangeRejection::NonceMismatch)
        ));
    }

    /// A mismatched identity-token nonce is rejected before the authorization
    /// code is ever exchanged — pins that `sign_up_or_log_in` checks the free
    /// thing first.
    #[tokio::test]
    async fn sign_up_or_log_in_rejects_a_mismatched_identity_token_nonce_without_spending_the_code() {
        let (client, identity_token, transport) =
            client_for_sign_up_or_log_in("expected-nonce", "apple-user-1");

        let result = client
            .sign_up_or_log_in_with_nonce(
                &identity_token,
                "auth-code",
                "wrong-nonce",
                needs_exchange(),
            )
            .await;

        assert!(matches!(result, Err(SignInError::NonceMismatch)));
        assert!(transport.posts().is_empty());
    }

    /// An unverifiable exchanged `id_token` leaves a live refresh token behind
    /// that `sign_up_or_log_in` hands straight back — no revoke attempt — for
    /// the host to revoke after the call returns. See docs/architecture.md,
    /// "Why revocations are coordinated by the host, through
    /// `account_lookup`".
    #[tokio::test]
    async fn sign_up_or_log_in_hands_back_an_unverifiable_exchanged_token_without_revoking_it() {
        let config = test_token_config();
        let (identity_token, _, _) = signed_identity_token(&config.client_id, "apple-user-1");
        let transport = FakeAppleTransport::new(
            jwks_body_including(TEST_KID),
            r#"{"access_token":"at","refresh_token":"rt","id_token":"not-a-jwt","expires_in":3600}"#,
        );
        let client = AppleAuthClient::with_transport(config, VerificationConfig::default(), transport.clone())
            .expect("valid test key should construct client");

        let result = client
            .sign_up_or_log_in_with_nonce(
                &identity_token,
                "auth-code",
                "expected-nonce",
                needs_exchange(),
            )
            .await;

        match result {
            Err(SignInError::RevocationRequired(pending)) => {
                let PendingRevocation {
                    refresh_token,
                    identity,
                    cause,
                    ..
                } = *pending;
                assert!(matches!(cause, PostExchangeRejection::TokenUnverified(_)));
                assert_eq!(refresh_token.as_str(), "rt");
                assert_eq!(identity.apple_user_id, "apple-user-1");
            }
            other => panic!("expected RevocationRequired, got {other:?}"),
        }
        let posts = transport.posts();
        assert_eq!(posts.len(), 1);
        assert_eq!(posts[0].0, "https://appleid.apple.com/auth/token");
    }

    #[tokio::test]
    async fn sign_up_or_log_in_hands_back_the_token_when_the_exchanged_nonce_does_not_match() {
        let (client, identity_token, transport) =
            client_for_sign_up_or_log_in("a-different-nonce", "apple-user-1");

        let result = client
            .sign_up_or_log_in_with_nonce(
                &identity_token,
                "auth-code",
                "expected-nonce",
                needs_exchange(),
            )
            .await;

        assert!(matches!(
            result,
            Err(SignInError::RevocationRequired(pending))
                if matches!(pending.cause, PostExchangeRejection::NonceMismatch)
        ));
        let posts = transport.posts();
        assert_eq!(posts.len(), 1);
        assert_eq!(posts[0].0, "https://appleid.apple.com/auth/token");
    }

    /// Regression test for the identity-confusion gap this crate's
    /// `sign_up_or_log_in` closes: pairing one Apple user's identity token
    /// with an authorization code that resolves to a different Apple user.
    /// The token is simply discarded: see docs/architecture.md, "Why
    /// `sign_up_or_log_in` never revokes, and discards another user's token".
    #[tokio::test]
    async fn sign_up_or_log_in_discards_the_token_when_the_exchanged_id_token_is_for_another_user() {
        let (client, identity_token, transport) =
            client_for_sign_up_or_log_in("expected-nonce", "apple-user-2");

        let result = client
            .sign_up_or_log_in_with_nonce(
                &identity_token,
                "auth-code",
                "expected-nonce",
                needs_exchange(),
            )
            .await;

        assert!(matches!(result, Err(SignInError::SubjectMismatch)));
        let posts = transport.posts();
        assert_eq!(posts.len(), 1);
        assert_eq!(posts[0].0, "https://appleid.apple.com/auth/token");
    }

    /// A foreign authorization code carries the thief's own nonce, not the
    /// caller's — pins that the subject check runs before the nonce check, so
    /// it's always classified as `SubjectMismatch`, never `RevocationRequired`.
    #[tokio::test]
    async fn sign_up_or_log_in_checks_the_subject_before_the_exchanged_nonce() {
        let (client, identity_token, _transport) =
            client_for_sign_up_or_log_in("a-different-nonce", "apple-user-2");

        let result = client
            .sign_up_or_log_in_with_nonce(
                &identity_token,
                "auth-code",
                "expected-nonce",
                needs_exchange(),
            )
            .await;

        assert!(matches!(result, Err(SignInError::SubjectMismatch)));
    }

    /// A nonce lookup that fails outright (e.g. a database error) must not be
    /// reported the same way as a nonce the caller actually rejected.
    #[tokio::test]
    async fn sign_up_or_log_in_reports_a_failed_nonce_lookup_separately_from_a_mismatch() {
        let (client, identity_token, transport) =
            client_for_sign_up_or_log_in("expected-nonce", "apple-user-1");

        let result = client
            .sign_up_or_log_in(
                &identity_token,
                "auth-code",
                |_candidate| async move {
                    Err::<bool, Box<dyn std::error::Error + Send + Sync>>(
                        "session store unavailable".into(),
                    )
                },
                needs_exchange(),
            )
            .await;

        assert!(matches!(result, Err(SignInError::NonceCheckFailed(_))));
        assert!(transport.posts().is_empty());
    }

    #[tokio::test]
    async fn sign_up_or_log_in_with_nonce_matches_case_insensitively() {
        let (client, identity_token, _transport) =
            client_for_sign_up_or_log_in("Expected-Nonce", "apple-user-1");

        let result = client
            .sign_up_or_log_in_with_nonce(
                &identity_token,
                "auth-code",
                "EXPECTED-NONCE",
                needs_exchange(),
            )
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn logs_in_without_spending_the_code_when_the_account_is_already_on_file() {
        let (client, identity_token, transport) =
            client_for_sign_up_or_log_in("expected-nonce", "apple-user-1");

        let outcome = client
            .sign_up_or_log_in_with_nonce(
                &identity_token,
                "auth-code",
                "expected-nonce",
                |_identity| async move { Ok(AccountState::AlreadyOnFile) },
            )
            .await
            .unwrap();

        match outcome {
            SignInOutcome::LoggedIn { identity } => {
                assert_eq!(identity.apple_user_id, "apple-user-1");
            }
            other => panic!("expected LoggedIn, got {other:?}"),
        }
        assert!(transport.posts().is_empty());
    }

    #[tokio::test]
    async fn reports_a_failed_account_lookup_separately() {
        let (client, identity_token, transport) =
            client_for_sign_up_or_log_in("expected-nonce", "apple-user-1");

        let result = client
            .sign_up_or_log_in_with_nonce(
                &identity_token,
                "auth-code",
                "expected-nonce",
                |_identity| async move {
                    Err::<AccountState, Box<dyn std::error::Error + Send + Sync>>(
                        "account store unavailable".into(),
                    )
                },
            )
            .await;

        assert!(matches!(result, Err(SignInError::AccountLookupFailed(_))));
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
            .expect("valid test key should construct client");

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
            let client = AppleAuthClient::with_transport(
                test_token_config(),
                config,
                transport.clone(),
            )
            .expect("valid test key should construct client");

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
            let client = AppleAuthClient::with_transport(
                test_token_config(),
                config,
                transport.clone(),
            )
            .expect("valid test key should construct client");

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
            let client = AppleAuthClient::with_transport(
                test_token_config(),
                config,
                transport.clone(),
            )
            .expect("valid test key should construct client");

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
    }
}
