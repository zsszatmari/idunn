#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
// https://developer.apple.com/documentation/technotes/tn3194-handling-account-deletions-and-revoking-tokens-for-sign-in-with-apple
// https://developer.apple.com/documentation/signinwithapplerestapi/revoke-tokens
// https://developer.apple.com/support/offering-account-deletion-in-your-app/

mod error;
mod identity_verification;
mod jwks_store;
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod test_support;
mod token_exchange;
mod transport;

pub use error::{AppleErrorCode, IdunnError, InvalidTokenCause};
pub use identity_verification::{
    AppleEmail, AppleIdentity, IdentityVerificationConfig, NoncePolicy, RealUserStatus,
};
pub use token_exchange::{AppleTokenConfig, AppleTokenResponse};
use jwks_store::JwksStoreConfig;
use transport::HttpTransport;

use jsonwebtoken::EncodingKey;
use std::sync::Arc;

/// The credential material for signing client secrets: the config and the
/// `EncodingKey` derived from its `.p8` key. Grouped behind one `Arc` so
/// `AppleAuthClient::clone` never re-allocates or copies the private key
/// (`axum`'s `State` clones per request); they belong together anyway, the
/// key being derived from `token_config.private_key_pem`.
struct Credentials {
    token_config: AppleTokenConfig,
    signing_key: EncodingKey,
}

///Verifies Apple identity tokens and exchanges authorization codes for refresh
/// tokens, for a single app identified by `AppleTokenConfig::client_id`.
///
/// One client with one constructor, covering both identity verification and token
/// exchange even though they touch mostly-disjoint code (see `identity.rs` /
/// `token.rs`): see docs/architecture.md for why they're bundled together.
///
/// `Clone` is cheap — a few atomic increments, with no allocation and no copy of
/// the Apple private key — and is the intended way to use the client from several
/// tasks or handlers; wrapping it in an `Arc` yourself is unnecessary. Every clone
/// shares one JWKS cache **and** one fetch rate limiter. That is deliberate: it is
/// what keeps concurrent verifications collapsing onto a single request to Apple
/// rather than one fetch per clone. To get genuinely independent state (e.g. a
/// second app's `client_id`), construct a new client — cloning will never give you
/// that. See docs/architecture.md for why the shared state sits behind `Arc`.
#[derive(Clone)]
pub struct AppleAuthClient<T: HttpTransport> {
    identity_verification: Arc<identity_verification::IdentityVerificationClient<T>>,
    credentials: Arc<Credentials>,
    transport: T,
}

#[cfg(feature = "reqwest")]
impl AppleAuthClient<transport::ReqwestTransport> {
    pub fn new(token_config: AppleTokenConfig) -> Result<Self, IdunnError> {
        Self::with_transport(
            token_config,
            transport::ReqwestTransport::default(),
            JwksStoreConfig::default(),
            IdentityVerificationConfig::default(),
        )
    }
}

impl<T: HttpTransport> AppleAuthClient<T> {
    pub fn with_transport(
        token_config: AppleTokenConfig,
        transport: T,
        jwks_config: JwksStoreConfig,
        identity_verification_config: IdentityVerificationConfig,
    ) -> Result<Self, IdunnError> {
        let signing_key = EncodingKey::from_ec_pem(&token_config.private_key_pem)
            .map_err(IdunnError::InvalidPrivateKey)?;
        let identity_verification =
            Arc::new(identity_verification::IdentityVerificationClient::new(
                &token_config.client_id,
                transport.clone(),
                jwks_config,
                identity_verification_config,
            ));
        Ok(Self {
            identity_verification,
            credentials: Arc::new(Credentials {
                token_config,
                signing_key,
            }),
            transport,
        })
    }

    pub async fn refresh_keystore(&self) -> Result<(), IdunnError> {
        self.identity_verification.refresh_keystore().await;
        Ok(())
    }

    /// Validate and decode an Apple identity JWT.
    pub async fn verify_identity_token(
        &self,
        identity_token: &str,
    ) -> Result<AppleIdentity, IdunnError> {
        self.identity_verification
            .verify_identity_token(identity_token)
            .await
    }

    /// Exchange an authorization code (from `ASAuthorizationAppleIDCredential`)
    /// for Apple's access/refresh/id tokens.
    pub async fn exchange_authorization_code(
        &self,
        authorization_code: &str,
    ) -> Result<AppleTokenResponse, IdunnError> {
        token_exchange::exchange_authorization_code(
            &self.transport,
            &self.credentials.token_config,
            &self.credentials.signing_key,
            authorization_code,
        )
        .await
    }

    /// Revoke a refresh token previously issued by Apple (e.g. on sign-out or account
    /// deletion) so it can no longer be used.
    pub async fn revoke_refresh_token(&self, refresh_token: &str) -> Result<(), IdunnError> {
        token_exchange::revoke_refresh_token(
            &self.transport,
            &self.credentials.token_config,
            &self.credentials.signing_key,
            refresh_token,
        )
        .await
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::test_support::test_token_config;
    use crate::transport::{HttpGet, HttpPost, TransportError};
    use std::sync::Mutex as StdMutex;
    use std::time::Duration;

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

        assert!(matches!(result, Err(IdunnError::InvalidPrivateKey(_))));
    }

    /// Minimal well-formed JWKS body — the key contents don't matter here, only
    /// that each `get` is counted.
    const JWKS_BODY: &str = r#"{"keys":[{"kty":"RSA","kid":"test-kid","n":"AQAB","e":"AQAB"}]}"#;

    /// Transport that counts JWKS fetches and never posts. `Clone` shares the
    /// counter, so a fetch made through any clone is observed here. (This is a
    /// fourth hand-rolled transport mock in the crate — the ones in
    /// `jwks_store`/`identity_verification`/`token_exchange` tests are private to
    /// their own modules; consolidating them is a separate follow-up.)
    #[derive(Clone)]
    struct CountingTransport {
        get_calls: Arc<StdMutex<usize>>,
    }

    impl HttpGet for CountingTransport {
        async fn get(
            &self,
            _url: &str,
            _headers: &[(&str, &str)],
            _timeout: Duration,
        ) -> Result<String, TransportError> {
            *self.get_calls.lock().unwrap() += 1;
            Ok(JWKS_BODY.to_string())
        }
    }

    impl HttpPost for CountingTransport {
        async fn post_form(
            &self,
            _url: &str,
            _headers: &[(&str, &str)],
            _body: &str,
            _timeout: Duration,
        ) -> Result<String, TransportError> {
            // This test only drives `refresh_keystore`, which never posts.
            unreachable!("this test never posts")
        }
    }

    /// A clone must share the JWKS cache **and** the fetch rate limiter, not get
    /// its own. With shared state the 60s default `cooldown_period` suppresses
    /// the clone's refresh and the transport sees exactly one fetch; if a clone
    /// duplicated the state it would be two. This assertion is what pins the
    /// per-field `Arc` design against an accidental un-`Arc` of a field.
    #[tokio::test]
    async fn clone_shares_jwks_cache_and_rate_limiter() {
        let transport = CountingTransport {
            get_calls: Arc::new(StdMutex::new(0)),
        };
        let client = AppleAuthClient::with_transport(
            test_token_config(),
            transport.clone(),
            JwksStoreConfig::default(),
            IdentityVerificationConfig::default(),
        )
        .expect("valid test key should construct client");

        client.refresh_keystore().await.unwrap();
        client.clone().refresh_keystore().await.unwrap();

        assert_eq!(*transport.get_calls.lock().unwrap(), 1);
    }
}
