#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
// https://developer.apple.com/documentation/technotes/tn3194-handling-account-deletions-and-revoking-tokens-for-sign-in-with-apple
// https://developer.apple.com/documentation/signinwithapplerestapi/revoke-tokens
// https://developer.apple.com/support/offering-account-deletion-in-your-app/

mod error;
mod identity_verification;
mod jwks_store;
mod token_exchange;
mod transport;

pub use error::{
    AppleErrorCode, ClientSecretError, InvalidPrivateKeyError, InvalidTokenCause, SignInError,
    TokenExchangeError, TokenRevocationError, VerificationError,
};
pub use identity_verification::{
    AppleEmail, AppleIdentity, IdentityVerificationConfig, NoncePolicy, RealUserStatus,
};
use jwks_store::JwksStoreConfig;
pub use token_exchange::{AppleTokenConfig, RefreshToken};
use transport::HttpTransport;

use jsonwebtoken::EncodingKey;
use std::sync::Arc;

/// A Sign in with Apple authorization that was exchanged **and** verified.
///
/// Only constructible through `AppleAuthClient::exchange_authorization_code`, so
/// holding one means the identity below already passed `verify_identity_token` —
/// signature, `iss`, `aud` and `exp` all checked against Apple's published keys.
#[derive(Debug, Clone)]
pub struct VerifiedSignIn {
    /// Apple's refresh token. Store it: revoking it is how an app satisfies
    /// Apple's mandatory account-deletion requirement (TN3194).
    pub refresh_token: RefreshToken,
    /// The identity from the exchange's `id_token`, already verified.
    pub identity: AppleIdentity,
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
    pub fn new(token_config: AppleTokenConfig) -> Result<Self, InvalidPrivateKeyError> {
        Self::with_transport(
            token_config,
            transport::ReqwestTransport::default(),
            JwksStoreConfig::default(),
            IdentityVerificationConfig::default(),
        )
    }
}

// TODO: think about the order of constructor arguments
impl<T: HttpTransport> AppleAuthClient<T> {
    pub fn with_transport(
        token_config: AppleTokenConfig,
        transport: T,
        jwks_config: JwksStoreConfig,
        identity_verification_config: IdentityVerificationConfig,
    ) -> Result<Self, InvalidPrivateKeyError> {
        let signing_key = EncodingKey::from_ec_pem(&token_config.private_key_pem)
            .map_err(InvalidPrivateKeyError::from)?;
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

    /// Returns how long the caller should wait before calling again — see
    /// `JwksStore::refresh_keystore` for what that duration means and when a
    /// call is skipped for arriving too early.
    pub async fn refresh_keystore(&self) -> std::time::Duration {
        self.identity_verification.refresh_keystore().await
    }

    /// Validate and decode an Apple identity JWT.
    pub async fn verify_identity_token(
        &self,
        identity_token: &str,
    ) -> Result<AppleIdentity, VerificationError> {
        self.identity_verification
            .verify_identity_token(identity_token)
            .await
    }

    /// Exchange an authorization code (from `ASAuthorizationAppleIDCredential`)
    /// for Apple's refresh token, and verify the `id_token` returned alongside
    /// it the same way `verify_identity_token` does — this call also performs a
    /// JWKS fetch (served from the shared cache after the first), so it can
    /// fail with `CannotVerifyToken` in addition to the token-exchange errors.
    ///
    /// If the exchange succeeds but verification fails, Apple has already
    /// issued a live refresh token against a now-consumed authorization code;
    /// the returned `SignInError::ExchangedTokenUnverified` carries that token
    /// so the caller can revoke it (`revoke_refresh_token`) instead of losing
    /// track of it.
    pub async fn exchange_authorization_code(
        &self,
        authorization_code: &str,
    ) -> Result<VerifiedSignIn, SignInError> {
        let tokens = token_exchange::exchange_authorization_code(
            &self.transport,
            &self.credentials.token_config,
            &self.credentials.signing_key,
            authorization_code,
        )
        .await?;
        match self.verify_identity_token(&tokens.id_token).await {
            Ok(identity) => Ok(VerifiedSignIn {
                refresh_token: tokens.refresh_token,
                identity,
            }),
            Err(cause) => Err(SignInError::ExchangedTokenUnverified {
                refresh_token: tokens.refresh_token,
                cause,
            }),
        }
    }

    /// Revoke a refresh token previously issued by Apple (e.g. on sign-out or account
    /// deletion) so it can no longer be used.
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
            transport.clone(),
            JwksStoreConfig::default(),
            IdentityVerificationConfig::default(),
        )
        .expect("valid test key should construct client");

        client.refresh_keystore().await;
        client.clone().refresh_keystore().await;

        assert_eq!(transport.get_calls(), 1);
    }

    /// Signs an RS256 identity token, playing Apple, with `aud` as its audience —
    /// the rest of the claims are fixed. Returns the token plus its `iat`/`exp` so
    /// callers can assert `AppleIdentity::issued_at`/`expiration` exactly.
    fn signed_identity_token(aud: &str) -> (String, u64, u64) {
        let iat = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let exp = iat + 3600;
        let claims = serde_json::json!({
            "sub": "apple-user-1",
            "email": "user@example.com",
            "nonce": "expected-nonce",
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
        let (token, iat, exp) = signed_identity_token(&config.client_id);
        let transport = FakeAppleTransport::new(jwks_body_including(TEST_KID), "");
        let client = AppleAuthClient::with_transport(
            config,
            transport,
            JwksStoreConfig::default(),
            IdentityVerificationConfig::default(),
        )
        .expect("valid test key should construct client");

        let identity = client.verify_identity_token(&token).await.unwrap();

        assert_eq!(identity.apple_user_id, "apple-user-1");
        assert_eq!(
            identity.email.as_ref().map(|email| email.address.as_str()),
            Some("user@example.com")
        );
        assert_eq!(identity.nonce.as_deref(), Some("expected-nonce"));
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
        let (token, _, _) = signed_identity_token(&original_config.client_id);
        let mut config = original_config;
        config.client_id = "com.example.other".to_string();
        let transport = FakeAppleTransport::new(jwks_body_including(TEST_KID), "");
        let client = AppleAuthClient::with_transport(
            config,
            transport,
            JwksStoreConfig::default(),
            IdentityVerificationConfig::default(),
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
        let (id_token, _, _) = signed_identity_token(&config.client_id);
        let transport = FakeAppleTransport::new(
            jwks_body_including(TEST_KID),
            format!(
                r#"{{"access_token":"at","refresh_token":"rt","id_token":"{id_token}","expires_in":3600}}"#
            ),
        );
        let client = AppleAuthClient::with_transport(
            config,
            transport.clone(),
            JwksStoreConfig::default(),
            IdentityVerificationConfig::default(),
        )
        .expect("valid test key should construct client");

        let response = client
            .exchange_authorization_code("auth-code")
            .await
            .unwrap();

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
            transport,
            JwksStoreConfig::default(),
            IdentityVerificationConfig::default(),
        )
        .expect("valid test key should construct client");

        let result = client.exchange_authorization_code("auth-code").await;

        match result {
            Err(SignInError::ExchangedTokenUnverified {
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
            transport.clone(),
            JwksStoreConfig::default(),
            IdentityVerificationConfig::default(),
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
}
