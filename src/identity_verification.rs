use crate::error::{IdunnError, InvalidTokenCause};
use crate::jwks_store::{JwksStore, JwksStoreConfig};
use crate::transport::HttpGet;
use jsonwebtoken::Validation;
use serde::Deserialize;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Identity extracted from a verified Apple identity token.
#[derive(Clone, Debug)]
pub struct AppleIdentity {
    /// Stable per-app-developer-team Apple user identifier (JWT `sub`).
    pub apple_user_id: String,
    /// Only reliably present on the user's first authorization.
    pub email: Option<String>,
    /// The token's `nonce` claim, if present. Comparing it against whatever
    /// nonce the caller generated for this authentication attempt is the
    /// caller's responsibility. `None` only occurs when `NoncePolicy::Permissive`
    /// is configured and the token's `nonce_supported` claim is `false` or
    /// absent (see `NoncePolicy`) — with the default `NoncePolicy::Strict`, a
    /// missing nonce is rejected outright instead of ever reaching here. When
    /// `nonce` is `None`, `issued_at`/`expiration` are the raw material for
    /// building your own replay-detection window (e.g. dedupe on the token
    /// itself within the `issued_at..expiration` range).
    pub nonce: Option<String>,
    /// When the token was issued (JWT `iat`).
    pub issued_at: SystemTime,
    /// When the token expires (JWT `exp`) — already enforced by verification
    /// itself; exposed so a replay-detection window built from `issued_at`
    /// can be sized consistently with it.
    pub expiration: SystemTime,
}

/// Controls how `verify_identity_token` handles a token with no `nonce`
/// claim.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum NoncePolicy {
    /// A missing `nonce` claim is always `InvalidToken`, regardless of the
    /// token's `nonce_supported` claim. Stricter than Apple's own suggested
    /// handling (see `Permissive`), chosen as the default so replay
    /// protection is never silently disabled by a claim idunn can't verify
    /// the integrity of.
    #[default]
    Strict,
    /// Follow the `nonce_supported`-conditioned handling Apple's docs
    /// suggest: <https://developer.apple.com/documentation/signinwithapplejs/authorizationi/id_token>
    /// — a missing `nonce` is only tolerated (`AppleIdentity::nonce` is
    /// `None`) when `nonce_supported` is `false` or absent; if
    /// `nonce_supported` is `true`, a missing nonce is still `InvalidToken`.
    Permissive,
}

/// Configuration for `IdentityVerificationClient`.
#[derive(Clone, Copy, Debug, Default)]
pub struct IdentityVerificationConfig {
    pub nonce_policy: NoncePolicy,
}

#[derive(Deserialize)]
struct ApplePayload {
    sub: String,
    email: Option<String>,
    nonce: Option<String>,
    nonce_supported: Option<bool>,
    iat: u64,
    exp: u64,
}

pub(crate) struct IdentityVerificationClient<T: HttpGet> {
    jwks_store: JwksStore<T>,
    validation: Validation,
    config: IdentityVerificationConfig,
}

impl<T: HttpGet> IdentityVerificationClient<T> {
    pub(crate) fn new(
        client_id: &str,
        transport: T,
        jwks_config: JwksStoreConfig,
        config: IdentityVerificationConfig,
    ) -> Self {
        // https://developer.apple.com/documentation/signinwithapple/verifying-a-user
        //
        // steps needed to validate the identity token:
        // "To verify the identity token, your app server must:
        // 1. Verify the JWS E256 signature using the server’s public key
        // 2. Verify the nonce for the authentication
        // 3. Verify that the iss field contains https://appleid.apple.com
        // 4. Verify that the aud field is the developer’s client_id
        // 5. Verify that the time is earlier than the exp value of the" token
        //
        // 1 and 5 are handled by `jsonwebtoken::decode` itself (signature
        // against the key `jwks_store` fetched, and `exp`, by default). 3 and
        // 4 are configured into `validation` below. 2 is only partially done
        // here: `verify_identity_token` enforces nonce *presence* per the
        // configured `NoncePolicy` and returns the claim as-is on
        // `AppleIdentity`, but never compares its *value* — that requires
        // knowing where/how the caller tracked the nonce it issued, which
        // idunn has no generic way to do, so that comparison stays the
        // caller's responsibility.
        let mut validation = Validation::new(jsonwebtoken::Algorithm::RS256);

        // (some below are jsonwebtoken's defaults but let's be explicit here)

        // "3. Verify that the iss field contains https://appleid.apple.com"
        validation.set_issuer(&["https://appleid.apple.com"]);
        // "4. Verify that the aud field is the developer's client_id"
        validation.set_audience(&[client_id]);
        validation.validate_aud = true;
        // "5. Verify that the time is earlier than the exp value of the" token
        validation.validate_exp = true;
        validation.leeway = 0;
        // require iss/aud/exp to be present, so a token that leaves one out
        // doesn't silently skip that check
        validation.set_required_spec_claims(&["iss", "aud", "exp"]);

        Self {
            jwks_store: JwksStore::new(transport, jwks_config),
            validation,
            config,
        }
    }

    pub(crate) async fn refresh_keystore(&self) -> std::time::Duration {
        self.jwks_store.refresh_keystore().await
    }

    pub(crate) async fn verify_identity_token(
        &self,
        identity_token: &str,
    ) -> Result<AppleIdentity, IdunnError> {
        let decoded_header = jsonwebtoken::decode_header(identity_token)
            .map_err(InvalidTokenCause::Rejected)
            .map_err(IdunnError::InvalidToken)?;
        if decoded_header.alg != jsonwebtoken::Algorithm::RS256 {
            return Err(IdunnError::InvalidToken(
                InvalidTokenCause::AlgorithmMismatch(decoded_header.alg),
            ));
        }
        let key_id = decoded_header.kid.ok_or(IdunnError::InvalidToken(
            InvalidTokenCause::InvalidKeyId { kid: None },
        ))?;
        let decoding_key = self.jwks_store.get_key(&key_id).await?;

        let decoded =
            jsonwebtoken::decode::<ApplePayload>(identity_token, &decoding_key, &self.validation)
                .map_err(InvalidTokenCause::Rejected)
                .map_err(IdunnError::InvalidToken)?;

        if decoded.claims.nonce.is_none() {
            let nonce_required = match self.config.nonce_policy {
                NoncePolicy::Strict => true,
                NoncePolicy::Permissive => decoded.claims.nonce_supported == Some(true),
            };
            if nonce_required {
                return Err(IdunnError::InvalidToken(InvalidTokenCause::MissingNonce));
            }
        }

        Ok(AppleIdentity {
            apple_user_id: decoded.claims.sub,
            email: decoded.claims.email,
            nonce: decoded.claims.nonce,
            issued_at: UNIX_EPOCH + Duration::from_secs(decoded.claims.iat),
            expiration: UNIX_EPOCH + Duration::from_secs(decoded.claims.exp),
        })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::test_support::{TEST_KID, TEST_RSA_PRIVATE_KEY_PEM, jwks_body_including};
    use crate::transport::TransportError;
    use serde::Serialize;
    use std::sync::{Arc, Mutex};

    const TEST_BUNDLE_ID: &str = "com.example.myapp";

    #[derive(Clone)]
    enum MockResponse {
        Success(String),
        NetworkFailure,
    }

    #[derive(Clone)]
    struct MockTransport {
        calls: Arc<Mutex<usize>>,
        response: MockResponse,
    }

    impl MockTransport {
        fn new(jwks_body: String) -> Self {
            Self {
                calls: Arc::default(),
                response: MockResponse::Success(jwks_body),
            }
        }

        fn failing_with_network_error() -> Self {
            Self {
                calls: Arc::default(),
                response: MockResponse::NetworkFailure,
            }
        }

        fn call_count(&self) -> usize {
            *self.calls.lock().unwrap()
        }
    }

    impl HttpGet for MockTransport {
        async fn get(
            &self,
            _url: &str,
            _headers: &[(&str, &str)],
            _timeout: Duration,
        ) -> Result<String, TransportError> {
            *self.calls.lock().unwrap() += 1;
            match &self.response {
                MockResponse::Success(body) => Ok(body.clone()),
                MockResponse::NetworkFailure => Err(crate::test_support::network_error()),
            }
        }
    }

    #[derive(Serialize)]
    struct TestClaims<'a> {
        sub: &'a str,
        email: Option<&'a str>,
        nonce: Option<&'a str>,
        nonce_supported: Option<bool>,
        iss: &'a str,
        aud: &'a str,
        iat: u64,
        exp: u64,
    }

    fn test_claims(nonce: Option<&'static str>) -> TestClaims<'static> {
        let iat = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let exp = iat + 3600;
        TestClaims {
            sub: "apple-user-1",
            email: Some("user@example.com"),
            nonce,
            nonce_supported: None,
            iss: "https://appleid.apple.com",
            aud: TEST_BUNDLE_ID,
            iat,
            exp,
        }
    }

    fn sign_token<C: Serialize>(header: jsonwebtoken::Header, claims: &C) -> String {
        let key = match header.alg {
            jsonwebtoken::Algorithm::RS256 => {
                jsonwebtoken::EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_KEY_PEM.as_bytes())
                    .unwrap()
            }
            // in case of HS256 rs256 pem would panic on signing with EncodingKey::from_rsa_pem
            // therefore we need a different key
            _ => jsonwebtoken::EncodingKey::from_secret(b"unrelated-mock-test-secret"),
        };
        jsonwebtoken::encode(&header, claims, &key).unwrap()
    }

    fn rs256_header() -> jsonwebtoken::Header {
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some(TEST_KID.to_string());
        header
    }

    fn client(transport: MockTransport) -> IdentityVerificationClient<MockTransport> {
        client_with_config(transport, IdentityVerificationConfig::default())
    }

    fn client_with_config(
        transport: MockTransport,
        config: IdentityVerificationConfig,
    ) -> IdentityVerificationClient<MockTransport> {
        IdentityVerificationClient::new(
            TEST_BUNDLE_ID,
            transport,
            JwksStoreConfig::default(),
            config,
        )
    }

    #[tokio::test]
    async fn happy_path_with_nonce_returns_identity_and_nonce() {
        let claims = test_claims(Some("expected-nonce"));
        let token = sign_token(rs256_header(), &claims);
        let client = client(MockTransport::new(jwks_body_including(TEST_KID)));

        let identity = client.verify_identity_token(&token).await.unwrap();

        assert_eq!(identity.apple_user_id, "apple-user-1");
        assert_eq!(identity.email.as_deref(), Some("user@example.com"));
        assert_eq!(identity.nonce.as_deref(), Some("expected-nonce"));
        assert_eq!(
            identity.issued_at,
            UNIX_EPOCH + Duration::from_secs(claims.iat)
        );
        assert_eq!(
            identity.expiration,
            UNIX_EPOCH + Duration::from_secs(claims.exp)
        );
    }

    #[tokio::test]
    async fn missing_nonce_is_rejected_by_default() {
        let claims = test_claims(None);
        let token = sign_token(rs256_header(), &claims);
        let client = client(MockTransport::new(jwks_body_including(TEST_KID)));

        let result = client.verify_identity_token(&token).await;

        assert!(matches!(
            result,
            Err(IdunnError::InvalidToken(InvalidTokenCause::MissingNonce))
        ));
    }

    #[tokio::test]
    async fn missing_iat_is_rejected() {
        #[derive(Serialize)]
        struct ClaimsWithoutIat<'a> {
            sub: &'a str,
            iss: &'a str,
            aud: &'a str,
            exp: u64,
        }
        let claims = ClaimsWithoutIat {
            sub: "apple-user-1",
            iss: "https://appleid.apple.com",
            aud: TEST_BUNDLE_ID,
            exp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3600,
        };
        let token = sign_token(rs256_header(), &claims);
        let client = client(MockTransport::new(jwks_body_including(TEST_KID)));

        let result = client.verify_identity_token(&token).await;

        assert!(matches!(
            result,
            Err(IdunnError::InvalidToken(InvalidTokenCause::Rejected(_)))
        ));
    }

    #[tokio::test]
    async fn strict_policy_rejects_missing_nonce_even_when_unsupported() {
        let mut claims = test_claims(None);
        claims.nonce_supported = Some(false);
        let token = sign_token(rs256_header(), &claims);
        let client = client_with_config(
            MockTransport::new(jwks_body_including(TEST_KID)),
            IdentityVerificationConfig {
                nonce_policy: NoncePolicy::Strict,
            },
        );

        let result = client.verify_identity_token(&token).await;

        assert!(matches!(
            result,
            Err(IdunnError::InvalidToken(InvalidTokenCause::MissingNonce))
        ));
    }

    #[tokio::test]
    async fn strict_policy_rejects_missing_nonce_when_supported() {
        let mut claims = test_claims(None);
        claims.nonce_supported = Some(true);
        let token = sign_token(rs256_header(), &claims);
        let client = client_with_config(
            MockTransport::new(jwks_body_including(TEST_KID)),
            IdentityVerificationConfig {
                nonce_policy: NoncePolicy::Strict,
            },
        );

        let result = client.verify_identity_token(&token).await;

        assert!(matches!(
            result,
            Err(IdunnError::InvalidToken(InvalidTokenCause::MissingNonce))
        ));
    }

    #[tokio::test]
    async fn permissive_policy_accepts_missing_nonce_when_nonce_supported_absent() {
        let claims = test_claims(None);
        let token = sign_token(rs256_header(), &claims);
        let client = client_with_config(
            MockTransport::new(jwks_body_including(TEST_KID)),
            IdentityVerificationConfig {
                nonce_policy: NoncePolicy::Permissive,
            },
        );

        let identity = client.verify_identity_token(&token).await.unwrap();

        assert_eq!(identity.nonce, None);
    }

    #[tokio::test]
    async fn permissive_policy_accepts_missing_nonce_when_nonce_unsupported() {
        let mut claims = test_claims(None);
        claims.nonce_supported = Some(false);
        let token = sign_token(rs256_header(), &claims);
        let client = client_with_config(
            MockTransport::new(jwks_body_including(TEST_KID)),
            IdentityVerificationConfig {
                nonce_policy: NoncePolicy::Permissive,
            },
        );

        let identity = client.verify_identity_token(&token).await.unwrap();

        assert_eq!(identity.nonce, None);
    }

    #[tokio::test]
    async fn permissive_policy_rejects_missing_nonce_when_nonce_supported() {
        let mut claims = test_claims(None);
        claims.nonce_supported = Some(true);
        let token = sign_token(rs256_header(), &claims);
        let client = client_with_config(
            MockTransport::new(jwks_body_including(TEST_KID)),
            IdentityVerificationConfig {
                nonce_policy: NoncePolicy::Permissive,
            },
        );

        let result = client.verify_identity_token(&token).await;

        assert!(matches!(
            result,
            Err(IdunnError::InvalidToken(InvalidTokenCause::MissingNonce))
        ));
    }

    #[tokio::test]
    async fn algorithm_mismatch_is_rejected_before_any_transport_call() {
        let claims = test_claims(None);
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
        header.kid = Some(TEST_KID.to_string());
        let token = sign_token(header, &claims);
        let transport = MockTransport::new(jwks_body_including(TEST_KID));
        let client = client(transport.clone());

        let result = client.verify_identity_token(&token).await;

        assert!(matches!(
            result,
            Err(IdunnError::InvalidToken(
                InvalidTokenCause::AlgorithmMismatch(jsonwebtoken::Algorithm::HS256)
            ))
        ));
        assert_eq!(transport.call_count(), 0);
    }

    #[tokio::test]
    async fn missing_kid_is_rejected() {
        let claims = test_claims(None);
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = None;
        let token = sign_token(header, &claims);
        let client = client(MockTransport::new(jwks_body_including(TEST_KID)));

        let result = client.verify_identity_token(&token).await;

        assert!(matches!(
            result,
            Err(IdunnError::InvalidToken(InvalidTokenCause::InvalidKeyId {
                kid: None
            }))
        ));
    }

    #[tokio::test]
    async fn apple_unavailable_surfaces_as_cannot_verify_token() {
        let claims = test_claims(Some("expected-nonce"));
        let token = sign_token(rs256_header(), &claims);
        let transport = MockTransport::failing_with_network_error();
        let client = client(transport.clone());

        let result = client.verify_identity_token(&token).await;

        assert!(matches!(result, Err(IdunnError::CannotVerifyToken)));
        assert_eq!(transport.call_count(), 1);
    }

    #[tokio::test]
    async fn token_missing_aud_claim_is_rejected() {
        // `aud` is deliberately left out - should be rejected
        #[derive(Serialize)]
        struct ClaimsWithoutAud<'a> {
            sub: &'a str,
            iss: &'a str,
            iat: u64,
            exp: u64,
        }
        let iat = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let claims = ClaimsWithoutAud {
            sub: "apple-user-1",
            iss: "https://appleid.apple.com",
            iat,
            exp: iat + 3600,
        };
        let token = sign_token(rs256_header(), &claims);
        let client = client(MockTransport::new(jwks_body_including(TEST_KID)));

        let result = client.verify_identity_token(&token).await;

        assert!(matches!(
            result,
            Err(IdunnError::InvalidToken(InvalidTokenCause::Rejected(_)))
        ));
    }
}
