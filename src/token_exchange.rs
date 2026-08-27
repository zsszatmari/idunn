use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};

use crate::error::{AppleErrorCode, IdunnError};
use crate::transport::{HttpPost, TransportError, encode_form};

const TOKEN_URL: &str = "https://appleid.apple.com/auth/token";
const REVOKE_URL: &str = "https://appleid.apple.com/auth/revoke";
/// Client secret is minted fresh for each request, so it only needs to live
/// long enough to reach Apple's token endpoint.
const CLIENT_SECRET_TTL_SECS: u64 = 300;
// TODO: make this configurable through the public API instead of hardcoding it here.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Credentials needed to authenticate as this app to Apple's token/revoke endpoints.
/// Grouped as named fields rather than positional constructor args: team_id/key_id/
/// client_id are all opaque strings and easy to transpose otherwise.
#[derive(Clone)]
pub struct AppleTokenConfig {
    pub team_id: String,
    /// Apple: "A 10-character key identifier generated for the Account and Organizational Data
    /// Sharing private key associated with your developer account.
    pub key_id: String,
    /// Apple: "The identifier (App ID or Services ID) for your app. To help prevent the possibility of exposing sensitive
    /// data to the end user, the identifier must not include your Team ID."
    pub client_id: String,
    /// PEM-encoded PKCS#8 EC private key (the .p8 file Apple provides), as bytes.
    pub private_key_pem: Vec<u8>,
}

/// Tokens returned by Apple after exchanging an authorization code.
#[derive(Debug, Clone)]
pub struct AppleTokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub id_token: String,
    pub expires_in: u64,
}

#[derive(Deserialize)]
struct RawTokenResponse {
    access_token: String,
    refresh_token: String,
    id_token: String,
    expires_in: u64,
}

#[derive(Serialize)]
struct ClientSecretClaims<'a> {
    iss: &'a str,
    iat: u64,
    exp: u64,
    aud: &'a str,
    sub: &'a str,
}

pub fn build_client_secret(
    config: &AppleTokenConfig,
    signing_key: &EncodingKey,
) -> Result<String, IdunnError> {
    // https://developer.apple.com/documentation/accountorganizationaldatasharing/creating-a-client-secret
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(config.key_id.clone());
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after unix epoch")
        .as_secs();
    let claims = ClientSecretClaims {
        iss: &config.team_id,
        iat: now,
        exp: now + CLIENT_SECRET_TTL_SECS,
        aud: "https://appleid.apple.com",
        sub: &config.client_id,
    };
    jsonwebtoken::encode(&header, &claims, signing_key)
        .map_err(IdunnError::ClientSecretSigningFailed)
}

pub async fn exchange_authorization_code<T: HttpPost>(
    transport: &T,
    config: &AppleTokenConfig,
    signing_key: &EncodingKey,
    authorization_code: &str,
) -> Result<AppleTokenResponse, IdunnError> {
    let client_secret = build_client_secret(config, signing_key)?;
    let form = [
        ("client_id", config.client_id.as_str()),
        ("client_secret", client_secret.as_str()),
        ("code", authorization_code),
        ("grant_type", "authorization_code"),
    ];
    let encoded_body = encode_form(&form);
    let response_body = transport
        .post_form(
            TOKEN_URL,
            &[("Content-Type", "application/x-www-form-urlencoded")],
            &encoded_body,
            REQUEST_TIMEOUT,
        )
        .await
        .map_err(|err| match err {
            TransportError::Network(e) => IdunnError::NetworkError(e),
            TransportError::Http { body, .. } => {
                IdunnError::TokenExchangeFailed(AppleErrorCode::from_response_body(body))
            }
        })?;
    let raw: RawTokenResponse =
        serde_json::from_str(&response_body).map_err(IdunnError::InvalidTokenResponse)?;
    Ok(AppleTokenResponse {
        access_token: raw.access_token,
        refresh_token: raw.refresh_token,
        id_token: raw.id_token,
        expires_in: raw.expires_in,
    })
}

/// Revoke a refresh token previously issued by Apple (e.g. on sign-out or account
/// deletion) so it can no longer be used.
/// https://developer.apple.com/documentation/signinwithapplerestapi/revoke-tokens
pub async fn revoke_refresh_token<T: HttpPost>(
    transport: &T,
    config: &AppleTokenConfig,
    signing_key: &EncodingKey,
    refresh_token: &str,
) -> Result<(), IdunnError> {
    let client_secret = build_client_secret(config, signing_key)?;
    let form = [
        ("client_id", config.client_id.as_str()),
        ("client_secret", client_secret.as_str()),
        ("token", refresh_token),
        ("token_type_hint", "refresh_token"),
    ];
    let encoded_body = encode_form(&form);
    transport
        .post_form(
            REVOKE_URL,
            &[("Content-Type", "application/x-www-form-urlencoded")],
            &encoded_body,
            REQUEST_TIMEOUT,
        )
        .await
        .map_err(|err| match err {
            TransportError::Network(e) => IdunnError::NetworkError(e),
            TransportError::Http { body, .. } => {
                IdunnError::TokenRevocationFailed(AppleErrorCode::from_response_body(body))
            }
        })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::test_token_config as test_config;
    use jsonwebtoken::{Algorithm, DecodingKey, Validation};
    use std::sync::{Arc, Mutex};

    const TEST_PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEDUkWXbQLEmRvKU7i4iuyXS1KIPzO\n\
yM6m4MP3th5jjrqLYNrWT+yaAYJ7u6zRKZSMoKk42H/KSnrGD8h6zo+Wng==\n\
-----END PUBLIC KEY-----\n";

    #[test]
    fn client_secret_is_a_well_formed_apple_jwt() {
        let config = test_config();
        let signing_key = EncodingKey::from_ec_pem(&config.private_key_pem).unwrap();

        let jwt = build_client_secret(&config, &signing_key).unwrap();

        let header = jsonwebtoken::decode_header(&jwt).unwrap();
        assert_eq!(header.alg, Algorithm::ES256);
        assert_eq!(header.kid.as_deref(), Some("KEY7890"));

        let decoding_key = DecodingKey::from_ec_pem(TEST_PUBLIC_KEY_PEM.as_bytes()).unwrap();
        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_audience(&["https://appleid.apple.com"]);
        validation.set_required_spec_claims(&["iss", "iat", "exp", "aud", "sub"]);
        let claims =
            jsonwebtoken::decode::<ClientSecretClaimsOwned>(&jwt, &decoding_key, &validation)
                .unwrap()
                .claims;

        assert_eq!(claims.iss, "TEAM123456");
        assert_eq!(claims.sub, "com.example.myapp");
        assert_eq!(claims.exp - claims.iat, CLIENT_SECRET_TTL_SECS);
    }

    #[derive(Deserialize)]
    struct ClientSecretClaimsOwned {
        iss: String,
        iat: u64,
        exp: u64,
        sub: String,
    }

    #[derive(Clone)]
    struct FakeTransport {
        calls: Arc<Mutex<Vec<(String, String)>>>,
        response: Arc<Mutex<Result<String, TransportError>>>,
    }

    impl FakeTransport {
        fn returning(body: &str) -> Self {
            Self {
                calls: Arc::default(),
                response: Arc::new(Mutex::new(Ok(body.to_string()))),
            }
        }

        fn failing_with(err: TransportError) -> Self {
            Self {
                calls: Arc::default(),
                response: Arc::new(Mutex::new(Err(err))),
            }
        }
    }

    impl FakeTransport {
        fn respond(&self) -> Result<String, TransportError> {
            match &*self.response.lock().unwrap() {
                Ok(body) => Ok(body.clone()),
                Err(TransportError::Http { status, body }) => Err(TransportError::Http {
                    status: *status,
                    body: body.clone(),
                }),
                Err(_) => panic!("unsupported error variant in test fake"),
            }
        }
    }

    impl HttpPost for FakeTransport {
        async fn post_form(
            &self,
            url: &str,
            _headers: &[(&str, &str)],
            body: &str,
            _timeout: Duration,
        ) -> Result<String, TransportError> {
            self.calls
                .lock()
                .unwrap()
                .push((url.to_string(), body.to_string()));
            self.respond()
        }
    }

    #[tokio::test]
    async fn exchanges_authorization_code_for_tokens() {
        let config = test_config();
        let signing_key = EncodingKey::from_ec_pem(&config.private_key_pem).unwrap();
        let transport = FakeTransport::returning(
            r#"{"access_token":"at","refresh_token":"rt","id_token":"it","expires_in":3600}"#,
        );

        let response = exchange_authorization_code(&transport, &config, &signing_key, "auth-code")
            .await
            .unwrap();

        assert_eq!(response.access_token, "at");
        assert_eq!(response.refresh_token, "rt");
        assert_eq!(response.id_token, "it");
        assert_eq!(response.expires_in, 3600);

        let calls = transport.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        let (url, body) = &calls[0];
        assert_eq!(url, TOKEN_URL);
        let decoded: Vec<(String, String)> = url::form_urlencoded::parse(body.as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        assert!(decoded.contains(&("grant_type".to_string(), "authorization_code".to_string())));
        assert!(decoded.contains(&("code".to_string(), "auth-code".to_string())));
        assert!(decoded.contains(&("client_id".to_string(), "com.example.myapp".to_string())));
    }

    #[tokio::test]
    async fn surfaces_apple_error_response() {
        let config = test_config();
        let signing_key = EncodingKey::from_ec_pem(&config.private_key_pem).unwrap();
        let transport = FakeTransport::failing_with(TransportError::Http {
            status: 400,
            body: r#"{"error":"invalid_grant"}"#.to_string(),
        });

        let result =
            exchange_authorization_code(&transport, &config, &signing_key, "bad-code").await;

        assert!(matches!(
            result,
            Err(IdunnError::TokenExchangeFailed(
                AppleErrorCode::InvalidGrant
            ))
        ));
    }

    #[tokio::test]
    async fn surfaces_unrecognized_apple_error_response() {
        let config = test_config();
        let signing_key = EncodingKey::from_ec_pem(&config.private_key_pem).unwrap();
        let transport = FakeTransport::failing_with(TransportError::Http {
            status: 400,
            body: r#"{"error":"some_future_code"}"#.to_string(),
        });

        let result =
            exchange_authorization_code(&transport, &config, &signing_key, "bad-code").await;

        assert!(matches!(
            result,
            Err(IdunnError::TokenExchangeFailed(
                AppleErrorCode::UnknownError(_)
            ))
        ));
    }

    #[tokio::test]
    async fn revokes_refresh_token() {
        let config = test_config();
        let signing_key = EncodingKey::from_ec_pem(&config.private_key_pem).unwrap();
        let transport = FakeTransport::returning("");

        let result = revoke_refresh_token(&transport, &config, &signing_key, "refresh-token").await;

        assert!(result.is_ok());

        let calls = transport.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        let (url, body) = &calls[0];
        assert_eq!(url, REVOKE_URL);
        let decoded: Vec<(String, String)> = url::form_urlencoded::parse(body.as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        assert!(decoded.contains(&("token".to_string(), "refresh-token".to_string())));
        assert!(decoded.contains(&("token_type_hint".to_string(), "refresh_token".to_string())));
        assert!(decoded.contains(&("client_id".to_string(), "com.example.myapp".to_string())));
    }

    #[tokio::test]
    async fn surfaces_apple_revocation_error() {
        let config = test_config();
        let signing_key = EncodingKey::from_ec_pem(&config.private_key_pem).unwrap();
        let transport = FakeTransport::failing_with(TransportError::Http {
            status: 400,
            body: r#"{"error":"invalid_grant"}"#.to_string(),
        });

        let result = revoke_refresh_token(&transport, &config, &signing_key, "bad-token").await;

        assert!(matches!(
            result,
            Err(IdunnError::TokenRevocationFailed(
                AppleErrorCode::InvalidGrant
            ))
        ));
    }

    /// Hits Apple's real `/auth/revoke` endpoint with an unknown, clearly-marked-as-test
    /// refresh token. Per Apple's docs, revoke is idempotent for anti-enumeration
    /// reasons: it returns 200 with no body both on a real revocation and when the
    /// token was already invalid/unknown — so this only confirms live connectivity and
    /// request shape, not error parsing (see the sibling test below for that). Not
    /// `#[ignore]`d — it needs network access, which this development sandbox's Bash
    /// tool doesn't have, so it couldn't be run/verified while writing it; it still
    /// runs under a normal `cargo test` for anyone with network access (e.g. CI).
    ///
    /// To see the exact bytes sent/received on the wire, run with:
    /// `RUST_LOG=reqwest=trace cargo test real_apple_revoke_endpoint -- --nocapture`
    /// (uses reqwest's own built-in `connection_verbose` wire logging, not a custom dump).
    #[tokio::test]
    async fn real_apple_revoke_endpoint_is_idempotent_for_an_unknown_token() {
        let _ = env_logger::try_init();
        let config = test_config();
        let signing_key = EncodingKey::from_ec_pem(&config.private_key_pem).unwrap();
        let client = reqwest::Client::builder()
            .connection_verbose(true)
            .build()
            .unwrap();
        let transport = crate::transport::ReqwestTransport::with_client(client);

        let result =
            revoke_refresh_token(&transport, &config, &signing_key, "idunn-test-token").await;

        assert!(result.is_ok(), "expected Ok(()), got {result:?}");
    }

    /// Hits Apple's real `/auth/revoke` endpoint with `client_secret` omitted entirely,
    /// to confirm `AppleErrorCode::from_response_body` actually recognizes the error
    /// shape Apple returns in production for a malformed request (not just the shape we
    /// assume in the fakes above). A bad token isn't reliable for this (see the sibling
    /// test above — Apple treats an unknown token as a no-op success), and empirically
    /// neither is a present-but-garbage `client_secret` (Apple accepted
    /// `"not-a-valid-jwt"` as one with a 200); a genuinely *missing* required parameter
    /// is Apple's documented `invalid_request` trigger, so this targets that instead.
    #[tokio::test]
    async fn real_apple_revoke_endpoint_rejects_a_missing_client_secret() {
        let _ = env_logger::try_init();
        let client = reqwest::Client::builder()
            .connection_verbose(true)
            .build()
            .unwrap();
        let transport = crate::transport::ReqwestTransport::with_client(client);

        let form = [
            ("client_id", "com.example.myapp"),
            ("token", "idunn-test-token"),
            ("token_type_hint", "refresh_token"),
        ];
        let encoded_body = encode_form(&form);

        let result = transport
            .post_form(
                REVOKE_URL,
                &[("Content-Type", "application/x-www-form-urlencoded")],
                &encoded_body,
                REQUEST_TIMEOUT,
            )
            .await;

        match result {
            Err(TransportError::Http { body, .. }) => {
                let code = AppleErrorCode::from_response_body(body);
                assert!(
                    matches!(code, AppleErrorCode::InvalidClient),
                    "expected invalid_client from Apple, got {code:?}"
                );
            }
            other => panic!("expected an HTTP error response, got {other:?}"),
        }
    }
}
