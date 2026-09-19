use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};

use crate::error::{AppleErrorCode, ClientSecretError, TokenExchangeError, TokenRevocationError};
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
///
/// Zeroizes every field on drop (`ZeroizeOnDrop`), including every `Clone` of it, so
/// the `.p8` key is not left readable in freed memory — the `EncodingKey` idunn
/// derives from it already does the same. Its `Debug` impl is hand-written to
/// redact `private_key_pem` (a derived one would dump the raw key bytes into any
/// log line or panic message). See the note on `private_key_pem` for what the
/// zeroize guarantee does and does not cover.
#[derive(Clone, zeroize::ZeroizeOnDrop)]
pub struct AppleTokenConfig {
    /// The issuer registered claim identifies the principal that issued the client secret.
    /// Because the client secret belongs to your developer team, use the 10-character
    /// Team ID associated with your developer account.
    pub team_id: String,
    /// Apple: "A 10-character key identifier generated for the Account and Organizational Data
    /// Sharing private key associated with your developer account.
    pub key_id: String,
    /// Apple: "The identifier (App ID or Services ID) for your app. To help prevent the possibility of exposing sensitive
    /// data to the end user, the identifier must not include your Team ID."
    /// Also the expected `aud` claim on identity tokens passed to `verify_identity_token` —
    /// Apple's docs specify the identity token's audience is always the developer's client_id,
    /// so this one field drives both token exchange and identity verification.
    pub client_id: String,
    /// PEM-encoded PKCS#8 EC private key (the .p8 file Apple provides), as bytes.
    ///
    /// This struct wipes its own copy (and every `Clone`'s) on drop, but that only
    /// helps if the caller doesn't keep a separate one: read the `.p8` straight
    /// into the `Vec` handed to this field and move it in, rather than cloning it
    /// off a long-lived config object or leaving the PEM sitting in a `String`
    /// environment variable. And `Vec`'s zeroization is best-effort — a buffer
    /// that reallocated while being built may have left earlier bytes elsewhere on
    /// the heap, which nothing here can reach.
    pub private_key_pem: Vec<u8>,
}

impl std::fmt::Debug for AppleTokenConfig {
    /// Hand-written, not derived: the identifier fields are non-secret (see
    /// their docs) and printed in full, but `private_key_pem` is shown only as
    /// a byte count so the key never reaches a log or panic message. Keeping
    /// this explicit also means a later `#[derive(Debug)]` can't silently
    /// reintroduce the leak.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppleTokenConfig")
            .field("team_id", &self.team_id)
            .field("key_id", &self.key_id)
            .field("client_id", &self.client_id)
            .field(
                "private_key_pem",
                &format_args!("<{} redacted bytes>", self.private_key_pem.len()),
            )
            .finish()
    }
}

/// A refresh token issued by Apple.
///
/// Wrapped rather than a bare `String` so it can't print live credential
/// material through a derived `Debug` wherever it ends up — both
/// `VerifiedAuthorization::refresh_token` (a success value that might still be
/// logged) and `SignInError::ExchangedTokenUnverified` (an error, which gets
/// `{:?}`-printed into logs, `anyhow` chains and `unwrap()` panic messages by
/// convention). Deliberately has no `Display` impl either, for the same
/// reason. Reach for the value explicitly through `as_str`/`into_inner`.
#[derive(Clone)]
pub struct RefreshToken(String);

impl RefreshToken {
    pub(crate) fn new(token: String) -> Self {
        Self(token)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl std::fmt::Debug for RefreshToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RefreshToken(<redacted>)")
    }
}

/// What Apple's token endpoint returns, before the identity token is verified.
/// Crate-internal: the `id_token` never reaches a caller unverified — see
/// `AppleAuthClient::exchange_authorization_code`.
pub(crate) struct ExchangedTokens {
    pub(crate) refresh_token: RefreshToken,
    pub(crate) id_token: String,
}

/// Only `refresh_token`/`id_token` are captured: idunn doesn't use the access
/// token or its `expires_in`, and `serde` ignores the unlisted fields rather
/// than requiring them to be absent.
#[derive(Deserialize)]
struct RawTokenResponse {
    refresh_token: String,
    id_token: String,
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
) -> Result<String, ClientSecretError> {
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
    jsonwebtoken::encode(&header, &claims, signing_key).map_err(ClientSecretError::from)
}

pub(crate) async fn exchange_authorization_code<T: HttpPost>(
    transport: &T,
    config: &AppleTokenConfig,
    signing_key: &EncodingKey,
    authorization_code: &str,
) -> Result<ExchangedTokens, TokenExchangeError> {
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
            TransportError::Network(e) => TokenExchangeError::NetworkError(e),
            TransportError::Http { body, .. } => {
                TokenExchangeError::TokenExchangeFailed(AppleErrorCode::from_response_body(body))
            }
        })?;
    let raw: RawTokenResponse =
        serde_json::from_str(&response_body).map_err(TokenExchangeError::InvalidTokenResponse)?;
    Ok(ExchangedTokens {
        refresh_token: RefreshToken::new(raw.refresh_token),
        id_token: raw.id_token,
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
) -> Result<(), TokenRevocationError> {
    let client_secret = build_client_secret(config, signing_key)?;
    let form = [
        ("client_id", config.client_id.as_str()),
        ("client_secret", client_secret.as_str()),
        ("token", refresh_token),
        ("token_type_hint", "refresh_token"),
    ];
    let encoded_body = encode_form(&form);
    match transport
        .post_form(
            REVOKE_URL,
            &[("Content-Type", "application/x-www-form-urlencoded")],
            &encoded_body,
            REQUEST_TIMEOUT,
        )
        .await
    {
        Ok(_) => Ok(()),
        Err(TransportError::Network(e)) => Err(TokenRevocationError::NetworkError(e)),
        Err(TransportError::Http { body, .. }) => match AppleErrorCode::from_response_body(body) {
            // Apple doesn't recognize this as a usable grant any more — already
            // revoked, expired, or never valid.
            //
            // OAuth's `invalid_grant` also covers a token issued to a
            // different client; for a token this crate obtained with its own
            // credentials that can't legitimately happen.
            AppleErrorCode::InvalidGrant => {
                tracing::warn!(
                    "Apple rejected the refresh token as invalid_grant while revoking it; \
                     treating it as already revoked"
                );
                Ok(())
            }
            code => Err(TokenRevocationError::TokenRevocationFailed(code)),
        },
    }
}

#[cfg(any(test, feature = "test-fixtures"))]
#[cfg_attr(coverage_nightly, coverage(off))]
pub mod test_fixtures {
    use super::AppleTokenConfig;

    pub const TEST_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQggeco4/EEIM9ovqMW\n\
csOfc9dl5tGk8LndzgU4CVvEqLihRANCAAQNSRZdtAsSZG8pTuLiK7JdLUog/M7I\n\
zqbgw/e2HmOOuotg2tZP7JoBgnu7rNEplIygqTjYf8pKesYPyHrOj5ae\n\
-----END PRIVATE KEY-----\n";

    /// EC public half matching `TEST_PRIVATE_KEY_PEM`, for tests that need to verify
    /// a client secret idunn signed rather than just producing one.
    pub const TEST_PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEDUkWXbQLEmRvKU7i4iuyXS1KIPzO\n\
yM6m4MP3th5jjrqLYNrWT+yaAYJ7u6zRKZSMoKk42H/KSnrGD8h6zo+Wng==\n\
-----END PUBLIC KEY-----\n";

    pub fn test_token_config() -> AppleTokenConfig {
        AppleTokenConfig {
            team_id: "TEAM123456".to_string(),
            key_id: "KEY7890".to_string(),
            client_id: "com.example.myapp".to_string(),
            private_key_pem: TEST_PRIVATE_KEY_PEM.as_bytes().to_vec(),
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::test_fixtures::{TEST_PUBLIC_KEY_PEM, test_token_config as test_config};
    use super::*;
    use crate::transport::test_fixtures::network_error;
    use jsonwebtoken::{Algorithm, DecodingKey, Validation};
    use std::sync::{Arc, Mutex};

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
        // `Option` (not the bare `Result`) so `.take()` can move a non-`Clone`
        // `TransportError::Network` out on the single call each test makes,
        // rather than needing to clone the response on every call.
        response: Arc<Mutex<Option<Result<String, TransportError>>>>,
    }

    impl FakeTransport {
        fn returning(body: &str) -> Self {
            Self {
                calls: Arc::default(),
                response: Arc::new(Mutex::new(Some(Ok(body.to_string())))),
            }
        }

        fn failing_with(err: TransportError) -> Self {
            Self {
                calls: Arc::default(),
                response: Arc::new(Mutex::new(Some(Err(err)))),
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
            self.response
                .lock()
                .unwrap()
                .take()
                .expect("no response configured")
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

        assert_eq!(response.refresh_token.as_str(), "rt");
        assert_eq!(response.id_token, "it");

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
            Err(TokenExchangeError::TokenExchangeFailed(
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
            Err(TokenExchangeError::TokenExchangeFailed(
                AppleErrorCode::UnknownError(_)
            ))
        ));
    }

    #[tokio::test]
    async fn surfaces_network_error_on_exchange() {
        let config = test_config();
        let signing_key = EncodingKey::from_ec_pem(&config.private_key_pem).unwrap();
        let transport = FakeTransport::failing_with(network_error());

        let result =
            exchange_authorization_code(&transport, &config, &signing_key, "auth-code").await;

        assert!(matches!(result, Err(TokenExchangeError::NetworkError(_))));
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
            body: r#"{"error":"invalid_client"}"#.to_string(),
        });

        let result = revoke_refresh_token(&transport, &config, &signing_key, "bad-token").await;

        assert!(matches!(
            result,
            Err(TokenRevocationError::TokenRevocationFailed(
                AppleErrorCode::InvalidClient
            ))
        ));
    }

    /// Apple answering `invalid_grant` to a revoke means it no longer
    /// recognizes the token as a usable grant — already revoked, expired, or
    /// never valid. The call's purpose (the token can't be used) already
    /// holds, so this is treated as success rather than pushed into a retry
    /// loop that could never succeed.
    #[tokio::test]
    async fn treats_invalid_grant_as_a_successful_revocation() {
        let config = test_config();
        let signing_key = EncodingKey::from_ec_pem(&config.private_key_pem).unwrap();
        let transport = FakeTransport::failing_with(TransportError::Http {
            status: 400,
            body: r#"{"error":"invalid_grant"}"#.to_string(),
        });

        let result = revoke_refresh_token(&transport, &config, &signing_key, "bad-token").await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn surfaces_network_error_on_revocation() {
        let config = test_config();
        let signing_key = EncodingKey::from_ec_pem(&config.private_key_pem).unwrap();
        let transport = FakeTransport::failing_with(network_error());

        let result = revoke_refresh_token(&transport, &config, &signing_key, "refresh-token").await;

        assert!(matches!(result, Err(TokenRevocationError::NetworkError(_))));
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

    /// Guarantees the `ZeroizeOnDrop` derive stays on `AppleTokenConfig`: remove
    /// it and this stops compiling.
    ///
    /// A stronger test — fill `private_key_pem` with a known pattern, drop the
    /// config, then read the freed allocation back through a raw pointer and
    /// assert it is all zero — was tried and dropped. macOS's allocator writes
    /// free-list bookkeeping into the head of a just-freed small block, so the
    /// first ~11 bytes come back nonzero even though the derive zeroed the
    /// buffer (bytes 11..256 were `0x00`). Asserting on a use-after-free read is
    /// inherently allocator-dependent; the marker-trait check is what stays.
    #[test]
    fn apple_token_config_is_zeroize_on_drop() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<AppleTokenConfig>();
    }

    #[test]
    fn refresh_token_into_inner_returns_the_wrapped_string() {
        let token = RefreshToken::new("rt-value".to_string());

        assert_eq!(token.into_inner(), "rt-value");
    }

    #[test]
    fn refresh_token_debug_redacts_the_value() {
        let token = RefreshToken::new("rt-value".to_string());

        let rendered = format!("{token:?}");

        assert_eq!(rendered, "RefreshToken(<redacted>)");
        assert!(!rendered.contains("rt-value"));
    }

    /// The hand-written `Debug` shows the non-secret identifiers but must never
    /// render any of the key material.
    #[test]
    fn debug_redacts_the_private_key() {
        let config = test_config();
        let rendered = format!("{config:?}");

        assert!(rendered.contains("key_id: \"KEY7890\""));
        assert!(rendered.contains("redacted bytes"));
        assert!(!rendered.contains("BEGIN PRIVATE KEY"));
        let pem = String::from_utf8(config.private_key_pem.clone()).unwrap();
        for line in pem.lines().filter(|l| l.len() > 16) {
            assert!(
                !rendered.contains(line),
                "Debug output leaked a line of the PEM key"
            );
        }
    }
}
