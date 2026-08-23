use std::future::Future;
use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::error::IdunnError;

const TOKEN_URL: &str = "https://appleid.apple.com/auth/token";
/// Client secret is minted fresh for each request, so it only needs to live
/// long enough to reach Apple's token endpoint.
const CLIENT_SECRET_TTL_SECS: u64 = 300;

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

#[derive(Deserialize)]
struct AppleErrorResponse {
    error: String,
}

#[derive(Serialize)]
struct ClientSecretClaims<'a> {
    iss: &'a str,
    iat: u64,
    exp: u64,
    aud: &'a str,
    sub: &'a str,
}

/// Error from the HTTP transport used to reach Apple's endpoints — a network
/// failure, or a non-2xx HTTP response (status code + raw body). Deliberately
/// narrower than `IdunnError`: this is also what external `HttpTransport`
/// implementors construct, and they shouldn't need to know about idunn's
/// Apple-specific error variants. `Network` is boxed rather than tied to
/// `reqwest::Error` so a non-reqwest `HttpTransport` implementation can report
/// its own underlying error type.
#[derive(Debug, Error)]
pub enum TransportError {
    #[error("network error: {0}")]
    Network(Box<dyn std::error::Error + Send + Sync>),
    #[error("HTTP {status} response: {body}")]
    Http { status: u16, body: String },
}

/// Abstraction over the HTTP requests needed to talk to Apple's token endpoints.
/// Exists so the transport is swappable (idunn consumers may prefer a differently
/// configured or non-reqwest client) and so tests can substitute an in-memory fake
/// instead of hitting the network.
/// TODO: use this in AppleAuthClient as well
pub trait HttpTransport: Clone + Send + Sync + 'static {
    /// POSTs a body, returning the response body on success (2xx) or a `TransportError`
    /// (network failure, or the raw status/body on non-2xx). `body` is already
    /// url-encoded by idunn — implementors just need to send it, not assemble it
    /// themselves. `headers` are the header key/value pairs the caller wants attached
    /// (e.g. `Content-Type`) — implementors attach them as given, they don't assume or
    /// hardcode a content type themselves.
    fn post_form(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        body: &str,
    ) -> impl Future<Output = Result<String, TransportError>> + Send;

    /// GETs a resource, returning the response body on success (2xx) or a
    /// `TransportError` on failure. No body is sent; `headers` are attached as
    /// given, same as `post_form`.
    fn get(
        &self,
        url: &str,
        headers: &[(&str, &str)],
    ) -> impl Future<Output = Result<String, TransportError>> + Send;
}

#[derive(Clone, Default)]
pub struct ReqwestTransport(reqwest::Client);

impl ReqwestTransport {
    fn with_headers(
        mut request: reqwest::RequestBuilder,
        headers: &[(&str, &str)],
    ) -> reqwest::RequestBuilder {
        for (key, value) in headers {
            request = request.header(*key, *value);
        }
        request
    }

    async fn send(request: reqwest::RequestBuilder) -> Result<String, TransportError> {
        let resp = request
            .send()
            .await
            .map_err(|e| TransportError::Network(Box::new(e)))?;
        let status = resp.status();
        let body = resp
            .text()
            .await
            .map_err(|e| TransportError::Network(Box::new(e)))?;
        if !status.is_success() {
            return Err(TransportError::Http {
                status: status.as_u16(),
                body,
            });
        }
        Ok(body)
    }
}

impl HttpTransport for ReqwestTransport {
    async fn post_form(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        body: &str,
    ) -> Result<String, TransportError> {
        let request = Self::with_headers(self.0.post(url).body(body.to_string()), headers);
        Self::send(request).await
    }

    async fn get(&self, url: &str, headers: &[(&str, &str)]) -> Result<String, TransportError> {
        let request = Self::with_headers(self.0.get(url), headers);
        Self::send(request).await
    }
}

fn encode_form(pairs: &[(&str, &str)]) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish()
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

pub async fn exchange_authorization_code<T: HttpTransport>(
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
        )
        .await
        .map_err(|err| match err {
            TransportError::Network(e) => IdunnError::NetworkError(e),
            TransportError::Http { body, .. } => {
                let message = serde_json::from_str::<AppleErrorResponse>(&body)
                    .map(|e| e.error)
                    .unwrap_or(body);
                IdunnError::TokenExchangeFailed(message)
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

    impl HttpTransport for FakeTransport {
        async fn post_form(
            &self,
            url: &str,
            _headers: &[(&str, &str)],
            body: &str,
        ) -> Result<String, TransportError> {
            self.calls
                .lock()
                .unwrap()
                .push((url.to_string(), body.to_string()));
            self.respond()
        }

        async fn get(
            &self,
            url: &str,
            _headers: &[(&str, &str)],
        ) -> Result<String, TransportError> {
            self.calls
                .lock()
                .unwrap()
                .push((url.to_string(), String::new()));
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

        assert!(
            matches!(result, Err(IdunnError::TokenExchangeFailed(msg)) if msg == "invalid_grant")
        );
    }
}
