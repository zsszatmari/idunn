use thiserror::Error;

/// Error verifying an Apple identity token or exchanging an authorization code.
/// TODO: do we need all these, especially from the client's perspective?
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum IdunnError {
    /// The token is confirmed invalid — see `cause` for specifics.
    #[error("invalid Apple identity token: {0}")]
    InvalidToken(InvalidTokenCause),
    /// The token's validity could not be determined (e.g. Apple's key set
    /// couldn't be fetched or is being backed off after a recent failure).
    /// Distinct from `InvalidToken`: this is not a claim that the token is bad,
    /// only that verification couldn't be completed right now.
    #[error("could not verify Apple identity token: key set is unavailable")]
    CannotVerifyToken,
    #[error("network error: {0}")]
    NetworkError(Box<dyn std::error::Error + Send + Sync>),
    #[error("invalid Apple private key: {0}")]
    InvalidPrivateKey(jsonwebtoken::errors::Error),
    #[error("failed to sign client secret: {0}")]
    ClientSecretSigningFailed(jsonwebtoken::errors::Error),
    #[error("Apple token endpoint returned an error: {0}")]
    TokenExchangeFailed(AppleErrorCode),
    #[error("Apple revoke endpoint returned an error: {0}")]
    TokenRevocationFailed(AppleErrorCode),
    #[error("could not parse Apple token response: {0}")]
    InvalidTokenResponse(serde_json::Error),
}

/// Why an Apple identity token was found to be invalid. Only the causes this
/// crate currently detects are listed; more (issuer mismatch, expiry, bad
/// signature, ...) will be added as identity verification is completed.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum InvalidTokenCause {
    /// The token's `kid` is missing from its header, or isn't in Apple's
    /// currently published (successfully fetched, fresh) key set.
    #[error("Apple identity token key id {kid:?} not found in Apple's published key set")]
    InvalidKeyId { kid: Option<String> },
    /// `jsonwebtoken` rejected the token outright — malformed header, bad
    /// signature, or a claim (issuer/audience/expiry) it doesn't satisfy.
    #[error("Apple identity token failed verification: {0}")]
    Rejected(jsonwebtoken::errors::Error),
    /// Header declares an algorithm other than the RS256 Apple actually uses.
    #[error("Apple identity token uses algorithm {0:?} instead of the expected RS256")]
    AlgorithmMismatch(jsonwebtoken::Algorithm),
    /// The token has no `nonce` claim, and the configured `NoncePolicy`
    /// requires one — either because the policy is `Strict` (a nonce is
    /// required unconditionally), or because it's `Permissive` and the
    /// token's `nonce_supported` claim was `true`.
    #[error("Apple identity token carries no nonce claim, which the configured nonce policy requires")]
    MissingNonce,
}

/// Apple's documented `ErrorResponse.error` codes.
/// https://developer.apple.com/documentation/signinwithapplerestapi/errorresponse
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AppleErrorCode {
    #[error("invalid_request: the request is malformed")]
    InvalidRequest,
    #[error("invalid_client: client authentication failed")]
    InvalidClient,
    #[error("invalid_grant: the authorization grant or refresh token is invalid")]
    InvalidGrant,
    #[error(
        "unauthorized_client: the client isn't authorized to use this authorization grant type"
    )]
    UnauthorizedClient,
    #[error(
        "unsupported_grant_type: the authenticated client isn't authorized to use this grant type"
    )]
    UnsupportedGrantType,
    #[error("invalid_scope: the requested scope is invalid")]
    InvalidScope,
    /// The response body didn't parse as `ErrorResponse`, or its `error` value
    /// isn't one of Apple's documented codes. Carries the raw response body.
    #[error("unrecognized Apple error response: {0}")]
    UnknownError(String),
}

impl AppleErrorCode {
    /// Parses a raw HTTP error body from Apple's token/revoke endpoints into a
    /// typed code, falling back to `UnknownError` (holding the raw body) if it
    /// doesn't parse as `{"error": "..."}` or the code isn't one Apple documents.
    pub(crate) fn from_response_body(body: String) -> Self {
        #[derive(serde::Deserialize)]
        struct RawErrorResponse {
            error: String,
        }
        let Ok(raw) = serde_json::from_str::<RawErrorResponse>(&body) else {
            return AppleErrorCode::UnknownError(body);
        };
        match raw.error.as_str() {
            "invalid_request" => AppleErrorCode::InvalidRequest,
            "invalid_client" => AppleErrorCode::InvalidClient,
            "invalid_grant" => AppleErrorCode::InvalidGrant,
            "unauthorized_client" => AppleErrorCode::UnauthorizedClient,
            "unsupported_grant_type" => AppleErrorCode::UnsupportedGrantType,
            "invalid_scope" => AppleErrorCode::InvalidScope,
            _ => AppleErrorCode::UnknownError(body),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_all_documented_error_codes() {
        let cases = [
            ("invalid_request", AppleErrorCode::InvalidRequest),
            ("invalid_client", AppleErrorCode::InvalidClient),
            ("invalid_grant", AppleErrorCode::InvalidGrant),
            ("unauthorized_client", AppleErrorCode::UnauthorizedClient),
            (
                "unsupported_grant_type",
                AppleErrorCode::UnsupportedGrantType,
            ),
            ("invalid_scope", AppleErrorCode::InvalidScope),
        ];
        for (raw, expected) in cases {
            let body = format!(r#"{{"error":"{raw}"}}"#);
            assert_eq!(AppleErrorCode::from_response_body(body), expected);
        }
    }

    #[test]
    fn falls_back_to_unknown_for_unrecognized_code() {
        let body = r#"{"error":"some_future_code"}"#.to_string();
        assert_eq!(
            AppleErrorCode::from_response_body(body.clone()),
            AppleErrorCode::UnknownError(body)
        );
    }

    #[test]
    fn falls_back_to_unknown_for_malformed_body() {
        let body = "not json".to_string();
        assert_eq!(
            AppleErrorCode::from_response_body(body.clone()),
            AppleErrorCode::UnknownError(body)
        );
    }
}
