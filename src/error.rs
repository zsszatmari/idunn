use crate::identity_verification::AppleIdentity;
use crate::token_exchange::RefreshToken;
use thiserror::Error;

/// Error verifying an Apple identity token — returned by
/// `AppleAuthClient::verify_identity_token`, and embedded in
/// `CodeExchangeError::ExchangedTokenUnverified` when it's the `id_token` from a
/// token exchange that fails verification instead.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum VerificationError {
    /// The token is confirmed invalid — see `cause` for specifics.
    #[error("invalid Apple identity token: {0}")]
    InvalidToken(InvalidTokenCause),
    /// The token's validity could not be determined (e.g. Apple's key set
    /// couldn't be fetched or is being backed off after a recent failure).
    /// Distinct from `InvalidToken`: this is not a claim that the token is bad,
    /// only that verification couldn't be completed right now.
    #[error("could not verify Apple identity token: key set is unavailable")]
    CannotVerifyToken,
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
    /// Header declares an algorithm other than the RS256 Apple actually uses. Possibly an attack.
    #[error("Apple identity token uses algorithm {0:?} instead of the expected RS256")]
    AlgorithmMismatch(jsonwebtoken::Algorithm),
    /// The token has no `nonce` claim, and the configured `NoncePolicy`
    /// requires one — either because the policy is `Strict` (a nonce is
    /// required unconditionally), or because it's `Permissive` and the
    /// token's `nonce_supported` claim was `true`.
    #[error(
        "Apple identity token carries no nonce claim, which the configured nonce policy requires"
    )]
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
    /// isn't one of Apple's documented codes. Carries the raw response body, but does not log it
    /// to avoid leaking sensitive info
    #[error("unrecognized Apple error response.")]
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

/// The configured Apple private key (`AppleTokenConfig::private_key_pem`)
/// couldn't be parsed as a PEM-encoded EC key — returned by
/// `AppleAuthClient::new`/`with_transport`.
#[derive(Debug, Error)]
#[error("invalid Apple private key: {0}")]
pub struct InvalidPrivateKeyError(#[from] pub(crate) jsonwebtoken::errors::Error);

/// Signing the client secret sent with every token-exchange/revoke request
/// failed. In practice this should be unreachable — the private key is
/// already validated once at `AppleAuthClient::new`/`with_transport` — but
/// `jsonwebtoken::encode` is itself fallible, so this stays a real error
/// rather than a `panic!`/`unwrap()`.
#[derive(Debug, Error)]
#[error("failed to sign client secret: {0}")]
pub struct ClientSecretError(#[from] jsonwebtoken::errors::Error);

/// Error from `AppleAuthClient::exchange_authorization_code`'s call to
/// Apple's token endpoint — the exchange itself; a verification failure of
/// the resulting `id_token` is `CodeExchangeError::ExchangedTokenUnverified`
/// instead.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum TokenExchangeError {
    #[error("network error: {0}")]
    NetworkError(Box<dyn std::error::Error + Send + Sync>),
    #[error(transparent)]
    ClientSecretSigningFailed(#[from] ClientSecretError),
    #[error("Apple token endpoint returned an error: {0}")]
    TokenExchangeFailed(AppleErrorCode),
    #[error("could not parse Apple token response: {0}")]
    InvalidTokenResponse(serde_json::Error),
}

/// Error from `AppleAuthClient::revoke_refresh_token`.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum TokenRevocationError {
    #[error("network error: {0}")]
    NetworkError(Box<dyn std::error::Error + Send + Sync>),
    #[error(transparent)]
    ClientSecretSigningFailed(#[from] ClientSecretError),
    #[error("Apple revoke endpoint returned an error: {0}")]
    TokenRevocationFailed(AppleErrorCode),
}

/// Error from `AppleAuthClient::exchange_authorization_code`.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum CodeExchangeError {
    #[error(transparent)]
    Exchange(#[from] TokenExchangeError),
    /// The authorization code was exchanged successfully, but the `id_token`
    /// Apple returned with it failed verification.
    ///
    /// Carries `refresh_token` because the code has already been consumed and
    /// the token is live at Apple: the caller must revoke it with
    /// `AppleAuthClient::revoke_refresh_token`, ideally retrying later on failure until
    /// the revocation succeeds. Dropping this error without doing so leaves a
    /// live token that can't revoked in a nice way.
    #[error("authorization code exchanged, but its identity token failed verification")]
    ExchangedTokenUnverified {
        refresh_token: RefreshToken,
        #[source]
        cause: VerificationError,
    },
}

/// Why `AppleAuthClient::sign_in` rejected a sign-in *after* the authorization
/// code was already exchanged for a live refresh token — see
/// `SignInError::RejectedAfterExchange`/`RevocationRequired`.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum PostExchangeRejection {
    /// Apple's token endpoint exchanged the code, but the `id_token` it returned
    /// alongside failed verification.
    #[error("the id_token returned with the exchange failed verification")]
    TokenUnverified(#[source] VerificationError),
    /// The exchanged `id_token`'s nonce doesn't match the expected value.
    #[error("the exchanged id_token's nonce does not match the expected value")]
    NonceMismatch,
    /// The exchanged `id_token` is for a different Apple user than the caller's
    /// identity token — someone else's identity token paired with the caller's
    /// own authorization code.
    #[error("the exchanged id_token is for a different Apple user than the identity token")]
    SubjectMismatch,
}

/// A refresh token Apple issued that `sign_in` could not revoke — the caller
/// must retry [`super::AppleAuthClient::revoke_refresh_token`] with it until it
/// succeeds (TN3194). Carried by `SignInError::RevocationRequired`; a caller
/// that cannot revoke immediately stores this to file the pending revocation
/// against the sign-in attempt that produced it.
#[derive(Debug, Error)]
#[error(
    "sign-in rejected after the authorization code was exchanged, and revoking the refresh token failed — the caller must retry the revocation"
)]
pub struct PendingRevocation {
    pub refresh_token: RefreshToken,
    /// Comes from the caller's *own* identity token, verified before the
    /// exchange, and is carried so a retry that outlives the original call can
    /// be filed against the sign-in attempt that produced it (`apple_user_id`
    /// is the JWT `sub`). Note it names the user who attempted the sign-in,
    /// not necessarily the one Apple considers the token's owner: under
    /// `PostExchangeRejection::SubjectMismatch` the exchanged `id_token` named
    /// a different user, which is precisely why the sign-in was rejected.
    pub identity: AppleIdentity,
    pub cause: PostExchangeRejection,
    #[source]
    pub revocation_error: TokenRevocationError,
}

/// Error from `AppleAuthClient::sign_in`/`sign_in_with_nonce`.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum SignInError {
    // --- BEFORE the exchange: nothing was spent at Apple, no token exists ---
    #[error(transparent)]
    IdentityTokenRejected(#[from] VerificationError),
    #[error("the identity token's nonce does not match the expected value")]
    NonceMismatch,
    /// The nonce check itself could not be completed (e.g. the caller's session
    /// lookup failed). This does *not* mean the nonce was wrong.
    #[error("the nonce check could not be completed: {0}")]
    NonceCheckFailed(Box<dyn std::error::Error + Send + Sync>),
    #[error(transparent)]
    Exchange(#[from] TokenExchangeError),

    // --- AFTER the exchange: a live refresh token existed ---
    /// Rejected after the exchange, but the refresh token Apple issued was
    /// successfully revoked: nothing is left for the caller to do.
    #[error(
        "sign-in rejected after the authorization code was exchanged; the refresh token was revoked"
    )]
    RejectedAfterExchange {
        #[source]
        cause: PostExchangeRejection,
    },
    /// Rejected after the exchange, **and the revocation also failed**: the
    /// refresh token stays live at Apple. See [`PendingRevocation`] for the
    /// retry obligation this carries.
    #[error(transparent)]
    RevocationRequired(Box<PendingRevocation>),
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
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
