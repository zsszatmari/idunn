use crate::identity_verification::AppleIdentity;
use crate::token_exchange::RefreshToken;
use std::time::Duration;
use thiserror::Error;

/// Error verifying an Apple identity token — returned by
/// `AppleAuthClient::verify_identity_token`, and embedded in
/// `CodeExchangeError::ExchangedTokenUnverified` when it's the `id_token` from a
/// token exchange that fails verification instead.
#[derive(Debug, Clone, Error)]
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

/// Why an Apple identity token was found to be invalid.
#[derive(Debug, Clone, Error)]
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

/// Why `AppleAuthClient::sign_up_or_log_in` rejected a sign-in *after* the
/// authorization code was already exchanged for a live refresh token, whose
/// owner (to idunn's best knowledge) is the caller's own Apple user; see
/// `SignInError::RejectedAfterExchange`. Carried twice: once in the
/// `PendingRevocation` handed to `schedule_revocation`, once in
/// `SignInError::RejectedAfterExchange`.
#[derive(Debug, Clone, Error)]
pub enum PostExchangeRejection {
    /// Apple's token endpoint exchanged the code, but the `id_token` it returned
    /// alongside failed verification.
    #[error("the id_token returned with the exchange failed verification")]
    TokenUnverified(#[source] VerificationError),
    /// The exchanged `id_token`'s nonce doesn't match the expected value.
    #[error("the exchanged id_token's nonce does not match the expected value")]
    NonceMismatch,
}

/// A live refresh token that `sign_up_or_log_in` rejected after the
/// exchange and handed to the host's `schedule_revocation` hook, awaiting
/// it before returning `SignInError::RejectedAfterExchange` — see
/// docs/architecture.md, "Why revocations are coordinated by the host,
/// through `AppleAccounts`", and "Why a post-exchange rejection goes
/// through `schedule_revocation`". idunn never revokes it itself. The
/// hook files it durably for later revocation, per docs/usage.md, "The
/// `AppleAccounts` contract", obligation 5.
#[derive(Debug)]
pub struct PendingRevocation {
    pub refresh_token: RefreshToken,
    /// Comes from the caller's *own* identity token, verified before the
    /// exchange — this is the key (`apple_user_id` is the JWT `sub`) the host
    /// files the pending revocation against. Under
    /// `PostExchangeRejection::NonceMismatch`, the exchanged `id_token`
    /// verified this same subject. Under `PostExchangeRejection::TokenUnverified`,
    /// the exchanged token's owner could not be verified at all — see
    /// docs/architecture.md for the residual risk this carries.
    pub identity: AppleIdentity,
    pub cause: PostExchangeRejection,
    /// How long the host must wait, at minimum, before actually revoking
    /// this token — gives a fast retry a chance to land in
    /// `AppleAccounts::lookup` and cancel this pending revocation first (see
    /// docs/usage.md, obligation 3). Fixed by idunn, not configurable;
    /// add it to your own clock when filing the job (e.g. `NOW() +
    /// grace_period` or your storage's equivalent).
    pub grace_period: Duration,
}

/// idunn's own reasons `AppleAuthClient::sign_up_or_log_in`/`sign_up_or_log_in_with_nonce`
/// failed. Those methods return the host's `AppleAccounts::Error`, which every
/// host builds from this through `From<SignInError>`; the host's own hook
/// failures (`AppleAccounts::lookup`, `nonce_checker`) never pass through here.
/// [`SignInError::kind`] says how to answer each one. See docs/architecture.md,
/// "Why sign-in returns the host's own error type".
#[derive(Debug, Error)]
pub enum SignInError {
    // --- BEFORE the exchange: nothing was spent at Apple, no token exists ---
    #[error(transparent)]
    IdentityTokenRejected(#[from] VerificationError),
    #[error("the identity token's nonce does not match the expected value")]
    NonceMismatch,
    #[error(transparent)]
    Exchange(#[from] TokenExchangeError),

    /// After token exchange it turned out that the exchanged `id_token` names a
    /// different Apple user than the caller's identity token — someone else's authorization
    /// code paired with this identity token, possibly a malicious client. That user's refresh
    /// token was discarded: revoking would end their whole authorization of this app. Nothing
    /// is left for the caller to do. See docs/architecture.md.
    #[error(
        "the exchanged id_token is for a different Apple user than the identity token; its refresh token was discarded"
    )]
    SubjectMismatch,
    /// Rejected after the exchange for a reason in `PostExchangeRejection`: the
    /// refresh token Apple issued is the caller's own and live, and idunn has
    /// already handed it to `schedule_revocation` (and awaited it) before
    /// returning this — nothing is left for the caller to do but answer the
    /// request. Unlike `SubjectMismatch`, whose token belongs to another Apple
    /// user and is discarded without ever calling the hook.
    #[error("sign-in rejected after the authorization code was exchanged: {0}")]
    RejectedAfterExchange(PostExchangeRejection),
}

/// How to answer a failed sign-in — see [`SignInError::kind`]. Plain, not
/// `#[non_exhaustive]`, like idunn's error enums: a new kind is a new decision
/// for the host (a new class of response), so it should fail to compile until
/// the host makes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignInErrorKind {
    /// The sign-in itself was refused: the identity token failed verification,
    /// a nonce or Apple user didn't match, or Apple rejected the authorization
    /// code (`invalid_grant`, `invalid_request`). Answer it as a failed login
    /// (e.g. HTTP 401); resending the same request won't help.
    Rejected,
    /// Apple, or its published key set, couldn't be reached or gave an answer
    /// idunn couldn't interpret — nothing is known to be wrong with the
    /// request. Transient: answer e.g. HTTP 503. Resending the same request
    /// only helps while the authorization code is unspent; once an exchange was
    /// attempted, the client needs a fresh Apple authorization. A host that
    /// maps only the kind can't tell which, so its client should restart.
    Unavailable,
    /// Apple refused this app's own credentials or client configuration
    /// (`invalid_client`, `unauthorized_client`, `unsupported_grant_type`,
    /// `invalid_scope`), or the client secret couldn't be signed. Neither the
    /// caller's fault nor transient: answer e.g. HTTP 500 and alert — retrying
    /// won't help until the configuration is fixed.
    Misconfigured,
}

impl SignInError {
    /// Classifies this failure for the host's response, the way
    /// `std::io::Error::kind` classifies OS errors. idunn classifies every
    /// variant, including ones a later version adds, so a host that maps
    /// `kind()` isn't broken by a new variant — only by a new
    /// `SignInErrorKind`. Match the variants themselves where you need finer
    /// detail (e.g. logging `SubjectMismatch` as a security event). See
    /// docs/architecture.md, "Why the error enums are exhaustive".
    pub fn kind(&self) -> SignInErrorKind {
        match self {
            SignInError::IdentityTokenRejected(err) => err.sign_in_kind(),
            SignInError::NonceMismatch | SignInError::SubjectMismatch => SignInErrorKind::Rejected,
            SignInError::Exchange(err) => err.sign_in_kind(),
            SignInError::RejectedAfterExchange(cause) => cause.sign_in_kind(),
        }
    }
}

// Sign-in classifications of the payloads `SignInError::kind` delegates to.
// Private and named for sign-in on purpose: the same `AppleErrorCode` means
// something else during revocation (`invalid_grant` is a success there). No
// wildcard arms: a variant added to any of these enums fails to compile here
// until it is classified.
impl VerificationError {
    fn sign_in_kind(&self) -> SignInErrorKind {
        match self {
            VerificationError::InvalidToken(_) => SignInErrorKind::Rejected,
            VerificationError::CannotVerifyToken => SignInErrorKind::Unavailable,
        }
    }
}

impl AppleErrorCode {
    fn sign_in_kind(&self) -> SignInErrorKind {
        match self {
            AppleErrorCode::InvalidRequest | AppleErrorCode::InvalidGrant => {
                SignInErrorKind::Rejected
            }
            AppleErrorCode::InvalidClient
            | AppleErrorCode::UnauthorizedClient
            | AppleErrorCode::UnsupportedGrantType
            | AppleErrorCode::InvalidScope => SignInErrorKind::Misconfigured,
            // idunn doesn't see the HTTP status: an unparseable 5xx body lands here.
            AppleErrorCode::UnknownError(_) => SignInErrorKind::Unavailable,
        }
    }
}

impl TokenExchangeError {
    fn sign_in_kind(&self) -> SignInErrorKind {
        match self {
            TokenExchangeError::NetworkError(_) | TokenExchangeError::InvalidTokenResponse(_) => {
                SignInErrorKind::Unavailable
            }
            TokenExchangeError::ClientSecretSigningFailed(_) => SignInErrorKind::Misconfigured,
            TokenExchangeError::TokenExchangeFailed(code) => code.sign_in_kind(),
        }
    }
}

impl PostExchangeRejection {
    fn sign_in_kind(&self) -> SignInErrorKind {
        match self {
            PostExchangeRejection::TokenUnverified(err) => err.sign_in_kind(),
            PostExchangeRejection::NonceMismatch => SignInErrorKind::Rejected,
        }
    }
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

    /// Every `AppleErrorCode`, with how a sign-in that hit it at the token
    /// endpoint is classified. Shared by the two tests below.
    fn apple_error_code_kinds() -> [(AppleErrorCode, SignInErrorKind); 7] {
        [
            (AppleErrorCode::InvalidRequest, SignInErrorKind::Rejected),
            (AppleErrorCode::InvalidGrant, SignInErrorKind::Rejected),
            (
                AppleErrorCode::InvalidClient,
                SignInErrorKind::Misconfigured,
            ),
            (
                AppleErrorCode::UnauthorizedClient,
                SignInErrorKind::Misconfigured,
            ),
            (
                AppleErrorCode::UnsupportedGrantType,
                SignInErrorKind::Misconfigured,
            ),
            (AppleErrorCode::InvalidScope, SignInErrorKind::Misconfigured),
            (
                AppleErrorCode::UnknownError("<html>502</html>".to_string()),
                SignInErrorKind::Unavailable,
            ),
        ]
    }

    #[test]
    fn apple_error_codes_classify_for_sign_in() {
        for (code, expected) in apple_error_code_kinds() {
            assert_eq!(code.sign_in_kind(), expected, "{code:?}");
        }
    }

    /// One row per leaf failure `sign_up_or_log_in` can produce. The
    /// wildcard-free `match` makes a new `SignInError` variant fail to compile
    /// here, and `covered` makes a variant without a row fail at runtime.
    #[test]
    fn sign_in_error_kind_classifies_every_variant() {
        let invalid = || VerificationError::InvalidToken(InvalidTokenCause::MissingNonce);
        let signing_failure = || {
            ClientSecretError::from(
                jsonwebtoken::EncodingKey::from_ec_pem(b"not a key")
                    .expect_err("a malformed PEM is rejected"),
            )
        };
        let mut cases = vec![
            (
                SignInError::IdentityTokenRejected(invalid()),
                SignInErrorKind::Rejected,
            ),
            (
                SignInError::IdentityTokenRejected(VerificationError::CannotVerifyToken),
                SignInErrorKind::Unavailable,
            ),
            (SignInError::NonceMismatch, SignInErrorKind::Rejected),
            (
                SignInError::Exchange(TokenExchangeError::NetworkError(Box::new(
                    std::io::Error::other("connection refused"),
                ))),
                SignInErrorKind::Unavailable,
            ),
            (
                SignInError::Exchange(TokenExchangeError::ClientSecretSigningFailed(
                    signing_failure(),
                )),
                SignInErrorKind::Misconfigured,
            ),
            (
                SignInError::Exchange(TokenExchangeError::InvalidTokenResponse(
                    serde_json::from_str::<serde_json::Value>("not json").unwrap_err(),
                )),
                SignInErrorKind::Unavailable,
            ),
            (SignInError::SubjectMismatch, SignInErrorKind::Rejected),
            (
                SignInError::RejectedAfterExchange(PostExchangeRejection::NonceMismatch),
                SignInErrorKind::Rejected,
            ),
            (
                SignInError::RejectedAfterExchange(PostExchangeRejection::TokenUnverified(
                    invalid(),
                )),
                SignInErrorKind::Rejected,
            ),
            (
                SignInError::RejectedAfterExchange(PostExchangeRejection::TokenUnverified(
                    VerificationError::CannotVerifyToken,
                )),
                SignInErrorKind::Unavailable,
            ),
        ];
        cases.extend(apple_error_code_kinds().into_iter().map(|(code, kind)| {
            (
                SignInError::Exchange(TokenExchangeError::TokenExchangeFailed(code)),
                kind,
            )
        }));
        let mut covered = [false; 5];
        for (err, expected) in cases {
            covered[match &err {
                SignInError::IdentityTokenRejected(_) => 0,
                SignInError::NonceMismatch => 1,
                SignInError::Exchange(_) => 2,
                SignInError::SubjectMismatch => 3,
                SignInError::RejectedAfterExchange(_) => 4,
            }] = true;
            assert_eq!(err.kind(), expected, "{err:?}");
        }
        assert!(
            covered.iter().all(|&c| c),
            "every SignInError variant needs a row"
        );
    }
}
