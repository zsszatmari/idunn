//! Compiles only while idunn's public error enums, and `ErrorKind`, are
//! exhaustive: a `#[non_exhaustive]` enum would force a wildcard arm on this
//! crate-external code. See docs/architecture.md, "Why the error enums are
//! exhaustive".

use idunn::{
    AppleErrorCode, CodeExchangeError, ErrorKind, InvalidTokenCause, PostExchangeRejection,
    SignInError, TokenExchangeError, TokenRevocationError, VerificationError,
};

#[test]
fn error_enums_can_be_matched_without_a_wildcard() {
    let _: fn(&VerificationError) = |e| match e {
        VerificationError::InvalidToken(_) | VerificationError::CannotVerifyToken => {}
    };
    let _: fn(&InvalidTokenCause) = |e| match e {
        InvalidTokenCause::InvalidKeyId { .. }
        | InvalidTokenCause::Rejected(_)
        | InvalidTokenCause::AlgorithmMismatch(_)
        | InvalidTokenCause::MissingNonce => {}
    };
    let _: fn(&AppleErrorCode) = |e| match e {
        AppleErrorCode::InvalidRequest
        | AppleErrorCode::InvalidClient
        | AppleErrorCode::InvalidGrant
        | AppleErrorCode::UnauthorizedClient
        | AppleErrorCode::UnsupportedGrantType
        | AppleErrorCode::InvalidScope
        | AppleErrorCode::UnknownError(_) => {}
    };
    let _: fn(&TokenExchangeError) = |e| match e {
        TokenExchangeError::NetworkError(_)
        | TokenExchangeError::ClientSecretSigningFailed(_)
        | TokenExchangeError::TokenExchangeFailed(_)
        | TokenExchangeError::InvalidTokenResponse(_) => {}
    };
    let _: fn(&TokenRevocationError) = |e| match e {
        TokenRevocationError::NetworkError(_)
        | TokenRevocationError::ClientSecretSigningFailed(_)
        | TokenRevocationError::TokenRevocationFailed(_) => {}
    };
    let _: fn(&CodeExchangeError) = |e| match e {
        CodeExchangeError::Exchange(_) | CodeExchangeError::ExchangedTokenUnverified { .. } => {}
    };
    let _: fn(&PostExchangeRejection) = |e| match e {
        PostExchangeRejection::TokenUnverified(_) | PostExchangeRejection::NonceMismatch => {}
    };
    let _: fn(&SignInError) = |e| match e {
        SignInError::IdentityTokenRejected(_)
        | SignInError::NonceMismatch
        | SignInError::Exchange(_)
        | SignInError::SubjectMismatch
        | SignInError::RejectedAfterExchange(_) => {}
    };
    let _: fn(ErrorKind) = |kind| match kind {
        ErrorKind::Rejected | ErrorKind::Unavailable | ErrorKind::Misconfigured => {}
    };
}
