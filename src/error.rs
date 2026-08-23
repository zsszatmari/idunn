use apple_signin::AppleJwtError;
use thiserror::Error;

/// Error verifying an Apple identity token or exchanging an authorization code.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum IdunnError {
    #[error("invalid Apple identity token: {0}")]
    InvalidToken(AppleJwtError),
    #[error("network error: {0}")]
    NetworkError(Box<dyn std::error::Error + Send + Sync>),
    #[error("invalid Apple private key: {0}")]
    InvalidPrivateKey(jsonwebtoken::errors::Error),
    #[error("failed to sign client secret: {0}")]
    ClientSecretSigningFailed(jsonwebtoken::errors::Error),
    #[error("Apple token endpoint returned an error: {0}")]
    TokenExchangeFailed(String),
    #[error("could not parse Apple token response: {0}")]
    InvalidTokenResponse(serde_json::Error),
}

impl From<AppleJwtError> for IdunnError {
    fn from(value: AppleJwtError) -> Self {
        match value {
            AppleJwtError::HttpError(e) => Self::NetworkError(Box::new(e)),
            _ => Self::InvalidToken(value),
        }
    }
}
