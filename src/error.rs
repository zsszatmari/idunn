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
    TokenExchangeFailed(String),
    #[error("could not parse Apple token response: {0}")]
    InvalidTokenResponse(serde_json::Error),
}

/// Why an Apple identity token was found to be invalid. Only the causes this
/// crate currently detects are listed; more (issuer mismatch, expiry, bad
/// signature, ...) will be added as identity verification is completed.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum InvalidTokenCause {
    /// The token's `kid` isn't in Apple's currently published (successfully
    /// fetched, fresh) key set.
    #[error("key id {kid:?} not found in Apple's published key set")]
    InvalidKeyId { kid: String },
}
