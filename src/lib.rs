// https://developer.apple.com/documentation/technotes/tn3194-handling-account-deletions-and-revoking-tokens-for-sign-in-with-apple
// https://developer.apple.com/documentation/signinwithapplerestapi/revoke-tokens
// https://developer.apple.com/support/offering-account-deletion-in-your-app/

use apple_signin::{AppleJwtClient, AppleJwtError};
use reqwest::Error as ReqwestError;
use thiserror::Error;

/// Identity extracted from a verified Apple identity token.
#[derive(Clone, Debug)]
pub struct AppleIdentity {
    /// Stable per-app-developer-team Apple user identifier (JWT `sub`).
    pub apple_user_id: String,
    /// Only reliably present on the user's first authorization.
    pub email: Option<String>,
}

/// Verifies Apple identity tokens for a set of app bundle ids.
#[derive(Clone)]
pub struct AppleAuthClient {
    apple_jwt: AppleJwtClient,
}

impl AppleAuthClient {
    pub fn new<T: ToString>(bundle_ids: &[T]) -> Self {
        Self {
            // TODO: there is a serious bug in AppleJwtClient regarding JWKS cache causing frequent trips to Apple
            // under heavy load. Either fix it or implement our own JWT checking (probably the latter but TBD)
            apple_jwt: AppleJwtClient::new(bundle_ids),
        }
    }

    /// Validate and decode an Apple identity JWT.
    pub async fn verify_identity_token(
        &self,
        identity_token: &str,
    ) -> Result<AppleIdentity, IdunnError> {
        let payload = self.apple_jwt.decode(identity_token).await?;
        Ok(AppleIdentity {
            apple_user_id: payload.user_id,
            email: payload.email,
        })
    }
}

/// Error verifying an Apple identity token.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum IdunnError {
    #[error("invalid Apple identity token: {0}")]
    InvalidToken(AppleJwtError),
    #[error("network error: {0}")]
    NetworkError(ReqwestError),
}

impl From<AppleJwtError> for IdunnError {
    fn from(value: AppleJwtError) -> Self {
        match value {
            AppleJwtError::HttpError(e) => Self::NetworkError(e),
            _ => Self::InvalidToken(value),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructs_client_with_bundle_ids() {
        let _client = AppleAuthClient::new(&["com.example.myapp"]);
    }
}
