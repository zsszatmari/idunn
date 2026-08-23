use crate::error::IdunnError;
use crate::token::HttpTransport;
use crate::AppleAuthClient;

/// Identity extracted from a verified Apple identity token.
#[derive(Clone, Debug)]
pub struct AppleIdentity {
    /// Stable per-app-developer-team Apple user identifier (JWT `sub`).
    pub apple_user_id: String,
    /// Only reliably present on the user's first authorization.
    pub email: Option<String>,
}

impl<T: HttpTransport> AppleAuthClient<T> {
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
