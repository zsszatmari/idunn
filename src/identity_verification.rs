use crate::AppleAuthClient;
use crate::error::IdunnError;
use crate::transport::HttpTransport;
use jsonwebtoken::Validation;

/// Identity extracted from a verified Apple identity token.
#[derive(Clone, Debug)]
pub struct AppleIdentity {
    /// Stable per-app-developer-team Apple user identifier (JWT `sub`).
    pub apple_user_id: String,
    /// Only reliably present on the user's first authorization.
    pub email: Option<String>,
}

struct IdentityVerificationClient;

impl<T: HttpTransport> AppleAuthClient<T> {
    /// Validate and decode an Apple identity JWT.
    pub async fn verify_identity_token(
        &self,
        identity_token: &str,
    ) -> Result<AppleIdentity, IdunnError> {
        // https://www.jwt.io/introduction
        let decoded_header =
            jsonwebtoken::decode_header(identity_token).map_err(|_| IdunnError::InvalidToken)?;
        if decoded_header.alg != jsonwebtoken::Algorithm::RS256 {
            return Err(IdunnError::InvalidToken);
        }
        let key_id = decoded_header.kid.ok_or_else(|| IdunnError::InvalidToken)?;
        // TODO: talan az lenne a legjobb ha a nonce ellenorzesre egy nonce_verifier closure -t varnank?
        // es akkor nehezebb figyelmen kivul hagyni

        let decoded = jsonwebtoken::decode(identity_token, &self.signing_key, validation)
            .map_err(|_| IdunnError::InvalidToken)?;
        let payload = self.apple_jwt.decode(identity_token).await?;
        Ok(AppleIdentity {
            apple_user_id: payload.user_id,
            email: payload.email,
        })
    }
}

impl IdentityVerificationClient {
    fn new<S: AsRef<str>>(bundle_ids: &[S]) -> Self {
        let validation = Validation::new(jsonwebtoken::Algorithm::ES256);
        validation.set_issuer("https://appleid.apple.com");

        // https://developer.apple.com/documentation/signinwithapple/verifying-a-user
        //
        // steps needed to validate the identity token:
        // "To verify the identity token, your app server must:
        // 1. Verify the JWS E256 signature using the server’s public key
        // 2. Verify the nonce for the authentication
        // 3. Verify that the iss field contains https://appleid.apple.com
        // 4. Verify that the aud field is the developer’s client_id
        // 5. Verify that the time is earlier than the exp value of the" token
        Self {}
    }
}
