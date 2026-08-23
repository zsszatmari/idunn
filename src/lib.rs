// https://developer.apple.com/documentation/technotes/tn3194-handling-account-deletions-and-revoking-tokens-for-sign-in-with-apple
// https://developer.apple.com/documentation/signinwithapplerestapi/revoke-tokens
// https://developer.apple.com/support/offering-account-deletion-in-your-app/

mod error;
mod identity;
#[cfg(test)]
mod test_support;
mod token;

pub use error::IdunnError;
pub use identity::AppleIdentity;
pub use token::{
    AppleTokenConfig, AppleTokenResponse, HttpTransport, ReqwestTransport, TransportError,
};

use apple_signin::AppleJwtClient;
use jsonwebtoken::EncodingKey;

///Verifies Apple identity tokens and exchanges authorization codes for refresh
/// tokens, for a set of app bundle ids.
///
/// One client with one constructor, covering both identity verification and token
/// exchange even though they touch mostly-disjoint code (see `identity.rs` /
/// `token.rs`): see docs/architecture.md for why they're bundled together.
///
/// TODO: think about whether Clone is needed, how is the API cleaner and less error-prone
/// but keep in mind that there might be inner state going on, for example in-flight key
/// refreshes
//#[derive(Clone)]
pub struct AppleAuthClient<T: HttpTransport = ReqwestTransport> {
    apple_jwt: AppleJwtClient,
    token_config: AppleTokenConfig,
    signing_key: EncodingKey,
    transport: T,
}

impl AppleAuthClient<ReqwestTransport> {
    pub fn new<S: AsRef<str>>(
        bundle_ids: &[S],
        token_config: AppleTokenConfig,
    ) -> Result<Self, IdunnError> {
        Self::with_transport(bundle_ids, token_config, ReqwestTransport::default())
    }
}

impl<T: HttpTransport> AppleAuthClient<T> {
    pub fn with_transport<S: AsRef<str>>(
        bundle_ids: &[S],
        token_config: AppleTokenConfig,
        transport: T,
    ) -> Result<Self, IdunnError> {
        let signing_key = EncodingKey::from_ec_pem(&token_config.private_key_pem)
            .map_err(IdunnError::InvalidPrivateKey)?;
        let bundle_ids: Vec<String> = bundle_ids
            .iter()
            .map(|id| id.as_ref().to_string())
            .collect();
        Ok(Self {
            // TODO: there is a serious bug in AppleJwtClient regarding JWKS cache causing frequent trips to Apple
            // under heavy load. Either fix it or implement our own JWT checking (probably the latter but TBD)
            apple_jwt: AppleJwtClient::new(&bundle_ids),
            token_config,
            signing_key,
            transport,
        })
    }

    /// Exchange an authorization code (from `ASAuthorizationAppleIDCredential`)
    /// for Apple's access/refresh/id tokens.
    pub async fn exchange_authorization_code(
        &self,
        authorization_code: &str,
    ) -> Result<AppleTokenResponse, IdunnError> {
        token::exchange_authorization_code(
            &self.transport,
            &self.token_config,
            &self.signing_key,
            authorization_code,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::test_token_config;

    #[test]
    fn constructs_client_with_bundle_ids_and_token_config() {
        let _client = AppleAuthClient::new(&["com.example.myapp"], test_token_config())
            .expect("valid test key should construct client");
    }

    #[test]
    fn rejects_malformed_private_key() {
        let mut config = test_token_config();
        config.private_key_pem = b"not a key".to_vec();

        let result = AppleAuthClient::new(&["com.example.myapp"], config);

        assert!(matches!(result, Err(IdunnError::InvalidPrivateKey(_))));
    }
}
