// https://developer.apple.com/documentation/technotes/tn3194-handling-account-deletions-and-revoking-tokens-for-sign-in-with-apple
// https://developer.apple.com/documentation/signinwithapplerestapi/revoke-tokens
// https://developer.apple.com/support/offering-account-deletion-in-your-app/

mod error;
mod identity_verification;
mod jwks_store;
#[cfg(test)]
mod test_support;
mod token_exchange;
mod transport;

pub use error::{IdunnError, InvalidTokenCause};
pub use identity_verification::{AppleIdentity, IdentityVerificationConfig, NoncePolicy};
pub use token_exchange::{AppleTokenConfig, AppleTokenResponse};
use jwks_store::JwksStoreConfig;
use transport::HttpTransport;

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
pub struct AppleAuthClient<T: HttpTransport = transport::ReqwestTransport> {
    identity_verification: identity_verification::IdentityVerificationClient<T>,
    token_config: AppleTokenConfig,
    signing_key: EncodingKey,
    transport: T,
}

impl AppleAuthClient<transport::ReqwestTransport> {
    pub fn new<S: AsRef<str>>(
        bundle_ids: &[S],
        token_config: AppleTokenConfig,
    ) -> Result<Self, IdunnError> {
        Self::with_transport(
            bundle_ids,
            token_config,
            transport::ReqwestTransport::default(),
            JwksStoreConfig::default(),
            IdentityVerificationConfig::default(),
        )
    }
}

impl<T: HttpTransport> AppleAuthClient<T> {
    pub fn with_transport<S: AsRef<str>>(
        bundle_ids: &[S],
        token_config: AppleTokenConfig,
        transport: T,
        jwks_config: JwksStoreConfig,
        identity_verification_config: IdentityVerificationConfig,
    ) -> Result<Self, IdunnError> {
        let signing_key = EncodingKey::from_ec_pem(&token_config.private_key_pem)
            .map_err(IdunnError::InvalidPrivateKey)?;
        let identity_verification = identity_verification::IdentityVerificationClient::new(
            bundle_ids,
            transport.clone(),
            jwks_config,
            identity_verification_config,
        );
        Ok(Self {
            identity_verification,
            token_config,
            signing_key,
            transport,
        })
    }

    pub async fn refresh_keystore(&self) -> Result<(), IdunnError> {
        self.identity_verification.refresh_keystore().await;
        Ok(())
    }

    /// Validate and decode an Apple identity JWT.
    pub async fn verify_identity_token(
        &self,
        identity_token: &str,
    ) -> Result<AppleIdentity, IdunnError> {
        self.identity_verification
            .verify_identity_token(identity_token)
            .await
    }

    /// Exchange an authorization code (from `ASAuthorizationAppleIDCredential`)
    /// for Apple's access/refresh/id tokens.
    pub async fn exchange_authorization_code(
        &self,
        authorization_code: &str,
    ) -> Result<AppleTokenResponse, IdunnError> {
        token_exchange::exchange_authorization_code(
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
