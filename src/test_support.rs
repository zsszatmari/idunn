use crate::token::AppleTokenConfig;

pub(crate) const TEST_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQggeco4/EEIM9ovqMW\n\
csOfc9dl5tGk8LndzgU4CVvEqLihRANCAAQNSRZdtAsSZG8pTuLiK7JdLUog/M7I\n\
zqbgw/e2HmOOuotg2tZP7JoBgnu7rNEplIygqTjYf8pKesYPyHrOj5ae\n\
-----END PRIVATE KEY-----\n";

pub(crate) fn test_token_config() -> AppleTokenConfig {
    AppleTokenConfig {
        team_id: "TEAM123456".to_string(),
        key_id: "KEY7890".to_string(),
        client_id: "com.example.myapp".to_string(),
        private_key_pem: TEST_PRIVATE_KEY_PEM.as_bytes().to_vec(),
    }
}
