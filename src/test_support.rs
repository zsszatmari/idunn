use crate::token_exchange::AppleTokenConfig;
use crate::transport::TransportError;
use serde_json::json;

pub(crate) const TEST_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQggeco4/EEIM9ovqMW\n\
csOfc9dl5tGk8LndzgU4CVvEqLihRANCAAQNSRZdtAsSZG8pTuLiK7JdLUog/M7I\n\
zqbgw/e2HmOOuotg2tZP7JoBgnu7rNEplIygqTjYf8pKesYPyHrOj5ae\n\
-----END PRIVATE KEY-----\n";

/// EC public half matching `TEST_PRIVATE_KEY_PEM`, for tests that need to verify
/// a client secret idunn signed rather than just producing one.
pub(crate) const TEST_PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEDUkWXbQLEmRvKU7i4iuyXS1KIPzO\n\
yM6m4MP3th5jjrqLYNrWT+yaAYJ7u6zRKZSMoKk42H/KSnrGD8h6zo+Wng==\n\
-----END PUBLIC KEY-----\n";

pub(crate) const TEST_KID: &str = "test-kid-1";

// 2048-bit RSA test key, generated with:
//   openssl genrsa -out rsa_private.pem 2048
//   openssl rsa -in rsa_private.pem -pubout -out rsa_public.pem
pub(crate) const TEST_RSA_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCzW0FgfS0/RLD5\n\
jf4KFqBqRG9oFunfzcbIa+h2GwpLRNtuTsBZ7N65lMqc9s7rbYVyQmD44N8oeV2s\n\
peoA92Q8iWUxOfnXhPYGfe5JmRvj9rQy0zV6uOgGilCEhrujVrTjo00USPEENv4s\n\
grQlFtzJTlQSfifNy7C2hPOTAFsU5G1zWsRQjQSXuLMIxn6cw6Nakv74V6PH4HX+\n\
FE4CbwhpDCOjAyOi2HWdc8cdvd/cncNWD4Ey9/PCGZSqmO7zaozaMW5r8csYElT6\n\
byF79XtZfoMkzvDHctHlSuBKl7kRRXBXyioPe9QY1cWk89ecLRcMXBLIB559hklh\n\
OmV/8f6lAgMBAAECggEABAkYBTuudoeNONbm9036MYc/1MvRMCcxOLtkKVt4kD1+\n\
Ih2qVSD6g5qeCB6YhMe70oM9AH86Hi8Zj7koSk8cBa2sux5mvqCVUuDnU+dv7yGS\n\
/TgZ3QdHNzXKU9UJPfFalBWi9hjMYs/O88GZcTfcuLh8X/HP46Dt5V7D8T6MjhbU\n\
8trkbc5CwabJFes4rIUKqVruwNmKcazliCiQoyZj1K1uBrec4jffflND01JVb5zQ\n\
L8tRF4NCjQ/9GrIxHu5+Fsikq7pP5+IVWydOwoPA/40ygRqTxvzJ82iJNfdnOlag\n\
b480u7VG70kdblUEnhvJi0DOFrhjecvC/20CW8gG2QKBgQD0SSgxZK5v+2zSPq84\n\
8xOq6O1jFZaaqJFPYNjAEoKTGAd29nOy6Q5Ux9gch/VwmzCTidZP0jKHbmmdLwZN\n\
s3EKOps745o6DqXTcOvoW6pBSvWjiUmTeq0Zb8r4omJ7yM2Tqwp706zvz9RsmINw\n\
30xIhbEdF0iY2+NGQgTq2VmtCQKBgQC79QdW63Xa3WRqvmB9ZIZf0RJexR4CgIsG\n\
Mp7K6KRQGD8aDP12KnXRsUO8idz2Y9vlmtwztTp7Y6q6wpIRieIZNajlqTNNeCFH\n\
D/VT6+8gFAb5zI0YoGWNXq/X8fFajVCQgDGPbtyYsmB9tB/p5DPWX/NPPS9QBPx/\n\
7aDHD3IHvQKBgHZydnOkrtQLZBN5Y3rImhO3x0rQ7+pjq7mCavaOwxNRhmUPUMBC\n\
Mrm3ALmszrxf8yjGn8yqTefPCJS3dWX9iOT9z8E1NdXKvmsMiMZsk9v+3aYC7lL9\n\
G6uGwjLWgcwlbFCakYXC+Ep7SjOxq6HyE8niUSOa44+CpuutHTdGVi4JAoGAaYPR\n\
vfrrK5XzxHThiCNByFJ/ZJJ2GWN+KFmMiU52x7wE2KQIOij2AWTpKNOgJvXCQbBh\n\
A+ouTYyTEMsf4xarxgk4qs0Ezu2siM8toxIlKLX1gJBTeUq6F9XbE3hwTKxeWPCO\n\
Yf4TeulQf+D5tXz1mNg+p/IqOFrEQTDufDFwi2UCgYB2wC8/D9YaXEpnX/nijxQQ\n\
AUm1esB28MjlUKNVFNPUPURKidj8yBL4wCYHtpCOc/NLXMfSslvlzpLBudVXQw45\n\
OSlzHzXYZcB3sMIch0Ej52sytNrzhtx2aJjyF9wO7QcCPFQoRoRCYNO38DP2X44B\n\
Q3WUtrCR4GerrtHhOp4Tdg==\n\
-----END PRIVATE KEY-----\n";
// Matching public key's RSA modulus/exponent, base64url-encoded (JWK `n`/`e`).
const TEST_RSA_N: &str = "s1tBYH0tP0Sw-Y3-ChagakRvaBbp383GyGvodhsKS0Tbbk7AWezeuZTKnPbO622FckJg-ODfKHldrKXqAPdkPIllMTn514T2Bn3uSZkb4_a0MtM1erjoBopQhIa7o1a046NNFEjxBDb-LIK0JRbcyU5UEn4nzcuwtoTzkwBbFORtc1rEUI0El7izCMZ-nMOjWpL--Fejx-B1_hROAm8IaQwjowMjoth1nXPHHb3f3J3DVg-BMvfzwhmUqpju82qM2jFua_HLGBJU-m8he_V7WX6DJM7wx3LR5UrgSpe5EUVwV8oqD3vUGNXFpPPXnC0XDFwSyAeefYZJYTplf_H-pQ";
const TEST_RSA_E: &str = "AQAB";

/// Well-formed JWKS body containing a single RSA key under `kid`, matching
/// `TEST_RSA_PRIVATE_KEY_PEM` — for serving to code under test that fetches
/// Apple's key set to verify a token signed with that key.
pub(crate) fn jwks_body_including(kid: &str) -> String {
    json!({
        "keys": [{
            "kty": "RSA",
            "kid": kid,
            "alg": "RS256",
            "use": "sig",
            "n": TEST_RSA_N,
            "e": TEST_RSA_E
        }]
    })
    .to_string()
}

pub(crate) fn test_token_config() -> AppleTokenConfig {
    AppleTokenConfig {
        team_id: "TEAM123456".to_string(),
        key_id: "KEY7890".to_string(),
        client_id: "com.example.myapp".to_string(),
        private_key_pem: TEST_PRIVATE_KEY_PEM.as_bytes().to_vec(),
    }
}

/// A `TransportError` standing in for Apple being unreachable (connection
/// refused, timeout, DNS failure, ...) — the exact underlying error never
/// matters to the code under test, only that it's the `Network` variant.
pub(crate) fn network_error() -> TransportError {
    TransportError::Network(Box::new(std::io::Error::new(
        std::io::ErrorKind::ConnectionRefused,
        "connection refused",
    )))
}
