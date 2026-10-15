//! Compiles the example in README.md. Rustdoc does not test it: the README
//! carries no hidden `#` lines, which GitHub and crates.io would show
//! verbatim. The test fails when the README's first `rust` block and the copy
//! below differ, so edit both together. See docs/maintaining.md, "Why the
//! README is the crate root documentation".

const START: &str = "// README example: start";
const END: &str = "// README example: end";

#[allow(
    unused_variables,
    reason = "the README match arms bind fields their comments say what to do with"
)]
#[rustfmt::skip]
async fn readme_example(
    identity_token: String,
    authorization_code: String,
    expected_nonce: String,
    stored_refresh_token: String,
) -> Result<(), Box<dyn std::error::Error>> {
    struct MyAccounts;

    impl MyAccounts {
        async fn lookup_account(&self, _apple_user_id: &str) -> Result<AccountState, MyError> {
            todo!()
        }

        async fn file_revocation(&self, _pending: PendingRevocation) {
            todo!()
        }
    }

    #[derive(Debug, thiserror::Error)]
    enum MyError {
        #[error("unauthorized")]
        Unauthorized,
        #[error("unavailable")]
        Unavailable,
        #[error("internal")]
        Internal,
    }

    let accounts = MyAccounts;

    // README example: start
    use idunn::{
        AccountState, AppleAccounts, AppleAuthClient, AppleIdentity, AppleTokenConfig, ErrorKind,
        PendingRevocation, SignInError, SignInOutcome,
    };

    // Once, at startup. Clones are cheap and share the JWKS cache.
    let apple = AppleAuthClient::new(AppleTokenConfig {
        team_id: "ABCDE12345".into(),
        key_id: "KEY1234567".into(),
        client_id: "com.example.app".into(),
        private_key_pem: std::fs::read("AuthKey_KEY1234567.p8")?,
    })?
    .with_background_refresh(tokio::runtime::Handle::current());

    // Your storage, once. idunn calls these during a sign-in. MyError is your own
    // error type; idunn's failures reach it through the From impl below.
    impl AppleAccounts for MyAccounts {
        type Error = MyError;

        async fn lookup(&self, identity: &AppleIdentity) -> Result<AccountState, MyError> {
            // AccountState::AlreadyOnFile { refresh_token } with the stored token
            // if one is stored for this Apple user, NotOnFile otherwise.
            self.lookup_account(&identity.apple_user_id).await
        }

        async fn schedule_revocation(&self, pending: PendingRevocation) {
            // Apple issued a live token for a new authorization that idunn then
            // rejected. Store it durably for your revocation worker, to run no
            // sooner than pending.grace_period from now.
            self.file_revocation(pending).await
        }
    }

    // When idunn itself rejects a sign-in, this decides what MyError you get.
    // kind() says how to answer.
    impl From<SignInError> for MyError {
        fn from(err: SignInError) -> Self {
            match err.kind() {
                ErrorKind::Rejected => MyError::Unauthorized,   // 401
                ErrorKind::Unavailable => MyError::Unavailable, // 503
                ErrorKind::Misconfigured => MyError::Internal,  // 500
            }
        }
    }

    // Per sign-in. `identity_token` and `authorization_code` come from the app's
    // ASAuthorizationAppleIDCredential; `expected_nonce` is the single-use value
    // your server issued for this attempt.
    // Errors come back as your own MyError: a failed lookup unchanged, idunn's
    // own failures through the From impl above.
    let outcome = apple
        .sign_up_or_log_in(
            &identity_token,
            &authorization_code,
            &expected_nonce,
            &accounts,
        )
        .await?;

    match outcome {
        SignInOutcome::LoggedIn { identity, refresh_token } => {
            // Known user: refresh_token is the freshly exchanged one, or the stored
            // one handed back when Apple couldn't issue a new one. Write it over
            // the stored token, then start a session. If writing fails, just drop
            // it: revoking would end the stored authorization too.
        }
        SignInOutcome::SignedUp { identity, refresh_token } => {
            // New authorization: store refresh_token under identity.apple_user_id,
            // then start a session. If storing fails, queue the token for
            // revocation instead.
        }
    }

    // On account deletion (required by Apple, TN3194):
    apple.revoke_refresh_token(&stored_refresh_token).await?;
    // README example: end
    Ok(())
}

fn readme_example_block(readme: &str) -> String {
    let mut lines = readme.lines().skip_while(|l| l.trim() != "```rust").skip(1);
    let mut block = String::new();
    for line in lines.by_ref().take_while(|l| l.trim() != "```") {
        block.push_str(line);
        block.push('\n');
    }
    block
}

fn copied_example_block(source: &str) -> String {
    let mut block = String::new();
    for line in source
        .lines()
        .skip_while(|l| l.trim() != START)
        .skip(1)
        .take_while(|l| l.trim() != END)
    {
        block.push_str(line.strip_prefix("    ").unwrap_or(line));
        block.push('\n');
    }
    block
}

#[test]
fn readme_example_compiles_and_matches_the_readme() {
    let _ = readme_example;
    assert_eq!(
        readme_example_block(include_str!("../README.md")),
        copied_example_block(include_str!("readme_example.rs")),
        "edit README.md and tests/readme_example.rs together"
    );
}
