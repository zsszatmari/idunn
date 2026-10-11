# idunn

[![crates.io](https://img.shields.io/crates/v/idunn.svg)](https://crates.io/crates/idunn)
[![Documentation](https://docs.rs/idunn/badge.svg)](https://docs.rs/idunn)
[![CI](https://github.com/zsszatmari/idunn/actions/workflows/ci.yml/badge.svg)](https://github.com/zsszatmari/idunn/actions/workflows/ci.yml)

`idunn` is a Rust crate for Sign in with Apple: it verifies identity tokens, exchanges authorization codes for refresh tokens, and revokes them, all against Apple's own REST API. It has no persistence layer and no opinion about your database, your web framework, or your async runtime — it hands you typed, verified results and gets out of the way.

idunn's guiding principle is to be easy to use correctly and hard to use incorrectly: the obvious way to integrate it is the one Apple's rules require.

## Example

```rust
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
```

What `lookup` and `schedule_revocation` must guarantee, and how to run the revocation queue, is described in the crate-level documentation on docs.rs, section "The `AppleAccounts` contract".

## Highlights 

- **One client, one constructor.** Identity verification and token exchange belong together, therefore idunn is constructed to make it hard to end up with a sign-in flow that can never revoke a token — a mandatory requirement under Apple's own rules (TN3194).
- **Verified by default.** `sign_up_or_log_in` never hands back an Apple `id_token` it hasn't checked itself — signature, issuer, audience, expiry, nonce presence — so there's no raw JWT for a caller to accidentally trust unchecked.
- **Secrets that can't leak by accident.** Refresh tokens and private keys get hand-written, redacting `Debug` impls and zeroize-on-drop, so an `unwrap()` panic or a stray `{:?}` in a log line can't print a live credential.
- **An injectable HTTP transport**, so you can bring your own HTTP client. reqwest is supported out of the box.
- **Mutation-tested.** CI fails when cargo-mutants finds a code change that no test catches, or when line coverage drops below 90%.

What it deliberately does not do: store anything, decide who "owns" an Apple account, or coordinate concurrent sign-ins and revocations for the same user — that needs a shared view of your own application state, so it's your job, but it's guided by the `AppleAccounts` trait you implement. The crate-level documentation on docs.rs describes that contract, and the `idunn::_architecture` module there explains the reasoning behind the crate's design.

## Getting started

Add the crate, pick a crypto backend feature (`aws_lc_rs`, the default, or `rust_crypto`), and enable `reqwest` for the built-in HTTP transport — or omit it and supply your own `HttpTransport` implementation:

```toml
[dependencies]
idunn = { version = "0.1", features = ["reqwest", "tokio-refresh"] }
```

`tokio-refresh` adds `with_background_refresh`; without it, see `with_refresh_loop` in the crate-level documentation.

The minimum supported Rust version is 1.88.

The full API — constructors, `sign_up_or_log_in`, `verify_identity_token`, `exchange_authorization_code`, `revoke_refresh_token` — is documented on [docs.rs](https://docs.rs/idunn); `cargo doc --open` builds the same documentation locally.

## Comparison with other Sign in with Apple crates

idunn is built around one call, `sign_up_or_log_in`, that runs a sign-in the way Apple's rules require: it verifies the identity token, checks the nonce, exchanges the authorization code and checks that the exchanged token names the same user and nonce. You implement two storage hooks, and idunn tells you which refresh token to store, which to revoke and which to drop. The rules live in idunn and in the `AppleAccounts` contract it documents, so you don't have to work them out from Apple's documentation.

As of October 2026, comparing the latest release of each crate:

| | idunn | [id_token_parser](https://crates.io/crates/id_token_parser) | [siwa-async](https://crates.io/crates/siwa-async) | [apple-signin](https://crates.io/crates/apple-signin) | [apple](https://crates.io/crates/apple) | [sign-in-with-apple](https://crates.io/crates/sign-in-with-apple) |
|---|---|---|---|---|---|---|
| Runs the whole sign-in in one call, including what to store and revoke | ✔️ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Verifies identity tokens (signature, issuer, audience, expiry) | ✔️ | ✔️ | ✔️ | ✔️ | ❌ | Partial |
| Checks the nonce | ✔️ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Caches Apple's signing keys, refetching on rotation | ✔️ | ✔️ | ❌ | ✔️ | ❌ | ❌ |
| Rate-limits key fetches and backs off after failures | ✔️ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Exchanges authorization codes | ✔️ | ✔️ | ✔️ | ❌ | ✔️ | ❌ |
| Verifies the exchanged token and checks it names the same user and nonce | ✔️ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Validates refresh tokens | Not needed¹ | ❌ | ✔️ | ❌ | ✔️ | ❌ |
| Revokes tokens | ✔️ | ✔️ | ✔️ | ❌ | ❌ | ❌ |
| Verifies server-to-server notifications² | ❌ | Partial | ❌ | ❌ | ❌ | Partial |
| Accepts your own HTTP client | ✔️ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Checked release | 0.1.0 | 0.2.5 (2025-12) | 0.5.2 (2022-06) | 0.2.0 (2025-11) | 0.2.0 (2026-02) | 0.2.0 (2022-02) |

¹ idunn exchanges the authorization code at every sign-in, so the stored refresh token follows the user's latest authorization. idunn uses it only to revoke that authorization when the account is deleted.

² A useful future addition, but strictly [required](https://developer.apple.com/news/?id=j9zukcr6) only for developers based in South Korea using a Services ID. Pull requests are welcome; please open an issue first to discuss the design.

`sign-in-with-apple` is based on [`siwa`](https://crates.io/crates/siwa) (0.1.2, 2021-03). [`apple_auth`](https://crates.io/crates/apple_auth) and [`oauth2-apple`](https://crates.io/crates/oauth2-apple) cover only the authorization code exchange.

If you feel an entry is wrong or out of date, please open an issue.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Why "idunn"?

In Norse mythology, Iðunn is the goddess who keeps the gods' apples — the ones that keep them young. Take her name away from them even briefly and they start aging; get the apples back and they're restored. That's close enough to what this crate does with Apple's tokens: it holds the things that keep a user's session valid, checks them properly before handing them back, and makes sure a stale or compromised one gets taken out of circulation promptly.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
