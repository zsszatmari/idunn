# idunn

`idunn` is a Rust crate for Sign in with Apple: it verifies identity tokens, exchanges authorization codes for refresh tokens, and revokes them, all against Apple's own REST API. It has no persistence layer and no opinion about your database, your web framework, or your async runtime — it hands you typed, verified results and gets out of the way.

## Example

```rust
use idunn::{AppleAuthClient, AppleTokenConfig, SignInError, SignInOutcome};

// Once, at startup. Clones are cheap and share the JWKS cache.
let apple = AppleAuthClient::new(AppleTokenConfig {
    team_id: "ABCDE12345".into(),
    key_id: "KEY1234567".into(),
    client_id: "com.example.app".into(),
    private_key_pem: std::fs::read("AuthKey_KEY1234567.p8")?,
})?
.with_background_refresh(tokio::runtime::Handle::current());

// Per sign-in. `identity_token` and `authorization_code` come from the app's
// ASAuthorizationAppleIDCredential; `expected_nonce` is the single-use value
// your server issued for this attempt.
let outcome = match apple
    .sign_up_or_log_in_with_nonce(
        &identity_token,
        &authorization_code,
        &expected_nonce,
        |identity| async move {
            // Your storage: AccountState::AlreadyOnFile if a usable refresh
            // token is stored for this Apple user, NeedsExchange otherwise.
            lookup_account(&identity.apple_user_id).await
        },
    )
    .await
{
    Ok(outcome) => outcome,
    Err(SignInError::RevocationRequired(pending)) => {
        // Apple issued a live token for a sign-in idunn then rejected:
        // queue pending.refresh_token for revocation, never just drop it.
        return Err(MyError::SignInRejected);
    }
    // Your `From<SignInError<LookupError>> for MyError`, where LookupError is
    // lookup_account's own error type, matches every variant with no
    // wildcard: a variant added in a later idunn version won't compile until
    // you decide what it means.
    Err(err) => return Err(err.into()),
};

match outcome {
    SignInOutcome::LoggedIn { identity } => {
        // Known user, token already on file: start a session.
    }
    SignInOutcome::SignedUp { identity, refresh_token } => {
        // Store refresh_token under identity.apple_user_id, then start a
        // session. If storing fails, queue the token for revocation instead.
    }
}

// On account deletion (required by Apple, TN3194):
apple.revoke_refresh_token(&stored_refresh_token).await?;
```

What `lookup_account` must guarantee, and how to run the revocation queue, is described in [docs/usage.md](docs/usage.md), "The `account_lookup` contract".

## Highlights 

- **One client, one constructor.** Identity verification and token exchange belong together, therefore idunn is constructed to make it hard to end up with a sign-in flow that can never revoke a token — a mandatory requirement under Apple's own rules (TN3194).
- **Verified by default.** `sign_up_or_log_in` never hands back an Apple `id_token` it hasn't checked itself — signature, issuer, audience, expiry, nonce presence — so there's no raw JWT for a caller to accidentally trust unchecked.
- **Secrets that can't leak by accident.** Refresh tokens and private keys get hand-written, redacting `Debug` impls and zeroize-on-drop, so an `unwrap()` panic or a stray `{:?}` in a log line can't print a live credential.
- **An injectable HTTP transport**, so you can bring your own HTTP client. reqwest is supported out of the box.

What it deliberately does not do: store anything, decide who "owns" an Apple account, or coordinate concurrent sign-ins and revocations for the same user — that needs a shared view of your own application state, so it's your job, but it's guided by `account_lookup`. See [docs/usage.md](docs/usage.md) for that contract and [docs/architecture.md](docs/architecture.md) for the reasoning behind the crate's design.

## Getting started

Add the crate, pick a crypto backend feature (`aws_lc_rs`, the default, or `rust_crypto`), and enable `reqwest` for the built-in HTTP transport — or omit it and supply your own `HttpTransport` implementation:

```toml
[dependencies]
idunn = { version = "0.1", features = ["reqwest", "tokio-refresh"] }
```

`tokio-refresh` adds `with_background_refresh`; without it, see `with_refresh_loop` in [docs/usage.md](docs/usage.md).

The full API — constructors, `sign_up_or_log_in`, `verify_identity_token`, `exchange_authorization_code`, `revoke_refresh_token` — is documented on the crate's own rustdoc, generated from [docs/usage.md](docs/usage.md). Build it locally with `cargo doc --open`, or read it on docs.rs once published.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Why "idunn"?

In Norse mythology, Iðunn is the goddess who keeps the gods' apples — the ones that keep them young. Take her name away from them even briefly and they start aging; get the apples back and they're restored. That's close enough to what this crate does with Apple's tokens: it holds the things that keep a user's session valid, checks them properly before handing them back, and makes sure a stale or compromised one gets taken out of circulation promptly.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
