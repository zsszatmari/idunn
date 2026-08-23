# Architecture

## Why `AppleAuthClient` is one client with one constructor

`idunn` does two things for Sign in with Apple:

1. **Verify identity tokens** (`AppleIdentity`, `verify_identity_token`, `src/identity.rs`) — needs only the app's bundle id(s), delegated to the third-party `apple-signin` crate.
2. **Exchange an authorization code for tokens** (`AppleTokenResponse`, `exchange_authorization_code`, `src/token.rs`) — needs a signed JWT client secret, which requires `team_id`, `key_id`, `client_id` and Apple's private key (`.p8`).

These two features barely touch the same code, which is why they live in separate submodules. They are nonetheless exposed through a single `AppleAuthClient` with a single constructor, rather than two independent client types, for one reason: **Apple requires apps to support account-deletion / token-revocation** (see [TN3194](https://developer.apple.com/documentation/technotes/tn3194-handling-account-deletions-and-revoking-tokens-for-sign-in-with-apple) and the [revoke-tokens REST API](https://developer.apple.com/documentation/signinwithapplerestapi/revoke-tokens), both linked at the top of `src/lib.rs`). Revocation needs the very refresh token this feature fetches, plus the same client-secret-signing credentials as the exchange call.

If verification and token exchange were separate client types, it would be possible to wire up a working sign-in flow that can never revoke a token — an app that's compliant on day one but silently unable to meet Apple's mandatory requirement later. A single constructor that requires all the credentials up front makes that state unreachable: correct usage (a fully-configured client) is the only usage. Token revocation itself isn't implemented yet — this constructor shape is what lets it be added later without changing any caller's configuration.

## Why the HTTP transport is injectable

`exchange_authorization_code` (and any future revoke call) talks to Apple over HTTP via the `HttpTransport` trait (`src/token.rs`), defaulted to a `reqwest`-backed `ReqwestTransport`. This is injected rather than hardcoded for two reasons:

- It keeps `idunn` swappable to a different HTTP stack (proxying, custom TLS, a differently configured client) without forking the crate.
- It makes `exchange_authorization_code` unit-testable with a small in-memory fake implementing `HttpTransport`, instead of requiring real network access or an HTTP-mocking dependency.

This abstraction only covers `idunn`'s own new code. It does **not** cover `apple-signin`'s internal JWKS fetch used during identity-token verification — that's opaque third-party behavior we don't control.

`post_form` returns a dedicated `TransportError` (network failure, or HTTP status + raw body) rather than `IdunnError`: the transport is a generic HTTP abstraction and shouldn't need to know about idunn's Apple-specific error variants. `exchange_authorization_code` — the Apple-aware caller — is what converts a `TransportError` into an `IdunnError`, parsing Apple's error body along the way. `TransportError::Network` itself carries a boxed `dyn Error` rather than concretely `reqwest::Error`, so a non-reqwest `HttpTransport` implementation can report its own underlying error type instead of being forced to produce one it doesn't have.
