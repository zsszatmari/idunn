# Architecture

TODO: ezt at kell neznem szemelyesen majd

## Why `AppleAuthClient` is one client with one constructor

`idunn` does two things for Sign in with Apple:

1. **Verify identity tokens** (`AppleIdentity`, `verify_identity_token`, `src/identity_verification.rs`) — needs only the app's bundle id(s), checked against Apple's own published keys via idunn's own `JwksStore` and `jsonwebtoken`-based verification.
2. **Exchange an authorization code for tokens** (`AppleTokenResponse`, `exchange_authorization_code`, `src/token_exchange.rs`) — needs a signed JWT client secret, which requires `team_id`, `key_id`, `client_id` and Apple's private key (`.p8`).

These two features barely touch the same code, which is why they live in separate submodules. They are nonetheless exposed through a single `AppleAuthClient` with a single constructor, rather than two independent client types, for one reason: **Apple requires apps to support account-deletion / token-revocation** (see [TN3194](https://developer.apple.com/documentation/technotes/tn3194-handling-account-deletions-and-revoking-tokens-for-sign-in-with-apple) and the [revoke-tokens REST API](https://developer.apple.com/documentation/signinwithapplerestapi/revoke-tokens), both linked at the top of `src/lib.rs`). Revocation needs the very refresh token this feature fetches, plus the same client-secret-signing credentials as the exchange call.

If verification and token exchange were separate client types, it would be possible to wire up a working sign-in flow that can never revoke a token — an app that's compliant on day one but silently unable to meet Apple's mandatory requirement later. A single constructor that requires all the credentials up front makes that state unreachable: correct usage (a fully-configured client) is the only usage. Token revocation itself isn't implemented yet — this constructor shape is what lets it be added later without changing any caller's configuration.

## Why the HTTP transport is injectable

`exchange_authorization_code` and `verify_identity_token` (via `JwksStore`'s fetch of Apple's published keys) both talk to Apple over HTTP through the same `HttpTransport` trait (`src/transport.rs`), defaulted to a `reqwest`-backed `ReqwestTransport`. This is injected rather than hardcoded for two reasons:

- It keeps `idunn` swappable to a different HTTP stack (proxying, custom TLS, a differently configured client) without forking the crate.
- It makes both `exchange_authorization_code` and `JwksStore` unit-testable with a small in-memory fake implementing `HttpTransport`, instead of requiring real network access or an HTTP-mocking dependency.

This abstraction covers every network call idunn makes, including the JWKS fetch — there's no third-party opacity left to carve out here.

`post_form`/`get` return a dedicated `TransportError` (network failure, or HTTP status + raw body) rather than `IdunnError`: the transport is a generic HTTP abstraction and shouldn't need to know about idunn's Apple-specific error variants. The Apple-aware callers (`exchange_authorization_code`, `JwksStore`) are what convert a `TransportError` into an `IdunnError`, parsing Apple's error body along the way. `TransportError::Network` itself carries a boxed `dyn Error` rather than concretely `reqwest::Error`, so a non-reqwest `HttpTransport` implementation can report its own underlying error type instead of being forced to produce one it doesn't have.

## Why `verify_identity_token` doesn't check the nonce itself

Apple's own verification checklist (see the comment in `IdentityVerificationClient::new`, `src/identity_verification.rs`) includes checking the token's `nonce` claim against whatever value the app generated for that authentication attempt. idunn deliberately stops short of that comparison: it requires knowing where and how the caller tracked the nonce it issued — typically a database lookup — which idunn has no generic way to perform. Instead, `verify_identity_token` extracts the `nonce` claim as-is onto `AppleIdentity` and leaves the value comparison to the caller.

idunn does, however, enforce nonce *presence*, controlled by `NoncePolicy` (part of `IdentityVerificationConfig`):

- `NoncePolicy::Strict` (the default): a token with no `nonce` claim is always `InvalidToken`, regardless of the token's `nonce_supported` claim. This is stricter than what Apple's docs technically require, chosen so replay protection is never silently disabled by a claim idunn has no way to verify the integrity of.
- `NoncePolicy::Permissive`: follows the handling Apple's own docs suggest (https://developer.apple.com/documentation/signinwithapplejs/authorizationi/id_token, `nonce_supported`) — a missing nonce is tolerated (`AppleIdentity::nonce` is `None`) only when `nonce_supported` is `false` or absent; a `nonce_supported: true` claim still fails the token even under this policy, since Apple's guidance is to treat the nonce as mandatory in that case.

When `nonce` is `None` under `Permissive`, `AppleIdentity::issued_at`/`expiration` (from the token's `iat`/`exp` claims) are exposed so the caller can still build its own replay-detection window (e.g. dedupe on the token itself within that range) instead of having no signal at all.
