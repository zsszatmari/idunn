use std::time::Duration;

/// Controls how `verify_identity_token` handles a token with no `nonce`
/// claim.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum NoncePolicy {
    /// A missing `nonce` claim is always `InvalidToken`, regardless of the
    /// token's `nonce_supported` claim. Stricter than Apple's own suggested
    /// handling (see `Permissive`), chosen as the default so replay
    /// protection is never silently disabled by a claim idunn can't verify
    /// the integrity of.
    #[default]
    Strict,
    /// Follow the `nonce_supported`-conditioned handling Apple's docs
    /// suggest: <https://developer.apple.com/documentation/signinwithapplejs/authorizationi/id_token>
    /// — a missing `nonce` is only tolerated (`IdentityWithPendingNonce::nonce`
    /// is `None`) when `nonce_supported` is `false` or absent; if
    /// `nonce_supported` is `true`, a missing nonce is still `InvalidToken`.
    Permissive,
}

// Sealing `NonceRequirement` behind a private supertrait in a private module is the
// standard sealed-trait idiom: the trait itself must be `pub` (it appears in
// `AppleAuthClient<T, N: NonceRequirement>`'s public bound), but `sealed::Sealed` can't
// be named outside this crate, so no downstream type can implement `NonceRequirement`
// and no third policy can appear. `Strict`/`Permissive` are the only two that ever will.
mod sealed {
    pub trait Sealed {}
}

/// Selects, at compile time, which [`NoncePolicy`] an `AppleAuthClient` enforces —
/// see [`Strict`] and [`Permissive`], the only two implementors. Sealed: cannot be
/// implemented outside this crate.
///
/// `AppleAuthClient::sign_in_with_nonce` compares a token's `nonce` claim
/// against one fixed expected value, which a `NoncePolicy::Permissive` token
/// may legitimately not carry at all. This type parameter makes that method
/// absent — a compile error, not a runtime one — on a `Permissive` client. See
/// docs/architecture.md ("Why the nonce policy is a type parameter").
pub trait NonceRequirement: sealed::Sealed {
    /// The runtime policy this type selects. Not meant to be read by callers —
    /// `AppleAuthClient::with_transport` uses it to configure identity-token
    /// verification internally.
    #[doc(hidden)]
    const POLICY: NoncePolicy;
}

/// Type-level marker selecting [`NoncePolicy::Strict`]. Distinct from that enum
/// variant — this is a type, used as `AppleAuthClient`'s second type parameter
/// (its default), not a value.
#[derive(Clone, Copy, Debug)]
pub struct Strict;

/// Type-level marker selecting [`NoncePolicy::Permissive`]. Distinct from that
/// enum variant — this is a type, used as `AppleAuthClient`'s second type
/// parameter, not a value. A client built with this marker has no
/// `sign_in_with_nonce` method; use `AppleAuthClient::sign_in` with a checker
/// that decides what a missing nonce means for your flow.
#[derive(Clone, Copy, Debug)]
pub struct Permissive;

impl sealed::Sealed for Strict {}
impl sealed::Sealed for Permissive {}

impl NonceRequirement for Strict {
    const POLICY: NoncePolicy = NoncePolicy::Strict;
}

impl NonceRequirement for Permissive {
    const POLICY: NoncePolicy = NoncePolicy::Permissive;
}

/// Configures identity-token verification: the behaviour of the JWKS key cache
/// that backs signature checking (how eagerly Apple's published keys are
/// refreshed, how hard the fetch is rate-limited, and how stale a cached key
/// set may get before it is refused outright).
///
/// The nonce-presence policy lives on `AppleAuthClient`'s `N: NonceRequirement`
/// type parameter (`Strict`/`Permissive`), so `sign_in_with_nonce`'s
/// availability tracks it at compile time. See docs/architecture.md ("Why the
/// nonce policy is a type parameter").
#[derive(Clone, Copy, Debug)]
pub struct VerificationConfig {
    /// How long a successful fetch stays "fresh" before `get_key`'s lazy path
    /// tries again, even if every requested kid is still present — protects
    /// against holding a key Apple has since revoked. Not a hard expiry: a
    /// key already cached is still honored past this interval, right up
    /// until a fetch attempt actually replaces the snapshot.
    pub refresh_interval: Duration,
    /// Floor on how often `JwksStore` will actually contact Apple's key
    /// endpoint, regardless of why a refresh was requested: backing off
    /// after a failed attempt, an explicit `refresh_keystore()` call arriving
    /// sooner than expected, or a flood of `get_key` lookups for unknown
    /// kids. Not tied specifically to failure — it rate-limits every attempt.
    /// Important protectionagainst DoS attacks.
    pub cooldown_period: Duration,
    /// Extra window past `refresh_interval` during which `get_key` keeps
    /// serving a kid it already holds *without* first attempting a refresh.
    /// `refresh_interval` only makes the lazy refresh eligible; this is how
    /// long past that point a cached-kid lookup still short-circuits instead
    /// of blocking on `try_refresh` (which holds `network_request_mutex` for
    /// the whole fetch, up to `REQUEST_TIMEOUT`). So a brief refresh outage —
    /// Apple's endpoint down, or cooldown backoff after a failure — can't add
    /// fetch latency to logins whose key is already cached. Set to
    /// `Duration::ZERO` to refresh eagerly. Lookups for a kid
    /// that *isn't* in the snapshot ignore this and refresh immediately.
    pub stale_key_grace_period: Duration,
    /// Hard upper bound on how old the cached snapshot may be and still be
    /// trusted at all. Unlike `refresh_interval` and `stale_key_grace_period`
    /// — which only tune how *eagerly* a refresh is attempted and never stop
    /// a key we already hold from being honored — this one fails closed: once
    /// the last successful fetch is older than `max_key_age`, `get_key`
    /// refuses every kid (even one still present in the snapshot) with
    /// `CannotVerifyToken` and logs at `error` level.
    ///
    /// This caps the blast radius of a prolonged refresh outage (Apple's
    /// endpoint unreachable for days, or the host's egress broken): without
    /// it, a snapshot fetched long ago would keep validating tokens forever,
    /// including tokens signed with a key Apple has since revoked. Should be
    /// set comfortably larger than `refresh_interval + stale_key_grace_period`
    /// so it only ever bites when refresh has genuinely been failing for a
    /// long time.
    pub max_key_age: Duration,
}

impl Default for VerificationConfig {
    fn default() -> Self {
        Self {
            refresh_interval: Duration::from_secs(6 * 60 * 60),
            cooldown_period: Duration::from_secs(60),
            stale_key_grace_period: Duration::from_secs(10 * 60),
            max_key_age: Duration::from_secs(72 * 60 * 60),
        }
    }
}
