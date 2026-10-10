use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwapOption;
use jsonwebtoken::DecodingKey;
use jsonwebtoken::jwk::JwkSet;

use crate::config::VerificationConfig;
use crate::error::{InvalidTokenCause, VerificationError};
use crate::transport::{HttpGet, TransportError};

const JWKS_URL: &str = "https://appleid.apple.com/auth/keys";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// True while less than `window` has passed since `since`.
// Its `<` -> `<=` mutant is excluded in .cargo/mutants.toml; see docs/maintaining.md.
fn is_within(since: Instant, window: Duration) -> bool {
    since.elapsed() < window
}

struct CachedKeys {
    keys: HashMap<String, DecodingKey>,
    fetched_at: Instant,
}

impl CachedKeys {
    fn jwk_set_to_keymap(jwk_set: &JwkSet) -> HashMap<String, DecodingKey> {
        jwk_set
            .keys
            .iter()
            .filter_map(|jwk| {
                let key_id = jwk.common.key_id.clone()?;
                let decoding_key = DecodingKey::from_jwk(jwk).ok()?;
                Some((key_id, decoding_key))
            })
            .collect()
    }
}

pub(crate) struct JwksStore<T: HttpGet> {
    key_set: ArcSwapOption<CachedKeys>,
    transport: T,
    // Guards fetch attempts *and* records when the last attempt (success or
    // failure) happened, so the backoff/rate-limit floor has no separate
    // state to keep in sync with the lock.
    network_request_mutex: async_lock::Mutex<Option<Instant>>,
    config: VerificationConfig,
}

impl<T: HttpGet> JwksStore<T> {
    pub fn new(config: VerificationConfig, transport: T) -> Self {
        Self {
            key_set: ArcSwapOption::empty(),
            transport,
            network_request_mutex: async_lock::Mutex::new(None),
            config,
        }
    }

    /// Returns the decoding key Apple published for `kid`, fetching/refreshing
    /// the cached key set if needed. Concurrent misses share one in-flight
    /// fetch via `network_request_mutex`.
    pub async fn get_key(&self, kid: &str) -> Result<DecodingKey, VerificationError> {
        // A cached key short-circuits here while the snapshot is still fresh,
        // and — thanks to `stale_key_grace_period` — for a while after it goes
        // stale too. Only once that grace period is also spent does a
        // cached-kid lookup fall through to a blocking `try_refresh`, so a
        // brief refresh outage can't stall logins whose kid we already hold.
        // Callers that want the snapshot kept warmer can drive
        // `refresh_keystore()` on their own schedule, or let
        // `AppleSeed::with_refresh_loop`/`with_background_refresh`
        // (src/lib.rs) do it automatically.
        if !self.past_grace_period()
            && !self.snapshot_past_max_age()
            && let Some(key) = self.cached_key(kid)
        {
            return Ok(key);
        }

        self.try_refresh().await;

        match self.key_set.load().as_ref() {
            Some(cached) if cached.fetched_at.elapsed() >= self.config.max_key_age => {
                // Refresh has been failing long enough that the snapshot is
                // now older than `max_key_age`. Fail closed: keys Apple may
                // have revoked in the meantime must not stay trusted. Log
                // loudly so the outage is visible.
                tracing::error!(
                    snapshot_age = ?cached.fetched_at.elapsed(),
                    max_key_age = ?self.config.max_key_age,
                    "Apple's JWKS snapshot is older than max_key_age and cannot be \
                     refreshed; refusing to verify tokens against a possibly-stale key set"
                );
                Err(VerificationError::CannotVerifyToken)
            }
            Some(cached) => {
                if let Some(key) = cached.keys.get(kid) {
                    // A key we already have is honored regardless of staleness
                    // — refresh_interval governs how eagerly we go back to
                    // Apple, it is not a hard expiry on cached keys.
                    return Ok(key.clone());
                }
                // kid genuinely absent from the snapshot we have. A fetch
                // newer than `refresh_interval` is confident evidence it is
                // truly not there; an older (or never-completed) one leaves us
                // unsure. The bound is `refresh_interval`; the grace period
                // only governs when a cached kid stops short-circuiting.
                if is_within(cached.fetched_at, self.config.refresh_interval) {
                    Err(VerificationError::InvalidToken(
                        InvalidTokenCause::InvalidKeyId {
                            kid: Some(kid.to_string()),
                        },
                    ))
                } else {
                    Err(VerificationError::CannotVerifyToken)
                }
            }
            None => Err(VerificationError::CannotVerifyToken),
        }
    }

    /// Refreshes the cached key set now, unless the current snapshot is still
    /// within `refresh_interval` (see below). Optional to call: `get_key`
    /// already refreshes on demand. Useful for callers that want to warm the
    /// cache at startup and/or drive periodic refresh on their own schedule.
    ///
    /// Returns how long the caller should wait before calling again: a
    /// successful fetch suggests `refresh_interval`, tracking `get_key`'s own
    /// lazy-refresh cadence; a failed or cooldown-skipped attempt suggests
    /// `cooldown_period`, the earliest a retry is allowed anyway.
    ///
    /// If the current snapshot is still within `refresh_interval`, this skips
    /// `try_refresh()` entirely — the caller is early — and returns the time
    /// remaining until `refresh_interval` elapses instead.
    pub async fn refresh_keystore(&self) -> Duration {
        if let Some(remaining) = self.remaining_until_refresh_due() {
            return remaining;
        }

        if self.try_refresh().await {
            self.config.refresh_interval
        } else {
            self.config.cooldown_period
        }
    }

    /// `Some(remaining)` if there's a cached snapshot younger than
    /// `refresh_interval`, i.e. a refresh attempt right now would be premature.
    fn remaining_until_refresh_due(&self) -> Option<Duration> {
        let cached = self.key_set.load();
        let elapsed = cached.as_ref()?.fetched_at.elapsed();
        self.config.refresh_interval.checked_sub(elapsed)
    }

    /// Looks `kid` up in the cached snapshot without touching the network.
    /// Returns `None` if the store has never fetched successfully, or if the
    /// current snapshot doesn't contain this kid.
    fn cached_key(&self, kid: &str) -> Option<DecodingKey> {
        self.key_set.load().as_ref()?.keys.get(kid).cloned()
    }

    /// True when there's no cached snapshot yet, or the last successful fetch
    /// is older than `refresh_interval + stale_key_grace_period` — the point
    /// past which even a kid we still hold no longer short-circuits
    /// `get_key`'s refresh. Says nothing about which kids are in the snapshot
    /// — that's `cached_key`'s job.
    fn past_grace_period(&self) -> bool {
        let bound = self
            .config
            .refresh_interval
            .saturating_add(self.config.stale_key_grace_period);
        self.key_set
            .load()
            .as_ref()
            .is_none_or(|cached| cached.fetched_at.elapsed() >= bound)
    }

    /// True when a snapshot exists but its last successful fetch is older than
    /// `max_key_age` — the hard cap past which the whole snapshot is refused.
    /// `past_grace_period` is separate: it only governs when a cached-kid
    /// lookup stops short-circuiting the refresh.
    fn snapshot_past_max_age(&self) -> bool {
        self.key_set
            .load()
            .as_ref()
            .is_some_and(|cached| cached.fetched_at.elapsed() >= self.config.max_key_age)
    }

    async fn try_refresh(&self) -> bool {
        let mut last_attempt = self.network_request_mutex.lock().await;
        if let Some(attempted_at) = *last_attempt
            && is_within(attempted_at, self.config.cooldown_period)
        {
            return false;
        }
        *last_attempt = Some(Instant::now());

        if let Some(keys) = self.fetch_keys().await {
            self.key_set.store(Some(Arc::new(CachedKeys {
                keys,
                fetched_at: Instant::now(),
            })));
            true
        } else {
            false
        }
    }

    /// Fetches and parses Apple's JWKS. Returns `None` (after logging a
    /// warning) on any failure — network error, non-2xx, or malformed body —
    /// none of which are surfaced to callers.
    async fn fetch_keys(&self) -> Option<HashMap<String, DecodingKey>> {
        let body = match self.transport.get(JWKS_URL, &[], REQUEST_TIMEOUT).await {
            Ok(body) => body,
            Err(TransportError::Network(e)) => {
                tracing::warn!(error = %e, "network error fetching Apple's JWKS; will retry after cooldown period {:?}", self.config.cooldown_period);
                return None;
            }
            Err(TransportError::Http { status, body }) => {
                tracing::warn!(status, %body, "Apple's JWKS endpoint returned an error; will retry after cooldown period {:?}", self.config.cooldown_period);
                return None;
            }
        };

        let jwk_set: JwkSet = match serde_json::from_str(&body) {
            Ok(set) => set,
            Err(e) => {
                tracing::warn!(error = %e, "could not parse Apple's JWKS response; will retry after cooldown period {:?}", self.config.cooldown_period);
                return None;
            }
        };

        Some(CachedKeys::jwk_set_to_keymap(&jwk_set))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::transport::test_fixtures::{MockHttpGet, network_error};

    fn jwks_body(kid: &str) -> String {
        format!(r#"{{"keys":[{{"kty":"RSA","kid":"{kid}","n":"AQAB","e":"AQAB"}}]}}"#)
    }

    /// A `max_key_age` far larger than any sleep in these tests, so the
    /// hard-expiry path stays out of the way unless a test opts into it.
    const LONG_MAX_KEY_AGE: Duration = Duration::from_secs(3600);

    fn fast_config() -> VerificationConfig {
        VerificationConfig {
            refresh_interval: Duration::from_secs(6 * 60 * 60),
            cooldown_period: Duration::from_millis(20),
            stale_key_grace_period: Duration::ZERO,
            max_key_age: LONG_MAX_KEY_AGE,
        }
    }

    fn very_fast_config() -> VerificationConfig {
        VerificationConfig {
            refresh_interval: Duration::from_millis(20),
            cooldown_period: Duration::from_millis(20),
            stale_key_grace_period: Duration::ZERO,
            max_key_age: LONG_MAX_KEY_AGE,
        }
    }

    /// Refresh interval elapses quickly, but the cooldown floor stays long —
    /// isolates the cooldown-floor skip from the refresh-interval skip, since
    /// both would otherwise fire together.
    fn short_refresh_long_cooldown_config() -> VerificationConfig {
        VerificationConfig {
            refresh_interval: Duration::from_millis(20),
            cooldown_period: Duration::from_secs(60),
            stale_key_grace_period: Duration::ZERO,
            max_key_age: LONG_MAX_KEY_AGE,
        }
    }

    /// Refresh interval elapses quickly, but the grace period on top of it
    /// stays comfortably longer than the sleeps below — so a kid we already
    /// hold keeps being served straight from the snapshot after it goes
    /// stale, without any fetch.
    fn short_refresh_long_grace_config() -> VerificationConfig {
        VerificationConfig {
            refresh_interval: Duration::from_millis(20),
            cooldown_period: Duration::from_millis(20),
            stale_key_grace_period: Duration::from_secs(60),
            max_key_age: LONG_MAX_KEY_AGE,
        }
    }

    #[tokio::test]
    async fn fetches_and_caches_key_on_cold_cache() {
        let transport = MockHttpGet::returning(jwks_body("kid-1"));
        let store = JwksStore::new(VerificationConfig::default(), transport.clone());

        let key = store.get_key("kid-1").await.unwrap();

        assert_eq!(key.family(), jsonwebtoken::AlgorithmFamily::Rsa);
        assert_eq!(transport.call_count(), 1);
    }

    #[tokio::test]
    async fn second_lookup_for_cached_kid_does_not_refetch() {
        let transport = MockHttpGet::returning(jwks_body("kid-1"));
        let store = JwksStore::new(VerificationConfig::default(), transport.clone());

        store.get_key("kid-1").await.unwrap();
        store.get_key("kid-1").await.unwrap();

        assert_eq!(transport.call_count(), 1);
    }

    #[tokio::test]
    async fn concurrent_misses_share_a_single_fetch() {
        let transport = MockHttpGet::returning(jwks_body("kid-1"));
        let store = JwksStore::new(VerificationConfig::default(), transport.clone());

        let (first, second) = tokio::join!(store.get_key("kid-1"), store.get_key("kid-1"));

        assert!(first.is_ok());
        assert!(second.is_ok());
        assert_eq!(transport.call_count(), 1);
    }

    #[tokio::test]
    async fn cold_fetch_failure_does_not_surface_to_caller() {
        let transport = MockHttpGet::failing_with(TransportError::Http {
            status: 500,
            body: "boom".to_string(),
        });
        let store = JwksStore::new(VerificationConfig::default(), transport.clone());

        let result = store.get_key("kid-1").await;

        assert!(matches!(result, Err(VerificationError::CannotVerifyToken)));
        assert_eq!(transport.call_count(), 1);
    }

    #[tokio::test]
    async fn immediate_retry_after_failure_is_suppressed_by_floor() {
        let transport = MockHttpGet::failing_with(TransportError::Http {
            status: 500,
            body: "boom".to_string(),
        });
        let store = JwksStore::new(VerificationConfig::default(), transport.clone());

        store.get_key("kid-1").await.unwrap_err();
        store.get_key("kid-1").await.unwrap_err();

        assert_eq!(transport.call_count(), 1);
    }

    #[tokio::test]
    async fn retry_happens_once_min_fetch_interval_elapses() {
        let transport = MockHttpGet::sequence(vec![
            Err(TransportError::Http {
                status: 500,
                body: "boom".to_string(),
            }),
            Ok(jwks_body("kid-1")),
        ]);
        let store = JwksStore::new(fast_config(), transport.clone());

        store.get_key("kid-1").await.unwrap_err();
        assert_eq!(transport.call_count(), 1);

        std::thread::sleep(Duration::from_millis(40));

        let key = store.get_key("kid-1").await.unwrap();
        assert_eq!(key.family(), jsonwebtoken::AlgorithmFamily::Rsa);
        assert_eq!(transport.call_count(), 2);
    }

    #[tokio::test]
    async fn refetches_a_cached_kid_once_refresh_interval_elapses() {
        let transport = MockHttpGet::sequence(vec![Ok(jwks_body("kid-1")), Ok(jwks_body("kid-2"))]);
        let store = JwksStore::new(very_fast_config(), transport.clone());

        store.get_key("kid-1").await.unwrap();
        assert_eq!(transport.call_count(), 1);

        std::thread::sleep(Duration::from_millis(40));

        // kid-1 is still cached, but the interval elapsed, so this should
        // trigger a re-fetch that replaces the snapshot with kid-2's set.
        let result = store.get_key("kid-1").await;
        assert_eq!(transport.call_count(), 2);
        assert!(matches!(
            result,
            Err(VerificationError::InvalidToken(
                InvalidTokenCause::InvalidKeyId { .. }
            ))
        ));
        assert!(store.get_key("kid-2").await.is_ok());
    }

    #[tokio::test]
    async fn cached_kid_within_grace_period_is_served_without_refresh() {
        let transport = MockHttpGet::sequence(vec![Ok(jwks_body("kid-1")), Ok(jwks_body("kid-2"))]);
        let store = JwksStore::new(short_refresh_long_grace_config(), transport.clone());

        store.get_key("kid-1").await.unwrap();
        assert_eq!(transport.call_count(), 1);

        std::thread::sleep(Duration::from_millis(40));

        // refresh_interval (20ms) has elapsed, but we're well inside the 60s
        // grace period and kid-1 is still cached — so this is served straight
        // from the snapshot without contacting Apple.
        let key = store.get_key("kid-1").await.unwrap();
        assert_eq!(transport.call_count(), 1);
        assert_eq!(key.family(), jsonwebtoken::AlgorithmFamily::Rsa);
    }

    #[tokio::test]
    async fn cached_kid_past_grace_period_triggers_refresh() {
        let transport = MockHttpGet::sequence(vec![Ok(jwks_body("kid-1")), Ok(jwks_body("kid-2"))]);
        let store = JwksStore::new(
            VerificationConfig {
                refresh_interval: Duration::from_millis(10),
                cooldown_period: Duration::from_millis(10),
                stale_key_grace_period: Duration::from_millis(20),
                max_key_age: LONG_MAX_KEY_AGE,
            },
            transport.clone(),
        );

        store.get_key("kid-1").await.unwrap();
        assert_eq!(transport.call_count(), 1);

        std::thread::sleep(Duration::from_millis(60));

        // Both refresh_interval and the grace period stacked on top of it have
        // now elapsed, so a cached-kid lookup falls through to a real refresh
        // that replaces the snapshot with kid-2's set.
        let result = store.get_key("kid-1").await;
        assert_eq!(transport.call_count(), 2);
        assert!(matches!(
            result,
            Err(VerificationError::InvalidToken(
                InvalidTokenCause::InvalidKeyId { .. }
            ))
        ));
        assert!(store.get_key("kid-2").await.is_ok());
    }

    #[tokio::test]
    async fn unknown_kid_within_grace_period_still_refreshes_immediately() {
        let transport = MockHttpGet::sequence(vec![Ok(jwks_body("kid-1")), Ok(jwks_body("kid-2"))]);
        let store = JwksStore::new(short_refresh_long_grace_config(), transport.clone());

        store.get_key("kid-1").await.unwrap();
        assert_eq!(transport.call_count(), 1);

        std::thread::sleep(Duration::from_millis(40));

        // The grace period only shields kids already in the snapshot. kid-2
        // isn't, so even inside the grace window this refreshes right away.
        assert!(store.get_key("kid-2").await.is_ok());
        assert_eq!(transport.call_count(), 2);
    }

    #[tokio::test]
    async fn refresh_keystore_warms_a_cold_store() {
        let transport = MockHttpGet::returning(jwks_body("kid-1"));
        let store = JwksStore::new(VerificationConfig::default(), transport.clone());

        let suggested_wait = store.refresh_keystore().await;

        assert_eq!(
            suggested_wait,
            VerificationConfig::default().refresh_interval
        );
        assert_eq!(transport.call_count(), 1);
    }

    #[tokio::test]
    async fn second_immediate_refresh_keystore_call_is_skipped_without_touching_try_refresh() {
        let transport = MockHttpGet::returning(jwks_body("kid-1"));
        let store = JwksStore::new(VerificationConfig::default(), transport.clone());

        assert_eq!(
            store.refresh_keystore().await,
            VerificationConfig::default().refresh_interval
        );
        assert_eq!(transport.call_count(), 1);

        // The snapshot is still well within refresh_interval, so this call
        // must be too early: it should never reach try_refresh() (and thus
        // never even get to the cooldown check) and instead report roughly
        // how long is left until refresh_interval elapses.
        let second_wait = store.refresh_keystore().await;
        let refresh_interval = VerificationConfig::default().refresh_interval;
        assert!(second_wait <= refresh_interval);
        assert!(second_wait > refresh_interval - Duration::from_secs(1));
        assert_eq!(transport.call_count(), 1);
    }

    #[tokio::test]
    async fn refresh_keystore_call_after_refresh_interval_elapses_is_skipped_by_cooldown_floor() {
        let transport = MockHttpGet::returning(jwks_body("kid-1"));
        let store = JwksStore::new(short_refresh_long_cooldown_config(), transport.clone());

        assert_eq!(store.refresh_keystore().await, Duration::from_millis(20));
        assert_eq!(transport.call_count(), 1);

        std::thread::sleep(Duration::from_millis(40));

        // refresh_interval has now elapsed, so this call is no longer "too
        // early" and reaches try_refresh() — which the 60s cooldown_period
        // then blocks, since the only attempt so far was ~40ms ago.
        assert_eq!(store.refresh_keystore().await, Duration::from_secs(60));
        assert_eq!(transport.call_count(), 1);
    }

    #[tokio::test]
    async fn unknown_kid_after_fresh_fetch_is_invalid_token() {
        let transport = MockHttpGet::returning(jwks_body("kid-1"));
        let store = JwksStore::new(VerificationConfig::default(), transport);

        let result = store.get_key("does-not-exist").await;

        assert!(matches!(
            result,
            Err(VerificationError::InvalidToken(InvalidTokenCause::InvalidKeyId { kid }))
                if kid.as_deref() == Some("does-not-exist")
        ));
    }

    #[tokio::test]
    async fn a_cached_key_survives_a_failed_refresh_after_going_stale() {
        let transport = MockHttpGet::sequence(vec![
            Ok(jwks_body("kid-1")),
            Err(TransportError::Http {
                status: 500,
                body: "boom".to_string(),
            }),
        ]);
        let store = JwksStore::new(very_fast_config(), transport.clone());

        let key = store.get_key("kid-1").await.unwrap();
        assert_eq!(transport.call_count(), 1);

        std::thread::sleep(Duration::from_millis(40));

        // The refresh interval has elapsed, so get_key attempts a refresh —
        // which fails. The kid-1 entry from the earlier successful fetch must
        // still be returned.
        let key_after_failed_refresh = store.get_key("kid-1").await.unwrap();
        assert_eq!(transport.call_count(), 2);
        assert_eq!(key_after_failed_refresh.family(), key.family());
    }

    #[tokio::test]
    async fn cached_key_is_refused_once_snapshot_passes_max_key_age() {
        let transport = MockHttpGet::sequence(vec![
            Ok(jwks_body("kid-1")),
            Err(TransportError::Http {
                status: 500,
                body: "boom".to_string(),
            }),
        ]);
        let store = JwksStore::new(
            VerificationConfig {
                refresh_interval: Duration::from_millis(10),
                cooldown_period: Duration::from_millis(10),
                stale_key_grace_period: Duration::ZERO,
                max_key_age: Duration::from_millis(30),
            },
            transport.clone(),
        );

        store.get_key("kid-1").await.unwrap();
        assert_eq!(transport.call_count(), 1);

        std::thread::sleep(Duration::from_millis(50));

        // The snapshot holding kid-1 is now older than max_key_age and the
        // refresh attempt fails, so even a kid we still hold must be refused:
        // Apple may have revoked keys from this key set.
        let result = store.get_key("kid-1").await;
        assert!(matches!(result, Err(VerificationError::CannotVerifyToken)));
        assert_eq!(transport.call_count(), 2);
    }

    #[tokio::test]
    async fn a_successful_refresh_lifts_the_max_key_age_refusal() {
        let transport = MockHttpGet::sequence(vec![
            Ok(jwks_body("kid-1")),
            Err(TransportError::Http {
                status: 500,
                body: "boom".to_string(),
            }),
            Ok(jwks_body("kid-1")),
        ]);
        let store = JwksStore::new(
            VerificationConfig {
                refresh_interval: Duration::from_millis(10),
                cooldown_period: Duration::from_millis(10),
                stale_key_grace_period: Duration::ZERO,
                max_key_age: Duration::from_millis(30),
            },
            transport.clone(),
        );

        store.get_key("kid-1").await.unwrap();
        std::thread::sleep(Duration::from_millis(50));

        // Snapshot too old + failing refresh: refused.
        assert!(matches!(
            store.get_key("kid-1").await,
            Err(VerificationError::CannotVerifyToken)
        ));
        assert_eq!(transport.call_count(), 2);

        std::thread::sleep(Duration::from_millis(15));

        // Cooldown has elapsed and this refresh succeeds, replacing the
        // snapshot with a fresh one — verification resumes, the fail-closed
        // state was not permanent.
        let key = store.get_key("kid-1").await.unwrap();
        assert_eq!(key.family(), jsonwebtoken::AlgorithmFamily::Rsa);
        assert_eq!(transport.call_count(), 3);
    }

    #[tokio::test]
    async fn max_key_age_overrides_a_longer_grace_period() {
        let transport = MockHttpGet::sequence(vec![
            Ok(jwks_body("kid-1")),
            Err(TransportError::Http {
                status: 500,
                body: "boom".to_string(),
            }),
        ]);
        let store = JwksStore::new(
            VerificationConfig {
                refresh_interval: Duration::from_millis(10),
                cooldown_period: Duration::from_millis(10),
                stale_key_grace_period: Duration::from_secs(60),
                max_key_age: Duration::from_millis(30),
            },
            transport.clone(),
        );

        store.get_key("kid-1").await.unwrap();
        assert_eq!(transport.call_count(), 1);

        std::thread::sleep(Duration::from_millis(50));

        // Misconfigured on purpose: max_key_age sits well inside the grace
        // window. The grace period alone would still serve kid-1 from the
        // snapshot without a fetch; max_key_age must win and force the refresh
        // attempt, whose failure then fails closed.
        let result = store.get_key("kid-1").await;
        assert!(matches!(result, Err(VerificationError::CannotVerifyToken)));
        assert_eq!(transport.call_count(), 2);
    }

    #[tokio::test]
    async fn malformed_json_does_not_surface_to_caller() {
        let transport = MockHttpGet::returning("not json".to_string());
        let store = JwksStore::new(VerificationConfig::default(), transport.clone());

        let result = store.get_key("kid-1").await;

        assert!(matches!(result, Err(VerificationError::CannotVerifyToken)));
        assert_eq!(transport.call_count(), 1);
    }

    #[tokio::test]
    async fn network_error_does_not_surface_to_caller() {
        let transport = MockHttpGet::failing_with(network_error());
        let store = JwksStore::new(VerificationConfig::default(), transport.clone());

        let result = store.get_key("kid-1").await;

        assert!(matches!(result, Err(VerificationError::CannotVerifyToken)));
        assert_eq!(transport.call_count(), 1);
    }

    #[tokio::test]
    async fn stale_cache_with_failed_refresh_and_unknown_kid_is_cannot_verify() {
        let transport = MockHttpGet::sequence(vec![
            Ok(jwks_body("kid-1")),
            Err(TransportError::Http {
                status: 500,
                body: "boom".to_string(),
            }),
        ]);
        let store = JwksStore::new(very_fast_config(), transport.clone());

        store.get_key("kid-1").await.unwrap();
        assert_eq!(transport.call_count(), 1);

        std::thread::sleep(Duration::from_millis(40));

        // kid-2 was never in any snapshot; the refresh attempt fails, so this
        // must be reported as "can't verify" (inconclusive); "invalid kid"
        // (confidently absent) is only trustworthy after a fresh, successful
        // fetch.
        let result = store.get_key("kid-2").await;
        assert!(matches!(result, Err(VerificationError::CannotVerifyToken)));
        assert_eq!(transport.call_count(), 2);
    }

    #[tokio::test]
    async fn concurrent_misses_share_a_single_failed_fetch() {
        let transport = MockHttpGet::failing_with(TransportError::Http {
            status: 500,
            body: "boom".to_string(),
        });
        let store = JwksStore::new(VerificationConfig::default(), transport.clone());

        let (first, second) = tokio::join!(store.get_key("kid-1"), store.get_key("kid-1"));

        assert!(matches!(first, Err(VerificationError::CannotVerifyToken)));
        assert!(matches!(second, Err(VerificationError::CannotVerifyToken)));
        assert_eq!(transport.call_count(), 1);
    }

    /// Contract test: Apple's live JWKS endpoint returns a JWK set that parses into at
    /// least one usable key. Ignored so `cargo test` and PR CI don't depend on Apple's
    /// availability; runs instead in the weekly `live-apple` workflow.
    #[tokio::test]
    #[ignore = "calls Apple's live endpoint; run with `cargo test -- --ignored real_apple`"]
    async fn real_apple_refresh() {
        let transport = crate::transport::ReqwestTransport::default();
        let result = transport.get(JWKS_URL, &[], REQUEST_TIMEOUT).await;

        match result {
            Ok(response) => {
                let jwks: JwkSet = serde_json::from_slice(response.as_bytes()).unwrap();
                let jwk_map: HashMap<String, DecodingKey> = CachedKeys::jwk_set_to_keymap(&jwks);
                assert!(jwk_map.keys().len() > 0);
            }
            other => panic!("expected an HTTP error response, got {other:?}"),
        }
    }
}
