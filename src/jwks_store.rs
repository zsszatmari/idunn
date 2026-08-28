use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwapOption;
use jsonwebtoken::DecodingKey;
use jsonwebtoken::jwk::JwkSet;

use crate::error::{IdunnError, InvalidTokenCause};
use crate::transport::{HttpGet, TransportError};

const JWKS_URL: &str = "https://appleid.apple.com/auth/keys";
// TODO: make this configurable through the public API instead of hardcoding it here
// (same TODO exists in token_exchange.rs's REQUEST_TIMEOUT).
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Debug)]
pub struct JwksStoreConfig {
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
}

impl Default for JwksStoreConfig {
    fn default() -> Self {
        Self {
            refresh_interval: Duration::from_secs(6 * 60 * 60),
            cooldown_period: Duration::from_secs(60),
        }
    }
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
    config: JwksStoreConfig,
}

impl<T: HttpGet> JwksStore<T> {
    pub fn new(transport: T, config: JwksStoreConfig) -> Self {
        Self {
            key_set: ArcSwapOption::empty(),
            transport,
            network_request_mutex: async_lock::Mutex::new(None),
            config,
        }
    }

    /// Returns the decoding key Apple published for `kid`, fetching/refreshing
    /// the cached key set if needed. Concurrent misses share one in-flight
    /// fetch via `network_request_mutex` instead of each hitting Apple.
    pub async fn get_key(&self, kid: &str) -> Result<DecodingKey, IdunnError> {
        if !self.is_stale()
            && let Some(key) = self.cached_key(kid)
        {
            return Ok(key);
        }

        self.try_refresh().await;

        match self.key_set.load().as_ref() {
            Some(cached) => {
                if let Some(key) = cached.keys.get(kid) {
                    // A key we already have is honored regardless of staleness
                    // — refresh_interval governs how eagerly we go back to
                    // Apple, it is not a hard expiry on cached keys.
                    return Ok(key.clone());
                }
                // kid genuinely absent from the snapshot we have. Use the same
                // freshness definition as the lazy-refresh trigger to decide
                // whether that's confident evidence (fresh fetch, truly not
                // there) or inconclusive (stale/never-fetched, we just don't
                // know).
                if cached.fetched_at.elapsed() < self.config.refresh_interval {
                    Err(IdunnError::InvalidToken(InvalidTokenCause::InvalidKeyId {
                        kid: Some(kid.to_string()),
                    }))
                } else {
                    Err(IdunnError::CannotVerifyToken)
                }
            }
            None => Err(IdunnError::CannotVerifyToken),
        }
    }

    /// Refreshes the cached key set now, ignoring `refresh_interval` (only
    /// `cooldown_period` applies). Optional to call: `get_key` already
    /// refreshes on demand. Useful for callers that want to warm the cache at
    /// startup and/or drive periodic refresh on their own schedule.
    ///
    /// Returns how long the caller should wait before calling again: a
    /// successful fetch suggests `refresh_interval`, tracking `get_key`'s own
    /// lazy-refresh cadence; a failed or cooldown-skipped attempt suggests
    /// `cooldown_period`, the earliest a retry is allowed anyway.
    pub async fn refresh_keystore(&self) -> Duration {
        if self.try_refresh().await {
            self.config.refresh_interval
        } else {
            self.config.cooldown_period
        }
    }

    /// Looks `kid` up in the cached snapshot without touching the network.
    /// Returns `None` if the store has never fetched successfully, or if the
    /// current snapshot doesn't contain this kid.
    fn cached_key(&self, kid: &str) -> Option<DecodingKey> {
        self.key_set.load().as_ref()?.keys.get(kid).cloned()
    }

    /// True when there's no cached snapshot yet, or the last successful fetch
    /// is older than `refresh_interval`. Says nothing about which kids are in
    /// the snapshot — that's `cached_key`'s job.
    fn is_stale(&self) -> bool {
        self.key_set
            .load()
            .as_ref()
            .is_none_or(|cached| cached.fetched_at.elapsed() >= self.config.refresh_interval)
    }

    async fn try_refresh(&self) -> bool {
        let mut last_attempt = self.network_request_mutex.lock().await;
        if let Some(attempted_at) = *last_attempt
            && attempted_at.elapsed() < self.config.cooldown_period
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
    /// none of which are surfaced to callers as an `IdunnError`.
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

    fn fast_config() -> JwksStoreConfig {
        JwksStoreConfig {
            refresh_interval: Duration::from_secs(6 * 60 * 60),
            cooldown_period: Duration::from_millis(20),
        }
    }

    fn very_fast_config() -> JwksStoreConfig {
        JwksStoreConfig {
            refresh_interval: Duration::from_millis(20),
            cooldown_period: Duration::from_millis(20),
        }
    }

    #[tokio::test]
    async fn fetches_and_caches_key_on_cold_cache() {
        let transport = MockHttpGet::returning(jwks_body("kid-1"));
        let store = JwksStore::new(transport.clone(), JwksStoreConfig::default());

        let key = store.get_key("kid-1").await.unwrap();

        assert_eq!(key.family(), jsonwebtoken::AlgorithmFamily::Rsa);
        assert_eq!(transport.call_count(), 1);
    }

    #[tokio::test]
    async fn second_lookup_for_cached_kid_does_not_refetch() {
        let transport = MockHttpGet::returning(jwks_body("kid-1"));
        let store = JwksStore::new(transport.clone(), JwksStoreConfig::default());

        store.get_key("kid-1").await.unwrap();
        store.get_key("kid-1").await.unwrap();

        assert_eq!(transport.call_count(), 1);
    }

    #[tokio::test]
    async fn concurrent_misses_share_a_single_fetch() {
        let transport = MockHttpGet::returning(jwks_body("kid-1"));
        let store = JwksStore::new(transport.clone(), JwksStoreConfig::default());

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
        let store = JwksStore::new(transport.clone(), JwksStoreConfig::default());

        let result = store.get_key("kid-1").await;

        assert!(matches!(result, Err(IdunnError::CannotVerifyToken)));
        assert_eq!(transport.call_count(), 1);
    }

    #[tokio::test]
    async fn immediate_retry_after_failure_is_suppressed_by_floor() {
        let transport = MockHttpGet::failing_with(TransportError::Http {
            status: 500,
            body: "boom".to_string(),
        });
        let store = JwksStore::new(transport.clone(), JwksStoreConfig::default());

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
        let store = JwksStore::new(transport.clone(), fast_config());

        store.get_key("kid-1").await.unwrap_err();
        assert_eq!(transport.call_count(), 1);

        std::thread::sleep(Duration::from_millis(40));

        let key = store.get_key("kid-1").await.unwrap();
        assert_eq!(key.family(), jsonwebtoken::AlgorithmFamily::Rsa);
        assert_eq!(transport.call_count(), 2);
    }

    #[tokio::test]
    async fn refetches_a_cached_kid_once_refresh_interval_elapses() {
        let transport =
            MockHttpGet::sequence(vec![Ok(jwks_body("kid-1")), Ok(jwks_body("kid-2"))]);
        let store = JwksStore::new(transport.clone(), very_fast_config());

        store.get_key("kid-1").await.unwrap();
        assert_eq!(transport.call_count(), 1);

        std::thread::sleep(Duration::from_millis(40));

        // kid-1 is still cached, but the interval elapsed, so this should
        // trigger a re-fetch that replaces the snapshot with kid-2's set.
        let result = store.get_key("kid-1").await;
        assert_eq!(transport.call_count(), 2);
        assert!(matches!(
            result,
            Err(IdunnError::InvalidToken(
                InvalidTokenCause::InvalidKeyId { .. }
            ))
        ));
        assert!(store.get_key("kid-2").await.is_ok());
    }

    #[tokio::test]
    async fn refresh_keystore_warms_a_cold_store() {
        let transport = MockHttpGet::returning(jwks_body("kid-1"));
        let store = JwksStore::new(transport.clone(), JwksStoreConfig::default());

        let suggested_wait = store.refresh_keystore().await;

        assert_eq!(suggested_wait, JwksStoreConfig::default().refresh_interval);
        assert_eq!(transport.call_count(), 1);
    }

    #[tokio::test]
    async fn second_immediate_refresh_keystore_call_is_skipped_by_floor_not_by_a_real_refresh() {
        let transport = MockHttpGet::returning(jwks_body("kid-1"));
        let store = JwksStore::new(transport.clone(), JwksStoreConfig::default());

        assert_eq!(
            store.refresh_keystore().await,
            JwksStoreConfig::default().refresh_interval
        );
        assert_eq!(transport.call_count(), 1);

        // The 60s default cooldown_period blocks this second call from
        // attempting anything, so it reports the cooldown-retry duration,
        // not another successful refresh.
        assert_eq!(
            store.refresh_keystore().await,
            JwksStoreConfig::default().cooldown_period
        );
        assert_eq!(transport.call_count(), 1);
    }

    #[tokio::test]
    async fn unknown_kid_after_fresh_fetch_is_invalid_token() {
        let transport = MockHttpGet::returning(jwks_body("kid-1"));
        let store = JwksStore::new(transport, JwksStoreConfig::default());

        let result = store.get_key("does-not-exist").await;

        assert!(matches!(
            result,
            Err(IdunnError::InvalidToken(InvalidTokenCause::InvalidKeyId { kid }))
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
        let store = JwksStore::new(transport.clone(), very_fast_config());

        let key = store.get_key("kid-1").await.unwrap();
        assert_eq!(transport.call_count(), 1);

        std::thread::sleep(Duration::from_millis(40));

        // The refresh interval has elapsed, so get_key attempts a refresh —
        // which fails. The kid-1 entry from the earlier successful fetch must
        // still be returned rather than treated as gone.
        let key_after_failed_refresh = store.get_key("kid-1").await.unwrap();
        assert_eq!(transport.call_count(), 2);
        assert_eq!(key_after_failed_refresh.family(), key.family());
    }

    #[tokio::test]
    async fn malformed_json_does_not_surface_to_caller() {
        let transport = MockHttpGet::returning("not json".to_string());
        let store = JwksStore::new(transport.clone(), JwksStoreConfig::default());

        let result = store.get_key("kid-1").await;

        assert!(matches!(result, Err(IdunnError::CannotVerifyToken)));
        assert_eq!(transport.call_count(), 1);
    }

    #[tokio::test]
    async fn network_error_does_not_surface_to_caller() {
        let transport = MockHttpGet::failing_with(network_error());
        let store = JwksStore::new(transport.clone(), JwksStoreConfig::default());

        let result = store.get_key("kid-1").await;

        assert!(matches!(result, Err(IdunnError::CannotVerifyToken)));
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
        let store = JwksStore::new(transport.clone(), very_fast_config());

        store.get_key("kid-1").await.unwrap();
        assert_eq!(transport.call_count(), 1);

        std::thread::sleep(Duration::from_millis(40));

        // kid-2 was never in any snapshot; the refresh attempt fails, so this
        // must be reported as "can't verify" (inconclusive), not "invalid
        // kid" (confidently absent) — that distinction is only trustworthy
        // after a fresh, successful fetch.
        let result = store.get_key("kid-2").await;
        assert!(matches!(result, Err(IdunnError::CannotVerifyToken)));
        assert_eq!(transport.call_count(), 2);
    }

    #[tokio::test]
    async fn concurrent_misses_share_a_single_failed_fetch() {
        let transport = MockHttpGet::failing_with(TransportError::Http {
            status: 500,
            body: "boom".to_string(),
        });
        let store = JwksStore::new(transport.clone(), JwksStoreConfig::default());

        let (first, second) = tokio::join!(store.get_key("kid-1"), store.get_key("kid-1"));

        assert!(matches!(first, Err(IdunnError::CannotVerifyToken)));
        assert!(matches!(second, Err(IdunnError::CannotVerifyToken)));
        assert_eq!(transport.call_count(), 1);
    }

    #[tokio::test]
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
