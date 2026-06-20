// AUTHORED-BY Claude Opus 4.8
//! DPoP `jti` replay protection.
//!
//! Ports `src/auth/replayStore.ts`: a pluggable [`ReplayStore`] trait so the in-memory (single-node)
//! implementation and a future shared (Redis) implementation share one contract; a default
//! std-only [`InMemoryReplayStore`] (a `Mutex<HashMap<jti, expiry>>` for an **atomic** check-and-set
//! that **never evicts a live `jti`**); and the **fail-closed** posture (a backend error — incl.
//! capacity exhaustion — rejects the request rather than silently weakening replay protection; the
//! verifier maps it to a 503).
//!
//! The per-entry TTL MUST cover the full window the proof's `iat` would still be accepted
//! (`DPOP_PROOF_MAX_AGE_SEC` + clock tolerance), else a captured proof could be replayed after the
//! store forgot its `jti` but before the freshness check rejects it. The verifier always marks with
//! exactly that window.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Whether a `jti` was newly recorded or had already been seen within its window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkResult {
    /// First time this `jti` was seen within the window — a fresh proof.
    New,
    /// The `jti` was already present — a replay.
    Replay,
}

/// A backend error from a replay store (e.g. a shared Redis unreachable). The verifier's fail-closed
/// policy turns this into a 503; the in-memory implementation never produces one.
#[derive(Debug, thiserror::Error)]
#[error("replay store backend error: {0}")]
pub struct ReplayBackendError(pub String);

/// A replay-protection store. Implementations record each accepted DPoP proof's `jti` for a bounded
/// window; a subsequent mark of the same `jti` within that window resolves to [`MarkResult::Replay`].
///
/// `mark` is fallible to model a network backend (Redis); the in-memory impl never errors. The
/// fail-closed/fail-open decision belongs to the caller (the verifier), matching the TS seam.
pub trait ReplayStore: Send + Sync {
    /// Atomically record `jti` as seen for `ttl`. Returns [`MarkResult::New`] on the first sighting
    /// within the window, [`MarkResult::Replay`] otherwise.
    fn mark(&self, jti: &str, ttl: Duration) -> Result<MarkResult, ReplayBackendError>;
}

/// In-memory replay store (single-node v1). A `Mutex`-guarded map of `jti -> expiry` gives an
/// **atomic** check-and-set (Finding #3) and **never evicts a live `jti`** before its window closes
/// (Finding #2): expired entries are pruned lazily, and if the live set is at capacity a NEW `jti`
/// **fails closed** (a backend error → the verifier returns 503) rather than evicting security state.
///
/// Mirrors `InProcessReplayStore`'s security contract: an expired `jti` is treated as fresh again
/// (the proof's independent `iat` freshness bound re-rejects a genuinely stale proof). A strictly
/// atomic check-and-set across *processes* is the M2 shared (Redis `SET NX`) impl; this is correct
/// for one process.
pub struct InMemoryReplayStore {
    inner: Mutex<HashMap<String, Instant>>,
    max_entries: usize,
}

impl InMemoryReplayStore {
    /// Build a store capped at `max_entries` live `jti`s. `ttl` is supplied per-mark (the verifier
    /// always uses `max_age + tolerance`), so no construction-time TTL is needed.
    pub fn new(max_entries: usize, _ttl: Duration) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            max_entries,
        }
    }

    /// Default cap (100_000, matching the TS default). `ttl` is accepted for API symmetry.
    pub fn with_window(ttl: Duration) -> Self {
        Self::new(100_000, ttl)
    }

    /// Remove expired entries (lazy GC). Called under the lock at each mark.
    fn prune_expired(map: &mut HashMap<String, Instant>, now: Instant) {
        map.retain(|_, &mut expiry| expiry > now);
    }
}

impl ReplayStore for InMemoryReplayStore {
    fn mark(&self, jti: &str, ttl: Duration) -> Result<MarkResult, ReplayBackendError> {
        let now = Instant::now();
        let mut map = self
            .inner
            .lock()
            .map_err(|_| ReplayBackendError("replay store mutex poisoned".into()))?;

        // An existing, still-live entry → replay. (An expired entry is treated as fresh — pruned below.)
        if let Some(&expiry) = map.get(jti) {
            if expiry > now {
                return Ok(MarkResult::Replay);
            }
        }

        // Prune expired entries so live capacity reflects only entries still in their window.
        Self::prune_expired(&mut map, now);

        // A non-positive TTL means the proof is already past its window: treat as fresh and do not
        // store (the freshness check rejects it independently). Otherwise record.
        if ttl > Duration::ZERO {
            // Fail CLOSED at capacity (Finding #2): never evict a live `jti` to make room — that would
            // reopen the replay window. Refuse the new entry so the verifier returns 503; the operator
            // must scale the shared (Redis) store. The capacity is large (100k default) so this is an
            // overload signal, not a normal path.
            if !map.contains_key(jti) && map.len() >= self.max_entries {
                return Err(ReplayBackendError(
                    "replay store at capacity; refusing to evict live jti (fail-closed)".into(),
                ));
            }
            map.insert(jti.to_string(), now + ttl);
        }
        Ok(MarkResult::New)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_mark_is_new_second_is_replay() {
        let store = InMemoryReplayStore::with_window(Duration::from_secs(305));
        assert_eq!(
            store.mark("jti-1", Duration::from_secs(305)).unwrap(),
            MarkResult::New
        );
        assert_eq!(
            store.mark("jti-1", Duration::from_secs(305)).unwrap(),
            MarkResult::Replay
        );
    }

    #[test]
    fn distinct_jtis_are_independent() {
        let store = InMemoryReplayStore::with_window(Duration::from_secs(305));
        assert_eq!(
            store.mark("a", Duration::from_secs(305)).unwrap(),
            MarkResult::New
        );
        assert_eq!(
            store.mark("b", Duration::from_secs(305)).unwrap(),
            MarkResult::New
        );
    }

    #[test]
    fn expired_jti_is_fresh_again() {
        let store = InMemoryReplayStore::with_window(Duration::from_millis(20));
        assert_eq!(
            store.mark("e", Duration::from_millis(20)).unwrap(),
            MarkResult::New
        );
        std::thread::sleep(Duration::from_millis(60));
        // The expired entry is treated as fresh (its window closed); the proof's own iat check
        // independently rejects a genuinely stale proof.
        assert_eq!(
            store.mark("e", Duration::from_millis(20)).unwrap(),
            MarkResult::New
        );
    }

    #[test]
    fn nonpositive_ttl_is_fresh_not_stored() {
        let store = InMemoryReplayStore::with_window(Duration::from_secs(305));
        // ttl == 0 ⇒ already past window ⇒ fresh, and not remembered (so a second call is also fresh).
        assert_eq!(store.mark("z", Duration::ZERO).unwrap(), MarkResult::New);
        assert_eq!(store.mark("z", Duration::ZERO).unwrap(), MarkResult::New);
    }

    #[test]
    fn fails_closed_at_capacity_never_evicts_live_jti() {
        // Capacity 2, long TTL → after two live entries a third NEW jti must fail closed (Finding #2:
        // never evict a live jti to make room — that would reopen the replay window).
        let store = InMemoryReplayStore::new(2, Duration::from_secs(305));
        assert_eq!(
            store.mark("a", Duration::from_secs(305)).unwrap(),
            MarkResult::New
        );
        assert_eq!(
            store.mark("b", Duration::from_secs(305)).unwrap(),
            MarkResult::New
        );
        // A third distinct jti at capacity → error (verifier maps to 503).
        assert!(store.mark("c", Duration::from_secs(305)).is_err());
        // The earlier live entries are STILL remembered (not evicted) → replay still detected.
        assert_eq!(
            store.mark("a", Duration::from_secs(305)).unwrap(),
            MarkResult::Replay
        );
    }

    #[test]
    fn concurrent_same_jti_only_one_is_new() {
        use std::sync::Arc;
        // Atomic check-and-set (Finding #3): N threads racing the SAME jti → exactly one `New`.
        let store = Arc::new(InMemoryReplayStore::with_window(Duration::from_secs(305)));
        let mut handles = Vec::new();
        for _ in 0..16 {
            let s = Arc::clone(&store);
            handles.push(std::thread::spawn(move || {
                s.mark("race", Duration::from_secs(305)).unwrap()
            }));
        }
        let news = handles
            .into_iter()
            .filter(|_| true)
            .map(|h| h.join().unwrap())
            .filter(|r| *r == MarkResult::New)
            .count();
        assert_eq!(news, 1, "exactly one racer must win the jti");
    }

    /// A fail-closed test stub: a store that always errors. The verifier turns this into a 503.
    struct AlwaysErr;
    impl ReplayStore for AlwaysErr {
        fn mark(&self, _jti: &str, _ttl: Duration) -> Result<MarkResult, ReplayBackendError> {
            Err(ReplayBackendError("backend down".into()))
        }
    }

    #[test]
    fn backend_error_propagates() {
        let store = AlwaysErr;
        assert!(store.mark("x", Duration::from_secs(1)).is_err());
    }
}
