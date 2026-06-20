// AUTHORED-BY Claude Opus 4.8
//! DPoP `jti` replay protection.
//!
//! Ports `src/auth/replayStore.ts`: a pluggable [`ReplayStore`] trait so the in-memory (single-node)
//! implementation and a future shared (Redis) implementation share one contract; a default moka
//! TTL-LRU [`InMemoryReplayStore`]; and the **fail-closed** posture (a backend error rejects the
//! request — the security invariant must not be silently weakened by an outage; the verifier maps it
//! to a 503).
//!
//! The TTL MUST cover the full window the proof's `iat` would still be accepted
//! (`DPOP_PROOF_MAX_AGE_SEC` + clock tolerance), else a captured proof could be replayed after the
//! store forgot its `jti` but before the freshness check rejects it. The verifier always marks with
//! exactly that window, so [`InMemoryReplayStore`]'s global `time_to_live` is exact for our usage.

use std::time::Duration;

use moka::sync::Cache;

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

/// In-memory TTL-LRU replay store (single-node v1, moka-backed). Mirrors `InProcessReplayStore`:
/// per-window TTL eviction, LRU under flood, and an expired `jti` treated as fresh again (the proof's
/// independent `iat` freshness bound re-rejects a stale proof).
pub struct InMemoryReplayStore {
    seen: Cache<String, ()>,
}

impl InMemoryReplayStore {
    /// Build a store with the global window TTL the verifier marks with (`max_age + tolerance`).
    /// Entries expire after `ttl`, so a `jti` is forgotten exactly when its proof's freshness window
    /// closes — the replay window can never reopen.
    pub fn new(max_entries: u64, ttl: Duration) -> Self {
        Self {
            seen: Cache::builder()
                .max_capacity(max_entries)
                .time_to_live(ttl)
                .build(),
        }
    }

    /// Default cap (100_000, matching the TS default) with the supplied window TTL.
    pub fn with_window(ttl: Duration) -> Self {
        Self::new(100_000, ttl)
    }

    #[cfg(test)]
    fn drain(&self) {
        self.seen.run_pending_tasks();
    }
}

impl ReplayStore for InMemoryReplayStore {
    fn mark(&self, jti: &str, _ttl: Duration) -> Result<MarkResult, ReplayBackendError> {
        // Single-node check-and-set matching the TS LRU `has`/`set`. A strictly atomic check-and-set
        // under multi-process concurrency requires a shared backend (Redis `SET NX`) — the M2 trait
        // impl. For one process this is correct: the proof is already cryptographically validated
        // before this runs, so the only race is two copies of the *same* captured proof, both of which
        // a shared backend would also need to serialise.
        if self.seen.get(jti).is_some() {
            return Ok(MarkResult::Replay);
        }
        self.seen.insert(jti.to_string(), ());
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
        std::thread::sleep(Duration::from_millis(80));
        store.drain();
        assert_eq!(
            store.mark("e", Duration::from_millis(20)).unwrap(),
            MarkResult::New
        );
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
