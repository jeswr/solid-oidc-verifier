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
//! The per-entry TTL MUST cover the full window the proof's `iat` would still be accepted, else a
//! captured proof could be replayed after the store forgot its `jti` but before the freshness check
//! rejects it. Because the freshness check is SYMMETRIC (`|now - iat| <= max_age + tolerance`), a
//! future-skewed-but-accepted proof stays replayable for `2 × (max_age + tolerance)` — and because that
//! check runs on INCLUSIVE integer seconds while this store expires on the sub-second monotonic clock,
//! the verifier marks with `2 × (max_age + tolerance) + 1` (the full window plus a +1s
//! inclusive-boundary safety margin — see [`crate::config::VerifierConfig::replay_ttl`]).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// The monotonic time source the in-memory store reads. This is an advanced seam: the default store
/// (`InMemoryReplayStore`) uses the real [`MonotonicClock`] (`Instant::now`), and you do NOT need to
/// implement this in normal use. It exists so a deterministic, manually-advanced clock can be injected
/// (e.g. in retention tests, avoiding scheduler-jitter-flaky sleeps). A MONOTONIC source is required —
/// the store keeps absolute expiry instants and compares `expiry > now`; a clock that can jump
/// backwards would be unsound here.
pub trait Clock: Send + Sync {
    fn now(&self) -> Instant;
}

/// The production clock: the real monotonic `Instant::now()`. Zero-sized, no overhead. This is the
/// default time source for [`InMemoryReplayStore`].
#[derive(Default)]
pub struct MonotonicClock;

impl Clock for MonotonicClock {
    #[inline]
    fn now(&self) -> Instant {
        Instant::now()
    }
}

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

    /// READ-ONLY existence probe: `Ok(true)` iff `jti` is currently recorded as seen (i.e. a replay of
    /// an already-marked, still-live `jti`), `Ok(false)` otherwise. An entry whose window has expired
    /// MUST read as `false` — consistent with [`mark`](ReplayStore::mark) treating an expired `jti` as
    /// fresh.
    ///
    /// 🔒 **INV-4 — `contains` is strictly READ-ONLY.** It MUST NOT mark, insert, refresh, evict, or
    /// otherwise mutate any replay state. The authoritative, atomic check-and-set is
    /// [`mark`](ReplayStore::mark), which remains the single source of truth and the only place a `jti`
    /// is recorded (the verifier calls it AFTER full DPoP + `cnf.jkt` validation). `contains` exists
    /// purely as an OPTIMIZATION: a consumer MAY probe it BEFORE the expensive signature/proof
    /// verification to reject an obvious replay early (parallel to, or ahead of, the crypto) — but it
    /// is NEVER the source of truth, and a positive [`mark`](ReplayStore::mark) is STILL REQUIRED after
    /// full validation. Because `contains` records nothing, two requests racing a fresh `jti` can both
    /// observe `false` here; only [`mark`](ReplayStore::mark)'s atomic check-and-set resolves the race
    /// (exactly one `New`). A backend implementing this MUST use a non-mutating read (e.g. a Redis
    /// `EXISTS`, never a `SET`).
    fn contains(&self, jti: &str) -> Result<bool, ReplayBackendError>;
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
pub struct InMemoryReplayStore<C: Clock = MonotonicClock> {
    inner: Mutex<HashMap<String, Instant>>,
    /// Live-entry cap, kept as `u64` for API stability (converted to `usize` internally). A NEW `jti`
    /// at capacity fails closed rather than evicting a live entry.
    max_entries: u64,
    /// The monotonic time source. Production is [`MonotonicClock`]; tests inject a deterministic one.
    clock: C,
}

impl InMemoryReplayStore<MonotonicClock> {
    /// Build a store capped at `max_entries` live `jti`s. `ttl` is supplied per-mark (the verifier
    /// always uses `max_age + tolerance`), so no construction-time TTL is needed.
    pub fn new(max_entries: u64, _ttl: Duration) -> Self {
        Self::with_clock(max_entries, MonotonicClock)
    }

    /// Default cap (100_000, matching the TS default). `ttl` is accepted for API symmetry.
    pub fn with_window(ttl: Duration) -> Self {
        Self::new(100_000, ttl)
    }
}

impl<C: Clock> InMemoryReplayStore<C> {
    /// Build a store over an explicit [`Clock`]. The default constructors ([`Self::new`] /
    /// [`Self::with_window`]) use the real [`MonotonicClock`]; this seam lets a deterministic,
    /// manually-advanced clock be injected so retention/TTL-boundary assertions are not at the mercy
    /// of CI scheduler jitter (and lets a downstream consumer drive expiry deterministically in its
    /// own tests). A MONOTONIC clock is required — the store keeps absolute expiry instants and
    /// compares `expiry > now`; a backwards-jumping clock would be unsound.
    pub fn with_clock(max_entries: u64, clock: C) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            max_entries,
            clock,
        }
    }

    /// The cap as a `usize` (saturating, so a `u64` larger than `usize::MAX` clamps rather than wraps).
    fn cap(&self) -> usize {
        usize::try_from(self.max_entries).unwrap_or(usize::MAX)
    }

    /// Remove expired entries (lazy GC). Called ONLY when the map is at/over capacity, so the common
    /// path is O(1), and the O(n) sweep amortises to once per ~capacity inserts (roborev round-2).
    fn prune_expired(map: &mut HashMap<String, Instant>, now: Instant) {
        map.retain(|_, &mut expiry| expiry > now);
    }
}

impl<C: Clock> ReplayStore for InMemoryReplayStore<C> {
    fn mark(&self, jti: &str, ttl: Duration) -> Result<MarkResult, ReplayBackendError> {
        let mut map = self
            .inner
            .lock()
            .map_err(|_| ReplayBackendError("replay store mutex poisoned".into()))?;
        // Sample the clock AFTER acquiring the lock (same reasoning as `contains`): under lock
        // contention a pre-lock `now` would be stale by the time the check-and-set runs, so an
        // expired entry could be mis-read as still live (false `Replay`) and a freshly stored
        // `now + ttl` expiry would be computed too early — shortening the retention window. Reading
        // `now` here evaluates expiry, and anchors the new entry's window, against the time the store
        // is actually mutated. (The check-and-set was already atomic under the lock; this only fixes
        // the timestamp it is evaluated against.)
        let now = self.clock.now();

        // An existing entry → replay if still live; if expired, treat as fresh and overwrite below.
        match map.get(jti) {
            Some(&expiry) if expiry > now => return Ok(MarkResult::Replay),
            _ => {}
        }

        // A non-positive TTL means the proof is already past its window: treat as fresh and do not
        // store (the freshness check rejects it independently). Otherwise record.
        if ttl > Duration::ZERO {
            let cap = self.cap();
            // Only sweep expired entries when we're about to exceed capacity (O(1) common path; the
            // O(n) prune amortises to ~once per `cap` inserts). A re-insert of an existing key never
            // grows the map, so it skips the capacity gate.
            if !map.contains_key(jti) && map.len() >= cap {
                Self::prune_expired(&mut map, now);
                // After pruning live-only, if STILL at capacity, fail CLOSED — never evict a live
                // `jti` to make room (that would reopen the replay window). The verifier returns 503;
                // the operator must scale the shared (Redis) store. With a 100k default this is an
                // overload signal, not a normal path.
                if map.len() >= cap {
                    return Err(ReplayBackendError(
                        "replay store at capacity; refusing to evict live jti (fail-closed)".into(),
                    ));
                }
            }
            map.insert(jti.to_string(), now + ttl);
        }
        Ok(MarkResult::New)
    }

    fn contains(&self, jti: &str) -> Result<bool, ReplayBackendError> {
        // INV-4: strictly READ-ONLY. We take the lock for a coherent snapshot under the same
        // monotonic clock as `mark`, but NEVER insert/remove/refresh — not even a lazy prune of the
        // probed entry. An expired entry reads as NOT contained (its `expiry > now` is false),
        // matching `mark`'s "an expired jti is fresh again" semantics; the dead entry is left for
        // `mark`'s at-capacity prune to reap, so `contains` has zero side effects.
        //
        // Sample the clock AFTER acquiring the lock so expiry is evaluated against the time the store
        // is ACTUALLY read, not when the call began. If `now` were read before the lock, a caller that
        // blocked on lock contention past an entry's expiry would compare against a STALE timestamp and
        // could report `true` for a `jti` that has already expired by the time the read happens —
        // violating the "expired reads as false" semantics and causing a spurious false-positive replay
        // rejection of a legitimate request.
        let map = self
            .inner
            .lock()
            .map_err(|_| ReplayBackendError("replay store mutex poisoned".into()))?;
        let now = self.clock.now();
        Ok(matches!(map.get(jti), Some(&expiry) if expiry > now))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    /// A deterministic, manually-advanced monotonic clock for retention tests. It reads a real base
    /// `Instant` once at construction, then reports `base + offset`; `advance` bumps `offset` with no
    /// sleeping. This removes ALL scheduler-jitter fragility from TTL-boundary assertions: time only
    /// moves when the test moves it. (Monotonic-safe — offset only ever increases.)
    struct FakeClock {
        base: Instant,
        offset: StdMutex<Duration>,
    }

    impl FakeClock {
        fn new() -> Self {
            Self {
                base: Instant::now(),
                offset: StdMutex::new(Duration::ZERO),
            }
        }
        fn advance(&self, by: Duration) {
            let mut o = self.offset.lock().unwrap();
            *o += by;
        }
    }

    impl Clock for FakeClock {
        fn now(&self) -> Instant {
            self.base + *self.offset.lock().unwrap()
        }
    }

    /// Helper: build an in-memory store driven by a shared deterministic clock.
    fn store_with(
        max_entries: u64,
        clock: std::sync::Arc<FakeClock>,
    ) -> InMemoryReplayStore<ArcClock> {
        InMemoryReplayStore::with_clock(max_entries, ArcClock(clock))
    }

    /// `Arc<FakeClock>` wrapper so the test can hold a handle to advance the clock while the store owns
    /// its own `Clock`.
    struct ArcClock(std::sync::Arc<FakeClock>);
    impl Clock for ArcClock {
        fn now(&self) -> Instant {
            self.0.now()
        }
    }

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
        // Deterministic (fake clock, no sleep): mark, advance well past the TTL, the entry is expired
        // and treated as fresh again (its window closed); the proof's own iat check independently
        // rejects a genuinely stale proof.
        let clock = std::sync::Arc::new(FakeClock::new());
        let store = store_with(100_000, std::sync::Arc::clone(&clock));
        let ttl = Duration::from_secs(20);
        assert_eq!(store.mark("e", ttl).unwrap(), MarkResult::New);
        clock.advance(Duration::from_secs(60));
        assert_eq!(store.mark("e", ttl).unwrap(), MarkResult::New);
    }

    #[test]
    fn jti_remembered_for_the_full_ttl_window() {
        // DETERMINISTIC retention test (Finding #2: no sleeps, no scheduler jitter). The verifier marks
        // with the full replay TTL; a future-skewed proof accepted now stays replayable across that
        // whole span, so the `jti` MUST remain marked for it. We drive a fake clock so time only moves
        // when we move it — the TTL boundary is then exact, not "≈ a sleep that CI might overshoot".
        //
        // Use a 100s TTL purely as a unit. The store remembers a jti while `expiry > now`, i.e. for
        // strictly less than the TTL after marking. We assert: just before the boundary → Replay; just
        // after → New (forgotten). A mutation shrinking the stored TTL makes the pre-boundary check a
        // false `New` and fails the test.
        let clock = std::sync::Arc::new(FakeClock::new());
        let store = store_with(100_000, std::sync::Arc::clone(&clock));
        let ttl = Duration::from_secs(100);

        assert_eq!(store.mark("f", ttl).unwrap(), MarkResult::New);

        // Advance to 1s BEFORE the TTL boundary (well past where the OLD one-sided 50s horizon would
        // have forgotten it): the entry is still live → replay.
        clock.advance(Duration::from_secs(99));
        assert_eq!(
            store.mark("f", ttl).unwrap(),
            MarkResult::Replay,
            "the jti must still be remembered for the entire TTL window — the replay-TTL hole"
        );

        // Advance just PAST the original 100s boundary: `expiry > now` is now false → forgotten → New.
        // (The first mark's expiry was at now=0 + 100s; we're now at 99s + 2s = 101s.)
        clock.advance(Duration::from_secs(2));
        assert_eq!(
            store.mark("f", ttl).unwrap(),
            MarkResult::New,
            "past the full TTL window the jti is forgotten (the proof's own iat check then rejects it)"
        );
    }

    #[test]
    fn fake_clock_drives_expiry_exactly_at_the_boundary() {
        // Pin the exact `expiry > now` boundary deterministically: at TTL-ε still a replay, at TTL+ε
        // forgotten. This is the boundary mutation-check for the retention semantics — no timing slack.
        let clock = std::sync::Arc::new(FakeClock::new());
        let store = store_with(100_000, std::sync::Arc::clone(&clock));
        let ttl = Duration::from_secs(60);
        assert_eq!(store.mark("b", ttl).unwrap(), MarkResult::New);
        // expiry = base + 60s. Move to base + 60s − 1ns → still live (expiry strictly greater).
        clock.advance(ttl - Duration::from_nanos(1));
        assert_eq!(store.mark("b", ttl).unwrap(), MarkResult::Replay);
        // Move to base + 60s + 1ns → expired (expiry no longer > now) → forgotten.
        clock.advance(Duration::from_nanos(2));
        assert_eq!(store.mark("b", ttl).unwrap(), MarkResult::New);
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
    fn capacity_prune_frees_expired_entries() {
        // Capacity 2, short TTL. Fill to capacity, advance past expiry (deterministic — no sleep), then
        // a NEW jti at capacity must succeed (the at-capacity prune frees the expired ghosts) — a legit
        // high-volume client is not blocked by dead entries (roborev round-2 Medium: prune at capacity,
        // not every call).
        let clock = std::sync::Arc::new(FakeClock::new());
        let store = store_with(2, std::sync::Arc::clone(&clock));
        let ttl = Duration::from_secs(20);
        assert_eq!(store.mark("a", ttl).unwrap(), MarkResult::New);
        assert_eq!(store.mark("b", ttl).unwrap(), MarkResult::New);
        clock.advance(Duration::from_secs(60)); // both expire
                                                // At capacity by count, but both are expired → the prune frees them → this succeeds.
        assert_eq!(store.mark("c", ttl).unwrap(), MarkResult::New);
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

    #[test]
    fn contains_is_false_for_unseen_jti() {
        let store = InMemoryReplayStore::with_window(Duration::from_secs(305));
        assert!(
            !store.contains("never-seen").unwrap(),
            "an unmarked jti is not contained"
        );
    }

    #[test]
    fn contains_is_true_after_mark() {
        let store = InMemoryReplayStore::with_window(Duration::from_secs(305));
        assert_eq!(
            store.mark("seen", Duration::from_secs(305)).unwrap(),
            MarkResult::New
        );
        assert!(
            store.contains("seen").unwrap(),
            "a marked, still-live jti is contained (a replay)"
        );
    }

    #[test]
    fn contains_is_false_after_expiry() {
        // Deterministic (fake clock): mark, advance past the TTL window, contains() must read false —
        // an expired jti is NOT contained, mirroring `mark` treating it as fresh again.
        let clock = std::sync::Arc::new(FakeClock::new());
        let store = store_with(100_000, std::sync::Arc::clone(&clock));
        let ttl = Duration::from_secs(20);
        assert_eq!(store.mark("g", ttl).unwrap(), MarkResult::New);
        assert!(store.contains("g").unwrap(), "live jti is contained");
        clock.advance(Duration::from_secs(60));
        assert!(
            !store.contains("g").unwrap(),
            "an expired jti reads as NOT contained"
        );
    }

    #[test]
    fn contains_does_not_mark_so_next_mark_is_new() {
        // INV-4: contains() is read-only. A contains() probe of a fresh jti must NOT record it, so a
        // subsequent mark() of the SAME jti still sees it as New (the contains did not insert).
        let store = InMemoryReplayStore::with_window(Duration::from_secs(305));
        assert!(
            !store.contains("probe-then-mark").unwrap(),
            "fresh jti not yet contained"
        );
        // Probe it repeatedly — still must not record anything.
        assert!(!store.contains("probe-then-mark").unwrap());
        assert!(!store.contains("probe-then-mark").unwrap());
        // The authoritative mark must STILL see New — proving contains() never inserted.
        assert_eq!(
            store
                .mark("probe-then-mark", Duration::from_secs(305))
                .unwrap(),
            MarkResult::New,
            "contains() must not mark — the subsequent fresh mark must be New, not Replay"
        );
        // And NOW it is contained (because mark recorded it).
        assert!(store.contains("probe-then-mark").unwrap());
    }

    #[test]
    fn contains_then_mark_pre_check_optimization_flow() {
        // Models the consumer's intended pre-check: contains() is the cheap probe, mark() is the
        // authoritative source of truth. First request: contains()==false (not a known replay), then
        // mark()==New. Replay request: contains()==true (early-reject signal) AND mark()==Replay
        // (the authoritative confirmation). The two never diverge for an already-marked jti.
        let store = InMemoryReplayStore::with_window(Duration::from_secs(305));
        let ttl = Duration::from_secs(305);

        // First sighting.
        assert!(!store.contains("flow").unwrap());
        assert_eq!(store.mark("flow", ttl).unwrap(), MarkResult::New);

        // Replay sighting: the cheap probe agrees with the authoritative mark.
        assert!(
            store.contains("flow").unwrap(),
            "pre-check sees the known replay"
        );
        assert_eq!(
            store.mark("flow", ttl).unwrap(),
            MarkResult::Replay,
            "authoritative mark confirms the replay"
        );
    }

    #[test]
    fn concurrent_contains_and_mark_are_consistent() {
        use std::sync::Arc;
        // Concurrency: N threads each probe-then-mark the SAME jti. contains() is racy by design (it
        // records nothing), so several probers may see false — but the AUTHORITATIVE mark()'s atomic
        // check-and-set must still admit EXACTLY ONE New, and every contains() result must be a clean
        // boolean (no panic / lock poison). The invariant under test is mark()'s atomicity holding
        // while contains() runs concurrently against the same lock.
        let store = Arc::new(InMemoryReplayStore::with_window(Duration::from_secs(305)));
        let mut handles = Vec::new();
        for _ in 0..16 {
            let s = Arc::clone(&store);
            handles.push(std::thread::spawn(move || {
                // probe (read-only) then the authoritative mark
                let _ = s.contains("c-race").unwrap();
                s.mark("c-race", Duration::from_secs(305)).unwrap()
            }));
        }
        let news = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|r| *r == MarkResult::New)
            .count();
        assert_eq!(
            news, 1,
            "exactly one racer wins the jti even with concurrent contains() probes"
        );
        // After the storm, the jti is contained exactly once-and-for-all.
        assert!(store.contains("c-race").unwrap());
    }

    #[test]
    fn contains_samples_clock_after_lock_so_expiry_under_contention_reads_false() {
        use std::sync::Arc;
        // Pins the stale-now fix: `contains()` MUST sample the clock AFTER acquiring the mutex, so an
        // entry that expires WHILE the prober is blocked on lock contention reads as `false` (not a
        // spurious false-positive replay). We reproduce "blocked past expiry" deterministically: the
        // test thread holds the store's lock, the prober thread calls `contains()` and parks on
        // `inner.lock()`, we advance the fake clock past the entry's expiry WHILE it is parked, then
        // release the lock. Because `now` is read after the lock is acquired, the prober evaluates
        // expiry against the ADVANCED (post-expiry) time → `false`.
        //
        // Mutation-check: revert the fix (read `now` before `inner.lock()`) and the prober samples the
        // pre-advance time (still within the window) → `true` → this assertion fails.
        let clock = Arc::new(FakeClock::new());
        let store = Arc::new(store_with(100_000, Arc::clone(&clock)));
        let ttl = Duration::from_secs(20);
        assert_eq!(store.mark("contended", ttl).unwrap(), MarkResult::New);
        assert!(
            store.contains("contended").unwrap(),
            "the entry is live before any contention"
        );

        // Hold the store's lock so the prober must block on `inner.lock()`.
        let guard = store.inner.lock().unwrap();

        let probe_store = Arc::clone(&store);
        let prober = std::thread::spawn(move || probe_store.contains("contended").unwrap());

        // Give the prober time to actually reach (and park on) `inner.lock()`. Then advance the clock
        // PAST the entry's expiry — simulating the wall-clock moving on while the call is blocked.
        std::thread::sleep(std::time::Duration::from_millis(50));
        clock.advance(Duration::from_secs(60));

        // Release the lock; the prober now acquires it and (post-fix) samples the advanced clock.
        drop(guard);

        let observed = prober.join().unwrap();
        assert!(
            !observed,
            "a contains() probe whose lock acquisition is delayed past the entry's expiry must read \
             false — the clock is sampled after the lock, not before"
        );
    }

    /// A fail-closed test stub: a store that always errors. The verifier turns this into a 503.
    struct AlwaysErr;
    impl ReplayStore for AlwaysErr {
        fn mark(&self, _jti: &str, _ttl: Duration) -> Result<MarkResult, ReplayBackendError> {
            Err(ReplayBackendError("backend down".into()))
        }
        fn contains(&self, _jti: &str) -> Result<bool, ReplayBackendError> {
            Err(ReplayBackendError("backend down".into()))
        }
    }

    #[test]
    fn backend_error_propagates() {
        let store = AlwaysErr;
        assert!(store.mark("x", Duration::from_secs(1)).is_err());
    }
}
