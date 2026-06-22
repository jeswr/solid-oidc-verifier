// AUTHORED-BY Claude Opus 4.8
//! SSRF public-address classification — a faithful port of the resource server's
//! `packages/guarded-fetch/src/addresses.ts` (itself the stricter copy from `webidResolver.ts`).
//!
//! Refuses: loopback, link-local, IPv4 private (RFC 1918), CGNAT (RFC 6598), IPv4 reserved/test
//! ranges, multicast, broadcast, `0.0.0.0/8`, IPv4-mapped IPv6, IPv6 ULA (`fc00::/7`), IPv6
//! unspecified, **6to4 (`2002::/16`) embedding a private v4**, and **NAT64 (RFC 6052) embedding a
//! private v4 at the IANA well-known prefix `64:ff9b::/96`**.
//!
//! ## Operator-configured NAT64 NSP allowlist (opt-in, default-OFF)
//!
//! Operator-defined NAT64 Network-Specific Prefixes (NSPs) are deliberately NOT matched
//! *speculatively*: their layout (RFC 6052 §2.2) has no globally-known structural discriminator, so
//! reading a private v4 out of every address that *could* be an NSP embedding would false-block
//! legitimate sparse global IPv6. So by default ([`Nat64Policy::default`] / [`is_public_address`])
//! only the IANA well-known `/96` is decoded — behaviour identical to before this allowlist existed.
//!
//! When an operator KNOWS they run a custom NSP, they can opt in by supplying it via
//! [`Nat64Policy`] (mirroring the existing `allow_loopback` config seam). For a v6 address that falls
//! under a *configured* NSP, the classifier DECODES the embedded IPv4 (RFC 6052 §2.2 bit layout — the
//! v4 straddles the reserved "u" octet at bits 64–71) and classifies on THAT v4, so an embedded
//! private/loopback/link-local v4 (e.g. `<nsp>:169.254.169.254`) is still rejected. This closes the
//! M2 SSRF-audit NAT64-NSP Low for operators that run an NSP, without re-introducing the false-block
//! risk for everyone else.
//!
//! **Fail-closed:** an address that does NOT fall under the well-known prefix OR any configured NSP
//! is classified by its raw IPv6 form (no silent allow). A configured NSP only ever makes the guard
//! *stricter* (it can decode-and-reject an embedded private v4); it never relaxes classification of
//! an address that wasn't already public, because a decoded *public* embedded v4 still had to pass
//! the full IPv4 classifier.
//!
//! `allow_loopback` re-permits loopback only (dev / IT).
//!
//! The verifier's WebID resolution uses this to refuse a profile URL that resolves to a non-public
//! address (the DNS-rebinding + private-network guard, TS risk R5). M1 implements the classifier (the
//! load-bearing security logic) and the per-record check; the DNS-pinning fetch/connector is the M2
//! network adapter behind the [`crate::webid::WebIdResolver`] trait.

use std::net::{Ipv4Addr, Ipv6Addr};

/// A single operator-configured NAT64 Network-Specific Prefix (RFC 6052 §2.2). Constructed from a
/// prefix IPv6 address + a prefix length the RFC permits for embedding (`32, 40, 48, 56, 64, 96`).
/// An address that falls under this prefix has its embedded IPv4 decoded and re-classified.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Nat64Nsp {
    /// The prefix's high segments, masked to `prefix_len` bits (so equality + matching are exact).
    masked: [u16; 8],
    /// The prefix length in bits — one of the RFC 6052 §2.2 embedding lengths.
    prefix_len: u8,
}

/// Failure parsing an operator-supplied NAT64 NSP (bad address, or a length RFC 6052 §2.2 forbids).
#[derive(Debug, thiserror::Error)]
#[error("invalid NAT64 NSP: {0}")]
pub struct Nat64NspError(pub String);

impl Nat64Nsp {
    /// The prefix lengths RFC 6052 §2.2 defines for IPv4 embedding. The well-known `64:ff9b::/96` is
    /// the `/96` member and is handled separately (always-on), but a `/96` NSP is still accepted here.
    const VALID_LENGTHS: [u8; 6] = [32, 40, 48, 56, 64, 96];

    /// Parse an operator NSP from `"<ipv6-prefix>/<len>"` (e.g. `"64:ff9b:1::/48"`). The length must be
    /// one of the RFC 6052 §2.2 embedding lengths. Bits below the prefix length are masked to zero so
    /// matching is exact and two equivalent CIDR spellings compare equal.
    pub fn parse(cidr: &str) -> Result<Self, Nat64NspError> {
        let (addr_str, len_str) = cidr
            .split_once('/')
            .ok_or_else(|| Nat64NspError(format!("expected `<ipv6>/<len>` form, got `{cidr}`")))?;
        let prefix_len: u8 = len_str
            .trim()
            .parse()
            .map_err(|_| Nat64NspError(format!("prefix length is not a number: `{len_str}`")))?;
        let addr: Ipv6Addr = addr_str
            .trim()
            .parse()
            .map_err(|_| Nat64NspError(format!("prefix is not an IPv6 address: `{addr_str}`")))?;
        Self::new(addr, prefix_len)
    }

    /// Build an NSP from a prefix address + length, masking off the host bits. Rejects a length that is
    /// not an RFC 6052 §2.2 embedding length.
    pub fn new(prefix: Ipv6Addr, prefix_len: u8) -> Result<Self, Nat64NspError> {
        if !Self::VALID_LENGTHS.contains(&prefix_len) {
            return Err(Nat64NspError(format!(
                "prefix length /{prefix_len} is not an RFC 6052 §2.2 embedding length (one of 32/40/48/56/64/96)"
            )));
        }
        let masked = mask_segments(prefix.segments(), prefix_len);
        Ok(Self { masked, prefix_len })
    }

    /// If `segments` falls under this NSP, decode + return the embedded IPv4 (RFC 6052 §2.2). `None`
    /// when the address is not under this prefix.
    fn embedded_v4(&self, segments: &[u16; 8]) -> Option<Ipv4Addr> {
        if mask_segments(*segments, self.prefix_len) != self.masked {
            return None;
        }
        Some(decode_embedded_v4(segments, self.prefix_len))
    }
}

/// Mask an IPv6 segment array to its top `prefix_len` bits, zeroing the rest. Used so an NSP compares
/// + matches exactly regardless of host-bit spelling.
fn mask_segments(mut segments: [u16; 8], prefix_len: u8) -> [u16; 8] {
    let mut bits_remaining = prefix_len as i32;
    for seg in segments.iter_mut() {
        if bits_remaining >= 16 {
            bits_remaining -= 16;
        } else if bits_remaining <= 0 {
            *seg = 0;
        } else {
            let keep = bits_remaining as u32;
            let mask: u16 = (!0u16) << (16 - keep);
            *seg &= mask;
            bits_remaining = 0;
        }
    }
    segments
}

/// Decode the IPv4 embedded by an RFC 6052 §2.2 NAT64 prefix of the given length. The 32-bit v4 is laid
/// out STARTING at `prefix_len` and SKIPPING bits 64–71 (the reserved "u" octet, which is always zero),
/// per the RFC's table. We read it bit-exactly out of the 128-bit address so every defined length
/// (`/32../96`) decodes correctly, including the `u`-octet straddle (e.g. `/40../56`).
fn decode_embedded_v4(segments: &[u16; 8], prefix_len: u8) -> Ipv4Addr {
    let bits = ((segments[0] as u128) << 112)
        | ((segments[1] as u128) << 96)
        | ((segments[2] as u128) << 80)
        | ((segments[3] as u128) << 64)
        | ((segments[4] as u128) << 48)
        | ((segments[5] as u128) << 32)
        | ((segments[6] as u128) << 16)
        | (segments[7] as u128);
    // Read 32 v4 bits starting at `prefix_len`, skipping the reserved bits 64..72.
    let mut v4: u32 = 0;
    let mut taken = 0u32;
    let mut pos = prefix_len as u32;
    while taken < 32 {
        if (64..72).contains(&pos) {
            pos = 72; // skip the reserved "u" octet (RFC 6052 §2.2)
            continue;
        }
        let bit = ((bits >> (127 - pos)) & 1) as u32;
        v4 = (v4 << 1) | bit;
        taken += 1;
        pos += 1;
    }
    Ipv4Addr::from(v4)
}

/// The classifier's NAT64 policy: the operator-configured NSP allowlist (default empty = OFF). The
/// IANA well-known `64:ff9b::/96` is ALWAYS decoded regardless of this list (it is part of the strict
/// baseline); this list adds operator-specific prefixes. Mirrors the `allow_loopback` config seam:
/// default-OFF, opt-in only.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Nat64Policy {
    nsps: Vec<Nat64Nsp>,
}

impl Nat64Policy {
    /// The default strict policy: no operator NSPs configured (only the well-known `/96` is decoded).
    pub fn strict() -> Self {
        Self::default()
    }

    /// Build a policy from already-parsed NSPs.
    pub fn with_nsps(nsps: Vec<Nat64Nsp>) -> Self {
        Self { nsps }
    }

    /// Parse a policy from a list of `<ipv6>/<len>` CIDR strings (operator config). An empty list
    /// yields the strict default. Any malformed entry fails the whole parse (fail-closed config).
    pub fn from_cidrs<I, S>(cidrs: I) -> Result<Self, Nat64NspError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let nsps = cidrs
            .into_iter()
            .map(|c| Nat64Nsp::parse(c.as_ref()))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { nsps })
    }

    /// Whether any operator NSP is configured.
    pub fn is_empty(&self) -> bool {
        self.nsps.is_empty()
    }

    /// If `segments` falls under a configured NSP, decode + return the embedded v4. The first matching
    /// NSP wins (operators should not configure overlapping prefixes). `None` ⇒ no configured NSP
    /// matches, so the caller keeps the strict (well-known-/96-only) classification.
    fn embedded_v4(&self, segments: &[u16; 8]) -> Option<Ipv4Addr> {
        self.nsps.iter().find_map(|nsp| nsp.embedded_v4(segments))
    }
}

/// Classify an IPv4/IPv6 literal as public. Returns `false` for any non-public range, malformed
/// input, or a non-IP string. `allow_loopback` re-permits loopback (127/8, ::1, mapped 127.x) only.
/// Mirrors `isPublicAddress`.
///
/// This uses the STRICT NAT64 policy (only the IANA well-known `64:ff9b::/96` is decoded). To honour
/// an operator-configured NAT64 NSP allowlist, use [`is_public_address_with_nat64`].
pub fn is_public_address(address: &str, allow_loopback: bool) -> bool {
    is_public_address_with_nat64(address, allow_loopback, &Nat64Policy::strict())
}

/// Classify an IPv4/IPv6 literal as public, honouring an operator-configured NAT64 NSP allowlist (in
/// addition to the always-on well-known `/96`). For a v6 address under a configured NSP the embedded
/// IPv4 is decoded and classified on; an unmatched address keeps its raw-IPv6 classification
/// (fail-closed). With [`Nat64Policy::strict`] (the default), behaviour is identical to
/// [`is_public_address`].
pub fn is_public_address_with_nat64(
    address: &str,
    allow_loopback: bool,
    nat64: &Nat64Policy,
) -> bool {
    if let Ok(v4) = address.parse::<Ipv4Addr>() {
        return is_public_ipv4(v4, allow_loopback);
    }
    if let Ok(v6) = address.parse::<Ipv6Addr>() {
        return is_public_ipv6(v6, allow_loopback, nat64);
    }
    false
}

/// Whether `address` is loopback (127/8, ::1, or IPv4-mapped ::ffff:127.x.x.x). Mirrors
/// `isLoopbackAddress`.
pub fn is_loopback_address(address: &str) -> bool {
    if let Ok(v4) = address.parse::<Ipv4Addr>() {
        return v4.octets()[0] == 127;
    }
    if let Ok(v6) = address.parse::<Ipv6Addr>() {
        if v6 == Ipv6Addr::LOCALHOST {
            return true;
        }
        // IPv4-mapped ::ffff:a.b.c.d
        if let Some(v4) = v6.to_ipv4_mapped() {
            return v4.octets()[0] == 127;
        }
    }
    false
}

fn is_public_ipv4(addr: Ipv4Addr, allow_loopback: bool) -> bool {
    let [a, b, c, _d] = addr.octets();
    if a == 0 {
        return false; // 0.0.0.0/8
    }
    if a == 127 {
        return allow_loopback;
    }
    if a == 10 {
        return false; // RFC 1918
    }
    if a == 172 && (16..=31).contains(&b) {
        return false; // RFC 1918
    }
    if a == 192 && b == 168 {
        return false; // RFC 1918
    }
    if a == 169 && b == 254 {
        return false; // Link-local
    }
    if a == 100 && (64..=127).contains(&b) {
        return false; // CGNAT 100.64.0.0/10
    }
    if (224..=239).contains(&a) {
        return false; // Multicast 224.0.0.0/4
    }
    if a >= 240 {
        return false; // Reserved / broadcast
    }
    if a == 192 && b == 0 && c == 2 {
        return false; // TEST-NET-1
    }
    if a == 198 && (b == 18 || b == 19) {
        return false; // Benchmarking
    }
    if a == 198 && b == 51 && c == 100 {
        return false; // TEST-NET-2
    }
    if a == 203 && b == 0 && c == 113 {
        return false; // TEST-NET-3
    }
    true
}

fn is_public_ipv6(addr: Ipv6Addr, allow_loopback: bool, nat64: &Nat64Policy) -> bool {
    // Loopback ::1
    if addr == Ipv6Addr::LOCALHOST {
        return allow_loopback;
    }
    // Unspecified ::
    if addr == Ipv6Addr::UNSPECIFIED {
        return false;
    }
    let segments = addr.segments();

    // IPv4-mapped ::ffff:a.b.c.d — classify per the embedded v4. Covers compressed AND expanded forms
    // (std's `to_ipv4_mapped` checks the [0,0,0,0,0,ffff] prefix exactly).
    if let Some(v4) = addr.to_ipv4_mapped() {
        return is_public_ipv4(v4, allow_loopback);
    }

    // IPv4-COMPATIBLE ::a.b.c.d (deprecated, RFC 4291 ::/96): segments[0..6] all zero, last 32 bits a
    // v4. NOT caught by `to_ipv4_mapped` (which requires the ::ffff: prefix), so without this an
    // address like `::10.0.0.1` would classify as public. `::1`/`::` are already handled above, so any
    // remaining all-zero-high address carries a non-trivial embedded v4 — classify per it.
    if segments[0..6].iter().all(|&s| s == 0) {
        let v4 = Ipv4Addr::new(
            (segments[6] >> 8) as u8,
            (segments[6] & 0xff) as u8,
            (segments[7] >> 8) as u8,
            (segments[7] & 0xff) as u8,
        );
        return is_public_ipv4(v4, allow_loopback);
    }

    let high = segments[0];

    // fe80::/10 link-local
    if (high & 0xffc0) == 0xfe80 {
        return false;
    }
    // fc00::/7 unique-local
    if (high & 0xfe00) == 0xfc00 {
        return false;
    }
    // ff00::/8 multicast
    if (high & 0xff00) == 0xff00 {
        return false;
    }
    // 2002::/16 6to4 — encodes a v4 in segments[1..3]. This is a recognized transition mechanism, so
    // it is FULLY classified by its embedded v4 (and is terminal — we must not also run the
    // speculative NAT64-NSP framing on it, which would mis-read the zero-filled low half).
    if high == 0x2002 {
        let v4 = Ipv4Addr::new(
            (segments[1] >> 8) as u8,
            (segments[1] & 0xff) as u8,
            (segments[2] >> 8) as u8,
            (segments[2] & 0xff) as u8,
        );
        return is_public_ipv4(v4, allow_loopback);
    }
    // NAT64 (RFC 6052) — the IANA **well-known** prefix `64:ff9b::/96` ONLY. It embeds a 32-bit
    // IPv4 in the last two segments, so an attacker could smuggle a private/loopback v4
    // (169.254/16, 127/8, 10/8, …) inside `64:ff9b::<priv-v4>` to slip past IPv6 classification —
    // we extract that v4 and reject if it is non-public. The well-known prefix is a fixed, globally
    // known value, so this check is exact and cannot over-block.
    //
    // Operator-defined Network-Specific Prefixes (NSPs) at the shorter §2.2 lengths
    // (/32../64) are deliberately NOT *speculatively* matched. We do not know the operator's NSP, and
    // RFC 6052 §2.2's only structural invariants (a zero reserved "u" octet + a zero suffix) are
    // ALSO satisfied by ordinary sparse global-unicast IPv6 allocations — so reading a candidate
    // v4 out of every such address would FALSE-BLOCK legitimate IPv6 whose interpreted candidate
    // merely happens to land in a private range (e.g. `2001:db8:a00:1::`, a valid global address,
    // would be read as embedding 10.0.0.1 under the /32 framing). The SSRF guard must never refuse
    // a legitimate public address, so by default we check only the well-known /96. An operator that
    // KNOWS it runs a custom NSP can opt in to decoding it via the `nat64` policy (handled below),
    // which is exact for that operator's configured prefix and so cannot over-block.
    if let Some(v4) = nat64_well_known_embedded_v4(&segments) {
        // The well-known prefix is fixed + globally known, so this is exact + terminal: classify
        // strictly on the embedded v4 (it cannot also be an operator NSP).
        return is_public_ipv4(v4, allow_loopback);
    }

    // OPERATOR-CONFIGURED NAT64 NSP allowlist (opt-in, default-OFF). The strict default policy is
    // empty, so this is a no-op unless an operator has supplied one or more NSPs — preserving the
    // pre-allowlist behaviour exactly. For an address that falls under a configured NSP we decode the
    // embedded v4 (RFC 6052 §2.2) and classify on it, so an embedded private/loopback/link-local v4
    // is rejected. An address that matches NO configured NSP (and not the well-known /96) keeps its
    // raw-IPv6 classification below — fail-closed, no silent allow. Note the asymmetry that makes this
    // safe: a matched NSP can only ever cause a REJECT here (a public embedded v4 still had to pass the
    // full IPv4 classifier and then we fall through to `true` exactly as a non-NAT64 v6 would), so a
    // misconfigured NSP can never widen what is accepted beyond the raw-IPv6 verdict.
    if let Some(v4) = nat64.embedded_v4(&segments) {
        if !is_public_ipv4(v4, allow_loopback) {
            return false;
        }
    }
    true
}

/// Extract the IPv4 embedded by the **well-known** NAT64 prefix `64:ff9b::/96` (RFC 6052 §2.1):
/// segments `[64, ff9b, 0, 0, 0, 0]` then a 32-bit v4 in the last two segments. Returns `None` when
/// the address is not under that exact prefix.
fn nat64_well_known_embedded_v4(segments: &[u16; 8]) -> Option<Ipv4Addr> {
    if segments[0] == 0x0064
        && segments[1] == 0xff9b
        && segments[2] == 0
        && segments[3] == 0
        && segments[4] == 0
        && segments[5] == 0
    {
        return Some(Ipv4Addr::new(
            (segments[6] >> 8) as u8,
            (segments[6] & 0xff) as u8,
            (segments[7] >> 8) as u8,
            (segments[7] & 0xff) as u8,
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_public_ipv4() {
        assert!(is_public_address("8.8.8.8", false));
        assert!(is_public_address("1.1.1.1", false));
        assert!(is_public_address("203.0.114.5", false)); // not TEST-NET-3 (that is .113)
    }

    #[test]
    fn rejects_private_and_reserved_ipv4() {
        assert!(!is_public_address("10.0.0.1", false));
        assert!(!is_public_address("192.168.1.1", false));
        assert!(!is_public_address("172.20.0.1", false));
        assert!(!is_public_address("169.254.1.1", false)); // link-local
        assert!(!is_public_address("100.64.0.1", false)); // CGNAT
        assert!(!is_public_address("0.0.0.0", false));
        assert!(!is_public_address("224.0.0.1", false)); // multicast
        assert!(!is_public_address("255.255.255.255", false)); // broadcast
        assert!(!is_public_address("192.0.2.1", false)); // TEST-NET-1
        assert!(!is_public_address("198.18.0.1", false)); // benchmarking
        assert!(!is_public_address("198.51.100.1", false)); // TEST-NET-2
        assert!(!is_public_address("203.0.113.1", false)); // TEST-NET-3
    }

    #[test]
    fn loopback_default_vs_allowed() {
        assert!(!is_public_address("127.0.0.1", false));
        assert!(is_public_address("127.0.0.1", true));
        assert!(!is_public_address("::1", false));
        assert!(is_public_address("::1", true));
    }

    #[test]
    fn accepts_public_ipv6() {
        assert!(is_public_address("2606:4700:4700::1111", false)); // cloudflare
    }

    #[test]
    fn rejects_ula_and_multicast_ipv6() {
        assert!(!is_public_address("fd00::1", false)); // ULA
        assert!(!is_public_address("fe80::1", false)); // link-local
        assert!(!is_public_address("ff02::1", false)); // multicast
        assert!(!is_public_address("::", false)); // unspecified
    }

    #[test]
    fn rejects_ipv4_mapped_private_v6() {
        assert!(!is_public_address("::ffff:10.0.0.1", false));
        assert!(!is_public_address("::ffff:127.0.0.1", false));
        // expanded form
        assert!(!is_public_address("0:0:0:0:0:ffff:0a00:0001", false)); // = 10.0.0.1
    }

    #[test]
    fn rejects_ipv4_compatible_private_v6() {
        // Deprecated RFC 4291 ::a.b.c.d (IPv4-COMPATIBLE, not ::ffff:) — NOT caught by to_ipv4_mapped.
        // Classified per the embedded v4 so an internal target can't slip through (SSRF audit Low).
        assert!(!is_public_address("::10.0.0.1", false)); // ::0a00:0001 → 10/8 private
        assert!(!is_public_address("::169.254.169.254", false)); // link-local metadata
        assert!(!is_public_address("::127.0.0.1", false)); // loopback (allow_loopback=false)
                                                           // A public embedded v4 still classifies public (per the embedded address).
        assert!(is_public_address("::8.8.8.8", false));
    }

    #[test]
    fn rejects_6to4_embedding_private_v4() {
        // 2002:0a00:0001:: encodes 10.0.0.1
        assert!(!is_public_address("2002:0a00:0001::", false));
    }

    #[test]
    fn rejects_nat64_embedding_private_v4() {
        // 64:ff9b::10.0.0.1 (well-known prefix)
        assert!(!is_public_address("64:ff9b::0a00:0001", false));
    }

    /// Build an IPv6 string from raw octets so NAT64 layouts are exact (no hand-formatting slips).
    fn v6_from_octets(o: [u8; 16]) -> String {
        Ipv6Addr::from(o).to_string()
    }

    #[test]
    fn rejects_nat64_well_known_various_private_v4() {
        // RFC 6052 §2.1 well-known prefix 64:ff9b::/96 embedding non-public v4s.
        assert!(!is_public_address("64:ff9b::7f00:0001", false)); // 127.0.0.1 loopback
        assert!(!is_public_address("64:ff9b::a9fe:a9fe", false)); // 169.254.169.254 link-local metadata
        assert!(!is_public_address("64:ff9b::0a00:0001", false)); // 10.0.0.1 RFC1918
    }

    #[test]
    fn accepts_nat64_well_known_embedding_public_v4() {
        // Well-known prefix embedding a PUBLIC v4 (8.8.8.8) → allowed.
        assert!(is_public_address("64:ff9b::0808:0808", false)); // 8.8.8.8
    }

    #[test]
    fn accepts_custom_nsp_shaped_ipv6_no_speculative_false_block() {
        // SECURITY-CORRECTNESS: the SSRF guard must NOT false-block a legitimate global IPv6 just
        // because, read under some hypothetical operator NSP framing, its bytes COULD spell a
        // private v4. We do not know any operator's NSP, and these structurally-NAT64-shaped
        // addresses are byte-for-byte indistinguishable from ordinary sparse global allocations —
        // so every one of them must classify PUBLIC (only the IANA well-known /96 is matched).
        //
        // Each of the following previously tripped the removed speculative /32../64 matching
        // (zero u-octet + zero suffix + a private-looking candidate) and was WRONGLY refused.

        // /32-shaped: 2001:db8:a00:1:: — octets 4..=7 = 0a 00 00 01 = "10.0.0.1", suffix all zero.
        let mut o32 = [0u8; 16];
        o32[0..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
        o32[4..8].copy_from_slice(&[0x0a, 0x00, 0x00, 0x01]); // would-be 10.0.0.1 under /32
        assert!(is_public_address(&v6_from_octets(o32), false));

        // /64-shaped: 2001:db8:1:2:0:a9fe:a9fe — octets 9..=12 = "169.254.169.254", suffix zero.
        let mut o64 = [0u8; 16];
        o64[0..8].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x02]);
        o64[9..13].copy_from_slice(&[0xa9, 0xfe, 0xa9, 0xfe]); // would-be 169.254.169.254 under /64
        assert!(is_public_address(&v6_from_octets(o64), false));

        // /48-shaped: octets 6,7 then 9,10 = "10.0.0.1" under /48, u-octet + suffix zero.
        let mut o48 = [0u8; 16];
        o48[0..6].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0xca, 0xfe]);
        o48[6] = 0x0a;
        o48[7] = 0x00;
        o48[9] = 0x00;
        o48[10] = 0x01;
        assert!(is_public_address(&v6_from_octets(o48), false)); // would-be 10.0.0.1 under /48

        // /64-shaped embedding a loopback-looking v4 (127.0.0.1) — still PUBLIC, not blocked.
        let mut olo = [0u8; 16];
        olo[0..8].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0xab, 0xcd, 0x00, 0x00]);
        olo[9..13].copy_from_slice(&[0x7f, 0x00, 0x00, 0x01]); // would-be 127.0.0.1 under /64
        assert!(is_public_address(&v6_from_octets(olo), false));
    }

    #[test]
    fn accepts_genuine_public_ipv6_no_nat64_false_block() {
        // Real public IPv6 addresses must not be misread as NAT64-embedded private v4s.
        assert!(is_public_address("2606:4700:4700::1111", false)); // cloudflare
        assert!(is_public_address("2001:4860:4860::8888", false)); // google dns
        assert!(is_public_address("2620:fe::fe", false)); // quad9
    }

    #[test]
    fn accepts_6to4_embedding_public_v4() {
        // 2002:0808:0808:: encodes 8.8.8.8
        assert!(is_public_address("2002:0808:0808::", false));
    }

    #[test]
    fn rejects_garbage() {
        assert!(!is_public_address("not-an-ip", false));
        assert!(!is_public_address("", false));
        assert!(!is_public_address("999.999.999.999", false));
    }

    #[test]
    fn loopback_address_helper() {
        assert!(is_loopback_address("127.0.0.1"));
        assert!(is_loopback_address("127.5.6.7"));
        assert!(is_loopback_address("::1"));
        assert!(is_loopback_address("::ffff:127.0.0.1"));
        assert!(!is_loopback_address("10.0.0.1"));
        assert!(!is_loopback_address("::ffff:8.8.8.8"));
    }

    // ============================================================================================
    // Operator-configured NAT64 NSP allowlist (opt-in, default-OFF).
    // ============================================================================================

    #[test]
    fn nsp_parse_accepts_valid_lengths_and_masks_host_bits() {
        // All RFC 6052 §2.2 embedding lengths parse.
        for len in [32u8, 40, 48, 56, 64, 96] {
            assert!(
                Nat64Nsp::parse(&format!("2001:db8::/{len}")).is_ok(),
                "/{len} should be a valid NSP length"
            );
        }
        // Two equivalent CIDRs (host bits set vs cleared) compare equal after masking.
        let a = Nat64Nsp::parse("2001:db8::/32").unwrap();
        let b = Nat64Nsp::parse("2001:db8:dead:beef::/32").unwrap();
        assert_eq!(a, b, "host bits below the prefix must be masked off");
    }

    #[test]
    fn nsp_parse_rejects_bad_input() {
        // A length RFC 6052 §2.2 does not define for embedding.
        assert!(Nat64Nsp::parse("2001:db8::/64x").is_err()); // not a number
        assert!(Nat64Nsp::parse("2001:db8::/33").is_err()); // not an embedding length
        assert!(Nat64Nsp::parse("2001:db8::/128").is_err()); // host route, not an NSP
        assert!(Nat64Nsp::parse("not-an-ip/32").is_err()); // bad prefix
        assert!(Nat64Nsp::parse("2001:db8::").is_err()); // missing /len
                                                         // An IPv4 prefix is not an IPv6 NSP.
        assert!(Nat64Nsp::parse("10.0.0.0/32").is_err());
    }

    #[test]
    fn policy_from_cidrs_is_all_or_nothing() {
        // A clean list parses.
        assert!(Nat64Policy::from_cidrs(["2001:db8::/32", "2001:db8:1::/48"]).is_ok());
        // One bad entry fails the whole parse (fail-closed config).
        assert!(Nat64Policy::from_cidrs(["2001:db8::/32", "garbage"]).is_err());
        // Empty list = strict default.
        assert!(Nat64Policy::from_cidrs(Vec::<String>::new())
            .unwrap()
            .is_empty());
    }

    /// `<nsp-prefix-of-len>` embedding `v4`, returned as an IPv6 string. Built by composing the masked
    /// prefix bits with the embedded v4 at the RFC 6052 §2.2 offsets — symmetric with the decoder, so a
    /// round-trip (`embed → classify`) exercises the real bit layout.
    fn embed_nat64(prefix: &str, prefix_len: u8, v4: Ipv4Addr) -> String {
        let p: Ipv6Addr = prefix.parse().unwrap();
        let pbits: u128 = u128::from(p);
        let v4n = u32::from(v4);
        let mut bits = pbits & (u128::MAX << (128 - prefix_len)); // keep only prefix bits
                                                                  // Write 32 v4 bits starting at prefix_len, skipping bits 64..72 (reserved "u").
        let mut taken = 0u32;
        let mut pos = prefix_len as u32;
        while taken < 32 {
            if (64..72).contains(&pos) {
                pos = 72;
                continue;
            }
            let bit = ((v4n >> (31 - taken)) & 1) as u128;
            bits |= bit << (127 - pos);
            taken += 1;
            pos += 1;
        }
        Ipv6Addr::from(bits).to_string()
    }

    #[test]
    fn default_off_unchanged_for_nsp_shaped_addresses() {
        // With NO operator NSP configured, an address under a hypothetical NSP that embeds a PRIVATE
        // v4 must STILL be classified PUBLIC (the pre-allowlist behaviour) — the SSRF guard never
        // speculatively decodes an operator prefix it wasn't told about.
        let private_embed = embed_nat64("2001:db8::", 32, Ipv4Addr::new(10, 0, 0, 1));
        assert!(
            is_public_address(&private_embed, false),
            "default (no NSP configured) must keep raw-IPv6 classification: {private_embed}"
        );
        // The strict policy passed explicitly is identical to the default.
        assert!(is_public_address_with_nat64(
            &private_embed,
            false,
            &Nat64Policy::strict()
        ));
    }

    #[test]
    fn configured_nsp_rejects_embedded_private_v4_at_every_length() {
        // The core fix: when the operator configures their NSP, an embedded private/loopback/
        // link-local v4 is decoded and REJECTED — at every RFC 6052 §2.2 embedding length.
        let private_v4s = [
            Ipv4Addr::new(10, 0, 0, 1),        // RFC 1918
            Ipv4Addr::new(192, 168, 1, 1),     // RFC 1918
            Ipv4Addr::new(169, 254, 169, 254), // link-local metadata
            Ipv4Addr::new(127, 0, 0, 1),       // loopback
            Ipv4Addr::new(100, 64, 0, 1),      // CGNAT
        ];
        for len in [32u8, 40, 48, 56, 64, 96] {
            let policy = Nat64Policy::from_cidrs([format!("2001:db8::/{len}")]).unwrap();
            for v4 in private_v4s {
                let addr = embed_nat64("2001:db8::", len, v4);
                assert!(
                    !is_public_address_with_nat64(&addr, false, &policy),
                    "/{len} NSP embedding private {v4} must be REJECTED: {addr}"
                );
            }
        }
    }

    #[test]
    fn configured_nsp_allows_embedded_public_v4_only_when_configured() {
        // An embedded PUBLIC v4 under a configured NSP is allowed. Under no NSP it's also allowed (the
        // raw-IPv6 verdict) — so the observable difference of configuring an NSP is ONLY the ability to
        // REJECT an embedded private v4, never to widen acceptance. Verify both halves.
        let public_embed = embed_nat64("2001:db8::", 48, Ipv4Addr::new(8, 8, 8, 8));
        let policy = Nat64Policy::from_cidrs(["2001:db8::/48"]).unwrap();
        assert!(
            is_public_address_with_nat64(&public_embed, false, &policy),
            "configured NSP embedding a public v4 → allowed: {public_embed}"
        );
        // Default-off: same address is also public (raw-IPv6 classification, no NSP decode).
        assert!(is_public_address(&public_embed, false));

        // And the discriminating case the task calls out: the SAME private-embedding address is
        // ALLOWED when the NSP is NOT configured but REJECTED once it is.
        let private_embed = embed_nat64("2001:db8::", 48, Ipv4Addr::new(192, 168, 0, 5));
        assert!(
            is_public_address(&private_embed, false),
            "no NSP configured → allowed (raw IPv6)"
        );
        assert!(
            !is_public_address_with_nat64(&private_embed, false, &policy),
            "NSP configured → rejected (embedded private v4)"
        );
    }

    #[test]
    fn configured_nsp_does_not_affect_addresses_outside_it() {
        // An NSP only matches addresses UNDER its prefix; a different global IPv6 keeps its raw verdict.
        let policy = Nat64Policy::from_cidrs(["2001:db8:abcd::/48"]).unwrap();
        // A genuine public address that does NOT fall under the configured NSP stays public.
        assert!(is_public_address_with_nat64(
            "2606:4700:4700::1111",
            false,
            &policy
        ));
        // An address under a DIFFERENT 2001:db8 sub-prefix (not the configured one) keeps its raw
        // classification (public), not decoded — fail-closed, no over-match.
        let other = embed_nat64("2001:db8:0001::", 48, Ipv4Addr::new(10, 0, 0, 1));
        assert!(
            is_public_address_with_nat64(&other, false, &policy),
            "address outside the configured NSP must not be decoded: {other}"
        );
    }

    #[test]
    fn well_known_prefix_still_decoded_regardless_of_policy() {
        // The IANA well-known 64:ff9b::/96 is ALWAYS decoded, even with an empty operator policy and
        // even when the operator policy lists unrelated prefixes — the strict baseline is preserved.
        let strict = Nat64Policy::strict();
        assert!(!is_public_address_with_nat64(
            "64:ff9b::a00:1",
            false,
            &strict
        )); // 10.0.0.1
        assert!(is_public_address_with_nat64(
            "64:ff9b::808:808",
            false,
            &strict
        )); // 8.8.8.8
        let unrelated = Nat64Policy::from_cidrs(["2001:db8::/32"]).unwrap();
        assert!(!is_public_address_with_nat64(
            "64:ff9b::a9fe:a9fe",
            false,
            &unrelated
        )); // 169.254.169.254
    }

    #[test]
    fn multiple_nsps_first_match_wins_and_each_is_honoured() {
        let policy = Nat64Policy::from_cidrs(["2001:db8:1::/48", "2001:db8:2::/48"]).unwrap();
        // Each configured NSP independently rejects an embedded private v4.
        assert!(!is_public_address_with_nat64(
            &embed_nat64("2001:db8:1::", 48, Ipv4Addr::new(10, 0, 0, 1)),
            false,
            &policy
        ));
        assert!(!is_public_address_with_nat64(
            &embed_nat64("2001:db8:2::", 48, Ipv4Addr::new(192, 168, 0, 1)),
            false,
            &policy
        ));
    }

    #[test]
    fn embed_helper_round_trips_via_decoder() {
        // Sanity: the test's embed helper and the production decoder are inverses, so the above tests
        // exercise the real bit layout rather than a self-consistent fiction.
        for len in [32u8, 40, 48, 56, 64, 96] {
            let v4 = Ipv4Addr::new(192, 0, 2, 33); // RFC 6052 §2.4 canonical example
            let addr: Ipv6Addr = embed_nat64("2001:db8::", len, v4).parse().unwrap();
            let nsp = Nat64Nsp::parse(&format!("2001:db8::/{len}")).unwrap();
            assert_eq!(
                nsp.embedded_v4(&addr.segments()),
                Some(v4),
                "/{len} embed→decode round-trip"
            );
        }
    }
}
