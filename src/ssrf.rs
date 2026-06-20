// AUTHORED-BY Claude Opus 4.8
//! SSRF public-address classification — a faithful port of the resource server's
//! `packages/guarded-fetch/src/addresses.ts` (itself the stricter copy from `webidResolver.ts`).
//!
//! Refuses: loopback, link-local, IPv4 private (RFC 1918), CGNAT (RFC 6598), IPv4 reserved/test
//! ranges, multicast, broadcast, `0.0.0.0/8`, IPv4-mapped IPv6, IPv6 ULA (`fc00::/7`), IPv6
//! unspecified, **6to4 (`2002::/16`) embedding a private v4**, and **NAT64 (RFC 6052) embedding a
//! private v4 at the IANA well-known prefix `64:ff9b::/96`**. Operator-defined NAT64
//! Network-Specific Prefixes (NSPs) are deliberately NOT matched: their layout (RFC 6052 §2.2)
//! has no globally-known structural discriminator, so speculatively reading a private v4 out of
//! every address that *could* be an NSP embedding would false-block legitimate sparse global IPv6.
//! An operator that runs a custom NSP fronts it with its own egress policy. `allow_loopback`
//! re-permits loopback only (dev / IT).
//!
//! The verifier's WebID resolution uses this to refuse a profile URL that resolves to a non-public
//! address (the DNS-rebinding + private-network guard, TS risk R5). M1 implements the classifier (the
//! load-bearing security logic) and the per-record check; the DNS-pinning fetch/connector is the M2
//! network adapter behind the [`crate::webid::WebIdResolver`] trait.

use std::net::{Ipv4Addr, Ipv6Addr};

/// Classify an IPv4/IPv6 literal as public. Returns `false` for any non-public range, malformed
/// input, or a non-IP string. `allow_loopback` re-permits loopback (127/8, ::1, mapped 127.x) only.
/// Mirrors `isPublicAddress`.
pub fn is_public_address(address: &str, allow_loopback: bool) -> bool {
    if let Ok(v4) = address.parse::<Ipv4Addr>() {
        return is_public_ipv4(v4, allow_loopback);
    }
    if let Ok(v6) = address.parse::<Ipv6Addr>() {
        return is_public_ipv6(v6, allow_loopback);
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

fn is_public_ipv6(addr: Ipv6Addr, allow_loopback: bool) -> bool {
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
    // (/32../64) are deliberately NOT speculatively matched. We do not know the operator's NSP, and
    // RFC 6052 §2.2's only structural invariants (a zero reserved "u" octet + a zero suffix) are
    // ALSO satisfied by ordinary sparse global-unicast IPv6 allocations — so reading a candidate
    // v4 out of every such address would FALSE-BLOCK legitimate IPv6 whose interpreted candidate
    // merely happens to land in a private range (e.g. `2001:db8:a00:1::`, a valid global address,
    // would be read as embedding 10.0.0.1 under the /32 framing). The SSRF guard must never refuse
    // a legitimate public address, so we check only the well-known /96. An operator running a
    // custom NSP is responsible for its own egress policy.
    if let Some(v4) = nat64_well_known_embedded_v4(&segments) {
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
}
