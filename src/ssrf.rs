// AUTHORED-BY Claude Opus 4.8
//! SSRF public-address classification — a faithful port of the resource server's
//! `packages/guarded-fetch/src/addresses.ts` (itself the stricter copy from `webidResolver.ts`).
//!
//! Refuses: loopback, link-local, IPv4 private (RFC 1918), CGNAT (RFC 6598), IPv4 reserved/test
//! ranges, multicast, broadcast, `0.0.0.0/8`, IPv4-mapped IPv6, IPv6 ULA (`fc00::/7`), IPv6
//! unspecified, **6to4 (`2002::/16`) embedding a private v4**, **NAT64 (`64:ff9b::/96`) embedding a
//! private v4**. `allow_loopback` re-permits loopback only (dev / IT).
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
    // 2002::/16 6to4 — encodes a v4 in segments[1..3]. Block when the embedded v4 is non-public.
    if high == 0x2002 {
        let v4 = Ipv4Addr::new(
            (segments[1] >> 8) as u8,
            (segments[1] & 0xff) as u8,
            (segments[2] >> 8) as u8,
            (segments[2] & 0xff) as u8,
        );
        if !is_public_ipv4(v4, allow_loopback) {
            return false;
        }
    }
    // 64:ff9b::/96 NAT64 well-known prefix (RFC 6052): segments [0..6) == [64, ff9b, 0, 0, 0, 0],
    // last 32 bits a v4. Block when the embedded v4 is non-public.
    if segments[0] == 0x0064
        && segments[1] == 0xff9b
        && segments[2] == 0
        && segments[3] == 0
        && segments[4] == 0
        && segments[5] == 0
    {
        let v4 = Ipv4Addr::new(
            (segments[6] >> 8) as u8,
            (segments[6] & 0xff) as u8,
            (segments[7] >> 8) as u8,
            (segments[7] & 0xff) as u8,
        );
        if !is_public_ipv4(v4, allow_loopback) {
            return false;
        }
    }
    true
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
    fn rejects_6to4_embedding_private_v4() {
        // 2002:0a00:0001:: encodes 10.0.0.1
        assert!(!is_public_address("2002:0a00:0001::", false));
    }

    #[test]
    fn rejects_nat64_embedding_private_v4() {
        // 64:ff9b::10.0.0.1
        assert!(!is_public_address("64:ff9b::0a00:0001", false));
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
