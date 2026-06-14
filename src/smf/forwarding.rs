use std::net::IpAddr;

/// Check the 7 forwarding rules from RFC 6621 §5.
///
/// Returns `true` if the packet should be forwarded (all rules pass),
/// `false` if the packet should be dropped.
///
/// Rules:
/// 1. Destination is not multicast — drop
/// 2. TTL/hop-limit <= 1 — drop
/// 3. Link-local multicast — drop
/// 4. Source address matches a local interface — drop
/// 5. MAC source matches local — drop (caller responsibility, not checked here)
/// 6. DPD uniqueness check — caller responsibility
/// 7. Forward (decrement TTL)
pub fn check_forwarding_rules(
    src_addr: IpAddr,
    dst_addr: IpAddr,
    ttl: u8,
    local_addrs: &[IpAddr],
) -> bool {
    // Rule 1: destination must be multicast
    if !is_multicast(dst_addr) {
        return false;
    }

    // Rule 2: TTL > 1
    if ttl <= 1 {
        return false;
    }

    // Rule 3: skip link-local multicast
    if is_link_local_multicast(dst_addr) {
        return false;
    }

    // Rule 4: source must not match any local interface
    if local_addrs.contains(&src_addr) {
        return false;
    }

    // Rule 6 (DPD) is handled by the caller (SmfEngine)
    // Rule 5 (MAC) is handled by the caller

    true
}

/// Returns true if the address is an IPv4 or IPv6 multicast address.
fn is_multicast(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(ip) => ip.is_multicast(),
        IpAddr::V6(ip) => ip.is_multicast(),
    }
}

/// Returns true if the address is in a link-local multicast range.
/// IPv4: 224.0.0.0/24, IPv6: ff02::/16
fn is_link_local_multicast(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            octets[0] == 224 && octets[1] == 0 && octets[2] == 0
        }
        IpAddr::V6(ip) => ip.segments()[0] == 0xff02,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn rule1_non_multicast_dropped() {
        assert!(!check_forwarding_rules(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), // unicast
            64,
            &[]
        ));
    }

    #[test]
    fn rule2_ttl_one_or_less_dropped() {
        assert!(!check_forwarding_rules(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)), // multicast
            1,
            &[]
        ));
        assert!(!check_forwarding_rules(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),
            0,
            &[]
        ));
    }

    #[test]
    fn rule3_link_local_multicast_dropped() {
        assert!(!check_forwarding_rules(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)), // link-local
            64,
            &[]
        ));
        assert!(!check_forwarding_rules(
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)), // link-local
            64,
            &[]
        ));
    }

    #[test]
    fn rule4_source_matches_local_dropped() {
        let local = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        assert!(!check_forwarding_rules(
            local,
            IpAddr::V4(Ipv4Addr::new(224, 0, 1, 1)),
            64,
            &[local]
        ));
    }

    #[test]
    fn all_rules_pass_forwards() {
        assert!(check_forwarding_rules(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(239, 0, 0, 1)), // non-link-local multicast
            64,
            &[IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))] // different from source
        ));
    }

    #[test]
    fn ipv6_non_link_local_multicast_forwarded() {
        assert!(check_forwarding_rules(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(0xff05, 0, 0, 0, 0, 0, 0, 1)), // site-local multicast
            64,
            &[]
        ));
    }
}
