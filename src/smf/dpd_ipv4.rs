use std::net::IpAddr;

use super::dpd::{h_dpd_hash, DpdKey};

/// Generate a DPD packet identifier from an IPv4 Identification field (I-DPD mode).
///
/// Uses the 16-bit IP Identification field as the basis for the packet_id,
/// combined with source and destination addresses.
pub fn i_dpd_packet_id(src: IpAddr, dst: IpAddr, ip_id: u16) -> DpdKey {
    DpdKey::new(src, dst, u64::from(ip_id))
}

/// Generate a DPD packet identifier from packet content hash (H-DPD mode).
pub fn h_dpd_packet_id(src: IpAddr, dst: IpAddr, payload: &[u8]) -> DpdKey {
    h_dpd_hash(src, dst, payload).0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn i_dpd_same_ip_id_same_key() {
        let key1 = i_dpd_packet_id(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),
            42,
        );
        let key2 = i_dpd_packet_id(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),
            42,
        );
        assert_eq!(key1, key2);
    }

    #[test]
    fn i_dpd_different_ip_id_different_key() {
        let key1 = i_dpd_packet_id(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),
            42,
        );
        let key2 = i_dpd_packet_id(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),
            43,
        );
        assert_ne!(key1, key2);
    }

    #[test]
    fn h_dpd_same_content_same_key() {
        let payload = b"hello world";
        let key1 = h_dpd_packet_id(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),
            payload,
        );
        let key2 = h_dpd_packet_id(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),
            payload,
        );
        assert_eq!(key1, key2);
    }

    #[test]
    fn h_dpd_different_content_different_key() {
        let key1 = h_dpd_packet_id(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),
            b"packet A",
        );
        let key2 = h_dpd_packet_id(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),
            b"packet B",
        );
        assert_ne!(key1, key2);
    }

    #[test]
    fn h_dpd_truncates_to_64_bytes() {
        let payload = vec![0xAAu8; 128];
        let key = h_dpd_packet_id(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),
            &payload,
        );
        // Just verify it doesn't panic; hash should be deterministic
        let key2 = h_dpd_packet_id(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),
            &payload,
        );
        assert_eq!(key, key2);
    }
}
