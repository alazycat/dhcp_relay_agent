use std::net::IpAddr;

use murmur3::murmur3_x64_128;

use super::dpd::DpdKey;
use super::dpd_option::SmfDpdOption;

/// Generate an I-DPD packet identifier for IPv6.
///
/// Priority for identifier source (RFC 6621 §6.2):
/// 1. Fragment header Identification field
/// 2. IPsec sequence number (AH/ESP)
/// 3. SMF_DPD option Identifier
pub fn i_dpd_packet_id_from_option(
    src: IpAddr,
    dst: IpAddr,
    dpd_opt: &SmfDpdOption,
) -> DpdKey {
    let packet_id = bytes_to_u64(&dpd_opt.identifier);
    DpdKey::new(src, dst, packet_id)
}

/// Generate an I-DPD packet identifier using a raw identifier (e.g., from Fragment or IPsec).
pub fn i_dpd_packet_id_from_raw(src: IpAddr, dst: IpAddr, identifier: u32) -> DpdKey {
    DpdKey::new(src, dst, u64::from(identifier))
}

/// Generate an H-DPD packet identifier for IPv6.
///
/// Hashes `src_addr || dst_addr || payload[..min(64, len)]` using murmur3_x64_128.
/// Returns the DPD key and the Hash Assist Value (lower 64 bits of hash).
pub fn h_dpd_packet_id(
    src: IpAddr,
    dst: IpAddr,
    payload: &[u8],
) -> (DpdKey, u64) {
    let hash_len = 64.min(payload.len());

    let mut input = Vec::with_capacity(32 + hash_len);
    match src {
        IpAddr::V4(ip) => input.extend_from_slice(&ip.octets()),
        IpAddr::V6(ip) => input.extend_from_slice(&ip.octets()),
    }
    match dst {
        IpAddr::V4(ip) => input.extend_from_slice(&ip.octets()),
        IpAddr::V6(ip) => input.extend_from_slice(&ip.octets()),
    }
    input.extend_from_slice(&payload[..hash_len]);

    let hash = murmur3_x64_128(&mut &input[..], 0)
        .expect("murmur3 hash should not fail on in-memory data");
    let packet_id = (hash & 0xFFFF_FFFF_FFFF_FFFF) as u64;

    (DpdKey::new(src, dst, packet_id), packet_id)
}

/// Check whether there was an H-DPD collision. If the HAV differs from the cached
/// hash for this `(src, dst)` pair, there was no collision.
///
/// Per RFC 6621 §6.5.2: the sender only adds the SMF_DPD option with HAV when
/// a collision is detected.
pub fn has_collision(cached_hav: Option<u64>, current_hav: u64) -> bool {
    match cached_hav {
        Some(hav) => hav == current_hav,
        None => false,
    }
}

/// Convert up to 8 bytes to a u64 (big-endian, zero-padded on the right).
fn bytes_to_u64(bytes: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    let len = 8.min(bytes.len());
    buf[..len].copy_from_slice(&bytes[..len]);
    u64::from_be_bytes(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    #[test]
    fn i_dpd_from_raw_same_id_same_key() {
        let key1 = i_dpd_packet_id_from_raw(
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)),
            42,
        );
        let key2 = i_dpd_packet_id_from_raw(
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)),
            42,
        );
        assert_eq!(key1, key2);
    }

    #[test]
    fn i_dpd_from_option_uses_identifier_bytes() {
        let opt = SmfDpdOption::new_i_dpd(vec![0, 0, 0, 0, 0, 0, 0, 42]);
        let key = i_dpd_packet_id_from_option(
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)),
            &opt,
        );
        assert_eq!(key.packet_id, 42);
    }

    #[test]
    fn h_dpd_same_content_same_key() {
        let payload = b"hello world";
        let (key1, _) = h_dpd_packet_id(
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)),
            payload,
        );
        let (key2, _) = h_dpd_packet_id(
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)),
            payload,
        );
        assert_eq!(key1, key2);
    }

    #[test]
    fn has_collision_true_when_hav_matches() {
        assert!(has_collision(Some(42), 42));
    }

    #[test]
    fn has_collision_false_when_hav_differs() {
        assert!(!has_collision(Some(42), 43));
    }

    #[test]
    fn has_collision_false_when_no_cached_hav() {
        assert!(!has_collision(None, 42));
    }
}
