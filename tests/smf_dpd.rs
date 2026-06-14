//! Integration test: SMF DPD duplicate detection and TTL attack protection.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use dhcp_relay_agent::smf::dpd::{DpdCache, DpdKey};

#[test]
fn same_packet_in_window_suppressed() {
    let cache = DpdCache::new(Duration::from_secs(10));
    let key = DpdKey::new(
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),
        42,
    );

    // First arrival: forward
    assert!(cache.check_and_insert(key.clone(), 64).unwrap());

    // Second arrival (same key, same TTL): suppress
    assert!(!cache.check_and_insert(key, 64).unwrap());
}

#[test]
fn ttl_lowering_attack_detected() {
    let cache = DpdCache::new(Duration::from_secs(10));
    let key = DpdKey::new(
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),
        42,
    );

    // First arrival with TTL=64
    cache.check_and_insert(key.clone(), 64).unwrap();

    // Second arrival with smaller TTL: possible attack
    let result = cache.check_and_insert(key, 32);
    assert!(result.is_err());
}

#[test]
fn ttl_preplay_countermeasure_accepts_higher_ttl() {
    let cache = DpdCache::new(Duration::from_secs(10));
    let key = DpdKey::new(
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),
        42,
    );

    cache.check_and_insert(key.clone(), 32).unwrap();

    // Higher TTL: pre-play countermeasure — accept
    assert!(cache.check_and_insert(key, 64).unwrap());
}

#[test]
fn window_expiry_allows_reforwarding() {
    let cache = DpdCache::new(Duration::from_millis(1));
    let key = DpdKey::new(
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),
        42,
    );

    cache.check_and_insert(key.clone(), 64).unwrap();
    assert_eq!(cache.len(), 1);

    // Wait for window to expire
    std::thread::sleep(Duration::from_millis(5));
    cache.evict_expired();

    assert_eq!(cache.len(), 0);

    // Same packet should be forwardable again
    assert!(cache.check_and_insert(key, 64).unwrap());
}
