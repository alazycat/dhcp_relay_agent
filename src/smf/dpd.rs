use std::net::IpAddr;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use murmur3::murmur3_x64_128;

use crate::error::{RelayError, RelayResult};

/// Key for a DPD cache entry — uniquely identifies a packet.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DpdKey {
    pub src_addr: IpAddr,
    pub dst_addr: IpAddr,
    pub packet_id: u64,
}

impl DpdKey {
    pub fn new(src_addr: IpAddr, dst_addr: IpAddr, packet_id: u64) -> Self {
        Self {
            src_addr,
            dst_addr,
            packet_id,
        }
    }
}

/// An entry in the DPD cache recording when a packet was first seen and its TTL.
#[derive(Debug, Clone)]
struct DpdEntry {
    first_seen: Instant,
    ttl: u8,
}

/// Duplicate Packet Detection cache with TTL-based DoS protection.
///
/// Uses a `DashMap` for lock-free concurrent access. A background eviction task
/// periodically removes entries older than the configured time window.
pub struct DpdCache {
    map: DashMap<DpdKey, DpdEntry>,
    window: Duration,
}

impl DpdCache {
    /// Create a new DPD cache with the given time window.
    ///
    /// Entries older than `window` are eligible for eviction.
    pub fn new(window: Duration) -> Self {
        Self {
            map: DashMap::new(),
            window,
        }
    }

    /// Check if a packet with the given key and TTL is a duplicate.
    ///
    /// Returns:
    /// - `Ok(true)` — new packet, should be forwarded
    /// - `Ok(false)` — duplicate, should be dropped
    /// - `Err(DpdStalePacket)` — possible DoS attack (smaller TTL), should be dropped
    pub fn check_and_insert(&self, key: DpdKey, ttl: u8) -> RelayResult<bool> {
        let now = Instant::now();

        // First, try to get an existing entry
        if let Some(mut entry) = self.map.get_mut(&key) {
            if entry.ttl < ttl {
                // Larger TTL — possible pre-play attack countermeasure.
                // Update the cached TTL and treat as a new packet (RFC 6621 §6.3).
                entry.ttl = ttl;
                entry.first_seen = now;
                return Ok(true);
            } else if entry.ttl == ttl {
                // Same TTL — normal duplicate
                return Ok(false);
            } else {
                // Smaller TTL — potential attack, reject
                return Err(RelayError::DpdStalePacket);
            }
        }

        // New entry
        self.map
            .insert(key, DpdEntry { first_seen: now, ttl });
        Ok(true)
    }

    /// Remove entries older than the configured time window.
    pub fn evict_expired(&self) {
        let cutoff = Instant::now() - self.window;
        self.map.retain(|_, entry| entry.first_seen > cutoff);
    }

    /// Return the number of entries currently in the cache.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Return true if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Clear all entries from the cache.
    pub fn clear(&self) {
        self.map.clear();
    }
}

/// Compute an H-DPD key and Hash Assist Value from packet content.
///
/// Hashes `src || dst || payload[..min(64, len)]` using murmur3_x64_128 and
/// returns the DPD key along with the lower 64 bits as the HAV.
pub fn h_dpd_hash(src: IpAddr, dst: IpAddr, payload: &[u8]) -> (DpdKey, u64) {
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

/// Spawn a background task that periodically evicts expired DPD cache entries.
///
/// The eviction interval is `window / 4`. Returns a `JoinHandle` that the caller
/// can `.abort()` to stop eviction.
pub fn spawn_eviction_task(cache: std::sync::Arc<DpdCache>) -> tokio::task::JoinHandle<()> {
    let interval = cache.window / 4;
    if interval < Duration::from_secs(1) {
        tracing::warn!(
            window_secs = cache.window.as_secs(),
            "DPD eviction interval too short — eviction disabled; entries will not expire"
        );
        tokio::spawn(async {})
    } else {
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            loop {
                tick.tick().await;
                cache.evict_expired();
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn v4_key(id: u64) -> DpdKey {
        DpdKey::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),
            id,
        )
    }

    #[test]
    fn new_packet_returns_true() {
        let cache = DpdCache::new(Duration::from_secs(10));
        let result = cache.check_and_insert(v4_key(1), 64).unwrap();
        assert!(result);
    }

    #[test]
    fn duplicate_same_ttl_returns_false() {
        let cache = DpdCache::new(Duration::from_secs(10));
        cache.check_and_insert(v4_key(1), 64).unwrap();
        let result = cache.check_and_insert(v4_key(1), 64).unwrap();
        assert!(!result);
    }

    #[test]
    fn larger_ttl_updates_and_returns_true() {
        let cache = DpdCache::new(Duration::from_secs(10));
        cache.check_and_insert(v4_key(1), 32).unwrap();
        let result = cache.check_and_insert(v4_key(1), 64).unwrap();
        assert!(result); // Possible pre-play, accept
    }

    #[test]
    fn smaller_ttl_returns_error() {
        let cache = DpdCache::new(Duration::from_secs(10));
        cache.check_and_insert(v4_key(1), 64).unwrap();
        let result = cache.check_and_insert(v4_key(1), 32);
        assert!(result.is_err());
    }

    #[test]
    fn different_keys_are_independent() {
        let cache = DpdCache::new(Duration::from_secs(10));
        assert!(cache.check_and_insert(v4_key(1), 64).unwrap());
        assert!(cache.check_and_insert(v4_key(2), 64).unwrap());
        assert!(!cache.check_and_insert(v4_key(1), 64).unwrap());
    }

    #[test]
    fn evict_expired_removes_old_entries() {
        let cache = DpdCache::new(Duration::from_millis(1));
        cache.check_and_insert(v4_key(1), 64).unwrap();
        assert_eq!(cache.len(), 1);
        std::thread::sleep(Duration::from_millis(5));
        cache.evict_expired();
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn different_src_addr_are_different_keys() {
        let cache = DpdCache::new(Duration::from_secs(10));
        let key1 = DpdKey::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),
            1,
        );
        let key2 = DpdKey::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),
            1,
        );
        assert!(cache.check_and_insert(key1, 64).unwrap());
        assert!(cache.check_and_insert(key2, 64).unwrap());
    }

    #[test]
    fn clear_removes_all() {
        let cache = DpdCache::new(Duration::from_secs(10));
        cache.check_and_insert(v4_key(1), 64).unwrap();
        cache.check_and_insert(v4_key(2), 64).unwrap();
        cache.clear();
        assert!(cache.is_empty());
    }
}
