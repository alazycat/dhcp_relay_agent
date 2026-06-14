use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::config::SmfConfig;
use crate::error::RelayResult;
use crate::traits::RelaySetSelector;

use super::dpd::DpdCache;
use super::forwarding;

/// SMF multicast forwarding engine (RFC 6621).
///
/// Integrates DPD cache, forwarding rules, and relay set selection into
/// a single `process_packet` entry point.
pub struct SmfEngine {
    dpd_cache: Arc<DpdCache>,
    relay_selector: Box<dyn RelaySetSelector>,
    local_addrs: Vec<IpAddr>,
}

impl SmfEngine {
    /// Create a new SMF engine with the given configuration.
    pub fn new(config: SmfConfig, local_addrs: Vec<IpAddr>) -> Self {
        let dpd_cache = Arc::new(DpdCache::new(Duration::from_secs(config.dpd_window_secs)));

        Self {
            dpd_cache,
            relay_selector: Box::new(super::relay_set::ClassicFlooding),
            local_addrs,
        }
    }

    /// Start the background DPD cache eviction task.
    ///
    /// Must be called from within a tokio runtime context.
    pub fn start_eviction(&self) -> tokio::task::JoinHandle<()> {
        super::dpd::spawn_eviction_task(self.dpd_cache.clone())
    }

    /// Inject a custom relay set selector.
    pub fn with_relay_selector(mut self, selector: Box<dyn RelaySetSelector>) -> Self {
        self.relay_selector = selector;
        self
    }

    /// Process a multicast packet.
    ///
    /// Returns `Ok(Some(modified_packet))` if the packet should be forwarded
    /// (with TTL decremented), or `Ok(None)` if it should be dropped.
    pub fn process_packet(
        &self,
        packet: &[u8],
        src_addr: IpAddr,
        dst_addr: IpAddr,
        ttl: u8,
        ingress_iface: &str,
        prev_hop: IpAddr,
    ) -> RelayResult<Option<Vec<u8>>> {
        // Step 1: Forwarding rules check
        if !forwarding::check_forwarding_rules(src_addr, dst_addr, ttl, &self.local_addrs) {
            return Ok(None);
        }

        // Step 2: Relay set selection
        if !self
            .relay_selector
            .should_forward(ingress_iface, prev_hop, src_addr, dst_addr)
        {
            return Ok(None);
        }

        // Step 3: Decrement TTL/hop-limit and forward
        let mut modified = packet.to_vec();

        // Locate the TTL field. For IPv4 it's at offset 8; for IPv6 hop-limit at offset 7.
        match dst_addr {
            IpAddr::V4(_) => {
                if modified.len() > 8 {
                    modified[8] = ttl - 1;
                }
            }
            IpAddr::V6(_) => {
                if modified.len() > 7 {
                    modified[7] = ttl - 1;
                }
            }
        }

        Ok(Some(modified))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn process_packet_forwards_valid_multicast() {
        let config = SmfConfig::default();
        let engine = SmfEngine::new(config, vec![]);

        let packet = vec![
            0x46, 0, 0, 20, // IP header (IPv4, no options)
            0, 0, 0, 0,
            64, // TTL = 64
            0, 0, 0, 0,
            10, 0, 0, 1, // src
            239, 0, 0, 1, // dst (multicast)
        ];

        let result = engine
            .process_packet(
                &packet,
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                IpAddr::V4(Ipv4Addr::new(239, 0, 0, 1)),
                64,
                "eth0",
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            )
            .unwrap();

        assert!(result.is_some());
        assert_eq!(result.unwrap()[8], 63); // TTL decremented
    }

    #[test]
    fn process_packet_drops_non_multicast() {
        let config = SmfConfig::default();
        let engine = SmfEngine::new(config, vec![]);

        let result = engine
            .process_packet(
                &[],
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), // unicast
                64,
                "eth0",
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            )
            .unwrap();

        assert!(result.is_none());
    }
}
