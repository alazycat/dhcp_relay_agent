pub mod config;
pub mod error;
pub mod pipeline;
pub mod traits;
pub mod transport;

#[cfg(feature = "dhcpv4")]
pub mod dhcp;

#[cfg(feature = "smf")]
pub mod smf;

use std::sync::atomic::{AtomicU64, Ordering};

use config::RelayConfig;
use error::RelayError;

/// Runtime statistics for the relay agent.
#[derive(Debug, Default)]
pub struct RelayStats {
    pub packets_received: AtomicU64,
    pub packets_forwarded: AtomicU64,
    pub packets_dropped_parse_error: AtomicU64,
    pub packets_dropped_spoof: AtomicU64,
    pub option82_inserted: AtomicU64,
    pub option82_stripped: AtomicU64,
    pub vss_not_supported: AtomicU64,
    pub smf_duplicates_detected: AtomicU64,
    pub smf_forwarded: AtomicU64,
}

impl RelayStats {
    pub fn snapshot(&self) -> RelayStatsSnapshot {
        RelayStatsSnapshot {
            packets_received: self.packets_received.load(Ordering::Relaxed),
            packets_forwarded: self.packets_forwarded.load(Ordering::Relaxed),
            packets_dropped_parse_error: self.packets_dropped_parse_error.load(Ordering::Relaxed),
            packets_dropped_spoof: self.packets_dropped_spoof.load(Ordering::Relaxed),
            option82_inserted: self.option82_inserted.load(Ordering::Relaxed),
            option82_stripped: self.option82_stripped.load(Ordering::Relaxed),
            vss_not_supported: self.vss_not_supported.load(Ordering::Relaxed),
            smf_duplicates_detected: self.smf_duplicates_detected.load(Ordering::Relaxed),
            smf_forwarded: self.smf_forwarded.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct RelayStatsSnapshot {
    pub packets_received: u64,
    pub packets_forwarded: u64,
    pub packets_dropped_parse_error: u64,
    pub packets_dropped_spoof: u64,
    pub option82_inserted: u64,
    pub option82_stripped: u64,
    pub vss_not_supported: u64,
    pub smf_duplicates_detected: u64,
    pub smf_forwarded: u64,
}

/// Top-level relay agent handle.
pub struct RelayAgent {
    config: RelayConfig,
    stats: RelayStats,
}

impl RelayAgent {
    pub fn new(config: RelayConfig) -> Result<Self, RelayError> {
        config.validate()?;
        Ok(Self {
            config,
            stats: RelayStats::default(),
        })
    }

    pub fn config(&self) -> &RelayConfig {
        &self.config
    }

    pub fn stats(&self) -> RelayStatsSnapshot {
        self.stats.snapshot()
    }
}

impl RelayConfig {
    pub fn validate(&self) -> Result<(), RelayError> {
        if self.interfaces.is_empty() {
            return Err(RelayError::Config(
                "at least one interface is required".into(),
            ));
        }
        for iface in &self.interfaces {
            if iface.name.is_empty() {
                return Err(RelayError::Config("interface name cannot be empty".into()));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;

    #[test]
    fn relay_agent_new_defaults() {
        let mut cfg = RelayConfig::default();
        cfg.interfaces.push(config::InterfaceConfig {
            name: "eth0".into(),
            ip_addr: "10.0.0.1".into(),
            trusted: false,
            enabled: true,
        });
        let agent = RelayAgent::new(cfg).unwrap();
        let snap = agent.stats();
        assert_eq!(snap.packets_received, 0);
    }

    #[test]
    fn config_requires_interface() {
        let cfg = RelayConfig::default();
        assert!(RelayAgent::new(cfg).is_err());
    }

    #[test]
    fn stats_snapshot_reflects_current_values() {
        let mut cfg = RelayConfig::default();
        cfg.interfaces.push(config::InterfaceConfig {
            name: "eth0".into(),
            ip_addr: "10.0.0.1".into(),
            trusted: false,
            enabled: true,
        });
        let agent = RelayAgent::new(cfg).unwrap();
        agent
            .stats
            .packets_received
            .fetch_add(5, Ordering::Relaxed);
        assert_eq!(agent.stats().packets_received, 5);
    }
}
