#![cfg(feature = "smf")]

//! Integration tests: SMF trait object injection and callback verification.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use dhcp_relay_agent::config::{InterfaceConfig, RelayConfig};
use dhcp_relay_agent::traits::{RelaySetSelector, TopologyProvider};
use dhcp_relay_agent::RelayAgent;

#[test]
fn topology_provider_called() {
    struct CountingProvider {
        count: Arc<AtomicU32>,
    }
    impl TopologyProvider for CountingProvider {
        fn neighbors(&self, iface: &str) -> Vec<IpAddr> {
            assert_eq!(iface, "eth0");
            self.count.fetch_add(1, Ordering::SeqCst);
            vec![]
        }
    }

    let mut cfg = RelayConfig::default();
    cfg.interfaces.push(InterfaceConfig {
        name: "eth0".into(),
        ip_addr: "10.0.0.1".into(),
        trusted: false,
        enabled: true,
    });

    let count = Arc::new(AtomicU32::new(0));
    let provider = CountingProvider {
        count: count.clone(),
    };

    let mut agent = RelayAgent::new(cfg).unwrap();
    agent.with_topology_provider(Box::new(provider));

    // Verify the provider was stored
    let taken = agent.take_topology_provider();
    assert!(taken.is_some());

    // Call the provider's method to verify it works
    let provider = taken.unwrap();
    provider.neighbors("eth0");
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[test]
fn relay_selector_called() {
    struct CountingSelector {
        count: Arc<AtomicU32>,
    }
    impl RelaySetSelector for CountingSelector {
        fn should_forward(
            &self,
            ingress: &str,
            _prev: IpAddr,
            _src: IpAddr,
            _dst: IpAddr,
        ) -> bool {
            assert_eq!(ingress, "eth0");
            self.count.fetch_add(1, Ordering::SeqCst);
            true
        }
    }

    let mut cfg = RelayConfig::default();
    cfg.interfaces.push(InterfaceConfig {
        name: "eth0".into(),
        ip_addr: "10.0.0.1".into(),
        trusted: false,
        enabled: true,
    });

    let count = Arc::new(AtomicU32::new(0));
    let selector = CountingSelector {
        count: count.clone(),
    };

    let mut agent = RelayAgent::new(cfg).unwrap();
    agent.with_relay_selector(Box::new(selector));

    // Verify the selector was stored
    let taken = agent.take_relay_selector();
    assert!(taken.is_some());

    // Call the selector's method to verify it works
    let selector = taken.unwrap();
    let result = selector.should_forward(
        "eth0",
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(239, 0, 0, 1)),
    );
    assert!(result);
    assert_eq!(count.load(Ordering::SeqCst), 1);
}
