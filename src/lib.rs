pub mod config;
pub mod error;
pub mod pipeline;
pub mod traits;
pub mod transport;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use config::RelayConfig;
use error::{RelayError, RelayResult};

#[cfg(feature = "dhcpv4")]
pub mod dhcp;

#[cfg(feature = "smf")]
pub mod smf;

#[cfg(feature = "smf")]
use traits::{RelaySetSelector, TopologyProvider};

/// Events emitted by the relay agent during operation.
#[derive(Debug, Clone)]
pub enum RelayEvent {
    /// A packet was received.
    PacketReceived { interface: String, len: usize },
    /// A packet was forwarded.
    PacketForwarded { interface: String, dst: String },
    /// A packet was dropped.
    PacketDropped { reason: String },
    /// An error occurred.
    Error { message: String },
}

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
    /// Return a snapshot of all counter values.
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

/// A snapshot of `RelayStats` counter values (serializable).
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

struct Inner {
    config: RelayConfig,
    stats: RelayStats,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    #[cfg(feature = "smf")]
    topology_provider: std::sync::Mutex<Option<Box<dyn TopologyProvider>>>,
    #[cfg(feature = "smf")]
    relay_selector: std::sync::Mutex<Option<Box<dyn RelaySetSelector>>>,
}

/// Top-level relay agent handle.
///
/// Create via [`RelayAgent::new`], start with [`RelayAgent::run`],
/// and stop with [`RelayAgent::shutdown`].
pub struct RelayAgent {
    inner: Arc<Inner>,
}

impl RelayAgent {
    /// Create a new relay agent from the given configuration.
    pub fn new(config: RelayConfig) -> Result<Self, RelayError> {
        config.validate()?;
        let (shutdown_tx, _) = tokio::sync::watch::channel(false);

        Ok(Self {
            inner: Arc::new(Inner {
                config,
                stats: RelayStats::default(),
                shutdown_tx,
                #[cfg(feature = "smf")]
                topology_provider: std::sync::Mutex::new(None),
                #[cfg(feature = "smf")]
                relay_selector: std::sync::Mutex::new(None),
            }),
        })
    }

    /// Return a reference to the current configuration.
    pub fn config(&self) -> &RelayConfig {
        &self.inner.config
    }

    /// Return a snapshot of runtime statistics.
    pub fn stats(&self) -> RelayStatsSnapshot {
        self.inner.stats.snapshot()
    }

    /// Return a reference to the internal statistics counters.
    pub fn stats_raw(&self) -> &RelayStats {
        &self.inner.stats
    }

    /// Start the relay agent main loop.
    ///
    /// Binds UDP sockets on each configured interface and processes incoming
    /// DHCP packets. Blocks until [`shutdown`](Self::shutdown) is called.
    pub async fn run(&self) -> RelayResult<()> {
        let mut handles = Vec::new();

        #[cfg(feature = "dhcpv4")]
        handles.extend(self.spawn_v4_tasks().await?);

        #[cfg(feature = "dhcpv6")]
        handles.extend(self.spawn_v6_tasks().await?);

        for handle in handles {
            let _ = handle.await;
        }

        Ok(())
    }

    /// Spawn DHCPv4 relay tasks — one per interface on port 67.
    #[cfg(feature = "dhcpv4")]
    async fn spawn_v4_tasks(&self) -> RelayResult<Vec<tokio::task::JoinHandle<()>>> {
        use std::net::Ipv4Addr;

        use dhcproto::{v4, Decodable};
        use pipeline::PipelineContext;

        let mut handles = Vec::new();
        let shutdown_rx = self.inner.shutdown_tx.subscribe();
        let inner = self.inner.clone();

        for iface in &self.inner.config.interfaces {
            if !iface.enabled {
                continue;
            }

            let bind_addr: std::net::SocketAddr = iface
                .ip_addr
                .parse()
                .map_err(|e| RelayError::Config(format!("invalid IP: {e}")))?;

            let mut transport = transport::udp::UdpTransport::bind(bind_addr)
                .await
                .map_err(|e| RelayError::Transport(format!("bind: {e}")))?;

            let iface_name = iface.name.clone();
            let iface_ip: Ipv4Addr = iface
                .ip_addr
                .split(':')
                .next()
                .unwrap_or("0.0.0.0")
                .parse()
                .unwrap_or(Ipv4Addr::UNSPECIFIED);
            let inner = inner.clone();
            let mut sr = shutdown_rx.clone();

            let handle = tokio::spawn(async move {
                loop {
                    tokio::select! {
                        biased;
                        _ = sr.changed() => {
                            if *sr.borrow() {
                                break;
                            }
                        }
                        result = transport.recv_from() => {
                            if let Ok((data, src)) = result {
                                inner.stats.packets_received.fetch_add(1, Ordering::Relaxed);

                                if let Ok(msg) = v4::Message::decode(
                                    &mut dhcproto::Decoder::new(&data)
                                ) {
                                    let is_client = msg.opts().msg_type().map(|t| {
                                        t == v4::MessageType::Discover
                                            || t == v4::MessageType::Request
                                    }).unwrap_or(false);

                                    if is_client && inner.config.dhcpv4.enable_option82 {
                                        let mut ctx = PipelineContext::new(
                                            data,
                                            src,
                                            iface_name.clone(),
                                        );

                                        let local_addrs: Vec<Ipv4Addr> = inner
                                            .config
                                            .interfaces
                                            .iter()
                                            .filter_map(|i| i.ip_addr.split(':').next()?.parse().ok())
                                            .collect();

                                        let mut pipeline = dhcp::v4::pipeline::Dhcpv4Pipeline::build_request(
                                            local_addrs,
                                            inner.config.dhcpv4.circuit_id.as_ref().map(|s| s.as_bytes().to_vec()),
                                            inner.config.dhcpv4.remote_id.as_ref().map(|s| s.as_bytes().to_vec()),
                                            iface_ip,
                                            inner.config.dhcpv4.server_addrs.first().copied().unwrap_or(bind_addr),
                                        );

                                        match pipeline.execute(&mut ctx) {
                                            Ok(true) => {
                                                inner.stats.packets_forwarded.fetch_add(1, Ordering::Relaxed);
                                                if let Some(dst) = ctx.dst_addr {
                                                    let _ = transport.send_to(&ctx.buffer, dst).await;
                                                }
                                            }
                                            Ok(false) => {}
                                            Err(_) => {
                                                inner.stats.packets_dropped_spoof.fetch_add(1, Ordering::Relaxed);
                                            }
                                        }
                                    } else if !is_client && inner.config.dhcpv4.enable_option82 {
                                        // Server→Client reply: extract echoed Option 82,
                                        // strip it with echo validation, and forward to client.
                                        let expected_sub_opts = msg
                                            .opts()
                                            .get(v4::OptionCode::RelayAgentInformation)
                                            .and_then(|opt| {
                                                if let v4::DhcpOption::RelayAgentInformation(info) = opt {
                                                    Some(
                                                        info.iter()
                                                            .map(|(_, ri)| {
                                                                dhcp::v4::option82::relay_info_to_sub_opt(ri)
                                                            })
                                                            .collect::<Vec<_>>(),
                                                    )
                                                } else {
                                                    None
                                                }
                                            });

                                        let mut ctx = PipelineContext::new(
                                            data,
                                            src,
                                            iface_name.clone(),
                                        );

                                        let mut pipeline = dhcp::v4::pipeline::Dhcpv4Pipeline::build_reply(
                                            expected_sub_opts,
                                        );

                                        match pipeline.execute(&mut ctx) {
                                            Ok(true) => {
                                                inner.stats.packets_forwarded.fetch_add(1, Ordering::Relaxed);
                                                inner.stats.option82_stripped.fetch_add(1, Ordering::Relaxed);
                                                if let Some(dst) = ctx.dst_addr {
                                                    let _ = transport.send_to(&ctx.buffer, dst).await;
                                                }
                                            }
                                            Ok(false) => {}
                                            Err(_) => {
                                                // Option82 echo mismatch or parse error — drop
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            });

            handles.push(handle);
        }

        Ok(handles)
    }

    /// Spawn DHCPv6 relay tasks — one per interface on port 547.
    /// Placeholder: full implementation in issue #3.
    #[cfg(feature = "dhcpv6")]
    async fn spawn_v6_tasks(&self) -> RelayResult<Vec<tokio::task::JoinHandle<()>>> {
        let _ = self.inner.shutdown_tx.subscribe();
        Ok(Vec::new())
    }

    /// Signal the relay agent to shut down gracefully.
    pub fn shutdown(&self) {
        let _ = self.inner.shutdown_tx.send(true);
    }

    /// Inject a custom topology provider for SMF neighbor discovery.
    #[cfg(feature = "smf")]
    pub fn with_topology_provider(&mut self, provider: Box<dyn TopologyProvider>) -> &mut Self {
        *self
            .inner
            .topology_provider
            .lock()
            .expect("topology_provider mutex poisoned") = Some(provider);
        self
    }

    /// Inject a custom relay set selector for SMF.
    #[cfg(feature = "smf")]
    pub fn with_relay_selector(&mut self, selector: Box<dyn RelaySetSelector>) -> &mut Self {
        *self
            .inner
            .relay_selector
            .lock()
            .expect("relay_selector mutex poisoned") = Some(selector);
        self
    }

    /// Take the injected topology provider for consumption by SMF engine.
    #[cfg(feature = "smf")]
    #[allow(dead_code)] // consumed by SMF integration (v0.3)
    pub(crate) fn take_topology_provider(&self) -> Option<Box<dyn TopologyProvider>> {
        self.inner
            .topology_provider
            .lock()
            .expect("topology_provider mutex poisoned")
            .take()
    }

    /// Take the injected relay set selector for consumption by SMF engine.
    #[cfg(feature = "smf")]
    #[allow(dead_code)] // consumed by SMF integration (v0.3)
    pub(crate) fn take_relay_selector(&self) -> Option<Box<dyn RelaySetSelector>> {
        self.inner
            .relay_selector
            .lock()
            .expect("relay_selector mutex poisoned")
            .take()
    }
}

impl RelayConfig {
    /// Validate the configuration, returning an error if something is inconsistent.
    pub fn validate(&self) -> Result<(), RelayError> {
        if self.interfaces.is_empty() {
            return Err(RelayError::Config("at least one interface is required".into()));
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
        assert_eq!(agent.stats().packets_received, 0);
    }

    #[test]
    fn config_requires_interface() {
        assert!(RelayAgent::new(RelayConfig::default()).is_err());
    }

    #[test]
    fn stats_snapshot_reflects_counters() {
        let mut cfg = RelayConfig::default();
        cfg.interfaces.push(config::InterfaceConfig {
            name: "eth0".into(),
            ip_addr: "10.0.0.1".into(),
            trusted: false,
            enabled: true,
        });
        let agent = RelayAgent::new(cfg).unwrap();
        agent.stats_raw().packets_received.fetch_add(5, Ordering::Relaxed);
        assert_eq!(agent.stats().packets_received, 5);
    }

    #[test]
    fn shutdown_sets_signal() {
        let mut cfg = RelayConfig::default();
        cfg.interfaces.push(config::InterfaceConfig {
            name: "eth0".into(),
            ip_addr: "10.0.0.1".into(),
            trusted: false,
            enabled: true,
        });
        let agent = RelayAgent::new(cfg).unwrap();
        agent.shutdown();
    }

    #[cfg(feature = "smf")]
    #[test]
    fn smf_trait_injection_stores_and_retrieves() {
        use std::net::IpAddr;

        struct DummyTopology;
        impl TopologyProvider for DummyTopology {
            fn neighbors(&self, _iface: &str) -> Vec<IpAddr> {
                vec![]
            }
        }

        struct DummySelector;
        impl RelaySetSelector for DummySelector {
            fn should_forward(
                &self,
                _ingress: &str,
                _prev: IpAddr,
                _src: IpAddr,
                _dst: IpAddr,
            ) -> bool {
                false
            }
        }

        let mut cfg = RelayConfig::default();
        cfg.interfaces.push(config::InterfaceConfig {
            name: "eth0".into(),
            ip_addr: "10.0.0.1".into(),
            trusted: false,
            enabled: true,
        });
        let mut agent = RelayAgent::new(cfg).unwrap();

        agent
            .with_topology_provider(Box::new(DummyTopology))
            .with_relay_selector(Box::new(DummySelector));

        assert!(agent.take_topology_provider().is_some());
        assert!(agent.take_relay_selector().is_some());

        // Second take returns None (already consumed)
        assert!(agent.take_topology_provider().is_none());
    }
}
