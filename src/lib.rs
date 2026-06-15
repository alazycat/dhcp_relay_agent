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

/// Define relay statistics counters and their snapshot type.
///
/// Each counter is declared once; the macro generates the `AtomicU64`-backed
/// `RelayStats` struct, the serializable `RelayStatsSnapshot` struct, and the
/// `snapshot()` mapping between them.
macro_rules! define_stats {
    ($($name:ident),* $(,)?) => {
        #[derive(Debug, Default)]
        pub struct RelayStats {
            $(pub $name: AtomicU64),*
        }

        impl RelayStats {
            pub fn snapshot(&self) -> RelayStatsSnapshot {
                RelayStatsSnapshot {
                    $($name: self.$name.load(Ordering::Relaxed)),*
                }
            }
        }

        #[derive(Debug, Clone, Default, serde::Serialize)]
        pub struct RelayStatsSnapshot {
            $(pub $name: u64),*
        }
    };
}

define_stats!(
    packets_received,
    packets_forwarded,
    packets_dropped_parse_error,
    packets_dropped_spoof,
    option82_inserted,
    option82_stripped,
    vss_not_supported,
    smf_duplicates_detected,
    smf_forwarded,
);

struct Inner {
    config: RelayConfig,
    stats: RelayStats,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    #[cfg(feature = "smf")]
    topology_provider: std::sync::Mutex<Option<Box<dyn TopologyProvider>>>,
    #[cfg(feature = "smf")]
    relay_selector: std::sync::Mutex<Option<Box<dyn RelaySetSelector>>>,
}

#[cfg(feature = "dhcpv4")]
#[derive(Clone)]
struct V4SpawnContext {
    inner: Arc<Inner>,
    enable_option82: bool,
    vss_enabled: bool,
    vss_cfg: config::VssConfig,
    circuit_id: Option<Vec<u8>>,
    remote_id: Option<Vec<u8>>,
    local_addrs: Vec<std::net::Ipv4Addr>,
}

#[cfg(feature = "dhcpv4")]
impl V4SpawnContext {
    fn from_inner(inner: &Arc<Inner>) -> Self {
        let cfg = &inner.config.dhcpv4;
        Self {
            inner: inner.clone(),
            enable_option82: cfg.enable_option82,
            vss_enabled: cfg.vss.enabled,
            vss_cfg: cfg.vss.clone(),
            circuit_id: cfg.circuit_id.as_ref().map(|s| s.as_bytes().to_vec()),
            remote_id: cfg.remote_id.as_ref().map(|s| s.as_bytes().to_vec()),
            local_addrs: inner.config.interfaces.iter()
                .filter_map(|i| i.ip_addr.split(':').next()?.parse().ok())
                .collect(),
        }
    }
}

#[cfg(feature = "dhcpv6")]
#[derive(Clone)]
struct V6SpawnContext {
    inner: Arc<Inner>,
    enable_interface_id: bool,
    enable_remote_id: bool,
    vss_enabled: bool,
    vss_cfg: config::VssConfig,
    remote_id: Vec<u8>,
}

#[cfg(feature = "dhcpv6")]
impl V6SpawnContext {
    fn from_inner(inner: &Arc<Inner>) -> Self {
        let cfg = &inner.config.dhcpv6;
        Self {
            inner: inner.clone(),
            enable_interface_id: cfg.enable_interface_id,
            enable_remote_id: cfg.enable_remote_id,
            vss_enabled: cfg.vss.enabled,
            vss_cfg: cfg.vss.clone(),
            remote_id: cfg.remote_id.clone().unwrap_or_default(),
        }
    }
}

#[cfg(feature = "dhcpv4")]
#[allow(clippy::too_many_arguments)]
async fn handle_v4_client(
    data: Vec<u8>,
    src: std::net::SocketAddr,
    iface_name: String,
    iface_ip: std::net::Ipv4Addr,
    local_addrs: Vec<std::net::Ipv4Addr>,
    circuit_id: Option<Vec<u8>>,
    remote_id: Option<Vec<u8>>,
    server_addr: std::net::SocketAddr,
    vss_cfg: Option<config::VssConfig>,
    enable_option82: bool,
    stats: &RelayStats,
    transport: &impl transport::Transport,
) {
    let mut ctx = pipeline::PipelineContext::new(data, src, iface_name);
    let mut pipeline = dhcp::v4::pipeline::build_request(
        local_addrs, circuit_id, remote_id, iface_ip, server_addr, vss_cfg, enable_option82,
    );
    match pipeline.execute(&mut ctx) {
        Ok(true) => {
            stats.packets_forwarded.fetch_add(1, Ordering::Relaxed);
            if let Some(dst) = ctx.dst_addr {
                let _ = transport.send_to(&ctx.buffer, dst).await;
            }
        }
        Ok(false) => {}
        Err(_) => {
            stats.packets_dropped_spoof.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[cfg(feature = "dhcpv4")]
#[allow(clippy::too_many_arguments)]
async fn handle_v4_server(
    data: Vec<u8>,
    src: std::net::SocketAddr,
    iface_name: String,
    expected_sub_opts: Option<Vec<dhcp::v4::option82::SubOption>>,
    vss_cfg: Option<config::VssConfig>,
    enable_option82: bool,
    stats: &RelayStats,
    transport: &impl transport::Transport,
) {
    let mut ctx = pipeline::PipelineContext::new(data, src, iface_name);
    let mut pipeline = dhcp::v4::pipeline::build_reply(
        expected_sub_opts, vss_cfg, enable_option82,
    );
    match pipeline.execute(&mut ctx) {
        Ok(true) => {
            stats.packets_forwarded.fetch_add(1, Ordering::Relaxed);
            stats.option82_stripped.fetch_add(1, Ordering::Relaxed);
            if let Some(dst) = ctx.dst_addr {
                let _ = transport.send_to(&ctx.buffer, dst).await;
            }
        }
        Ok(false) => {}
        Err(_) => {}
    }
}

#[cfg(feature = "dhcpv6")]
#[allow(clippy::too_many_arguments)]
async fn handle_v6_client(
    data: Vec<u8>,
    src: std::net::SocketAddr,
    iface_name: String,
    remote_id: Vec<u8>,
    server_addr: std::net::SocketAddr,
    vss_cfg: Option<config::VssConfig>,
    enable_interface_id: bool,
    enable_remote_id: bool,
    stats: &RelayStats,
    transport: &impl transport::Transport,
) {
    use std::net::Ipv6Addr;

    let link_addr = transport
        .local_addr()
        .map(|a| match a.ip() {
            std::net::IpAddr::V6(ip) => ip,
            _ => Ipv6Addr::UNSPECIFIED,
        })
        .unwrap_or(Ipv6Addr::UNSPECIFIED);

    let mut ctx = pipeline::PipelineContext::new(data, src, iface_name.clone());
    let mut pipeline = dhcp::v6::pipeline::build_request(
        iface_name, remote_id, link_addr, src, server_addr, vss_cfg,
        enable_interface_id, enable_remote_id,
    );
    match pipeline.execute(&mut ctx) {
        Ok(true) => {
            stats.packets_forwarded.fetch_add(1, Ordering::Relaxed);
            if let Some(dst) = ctx.dst_addr {
                let _ = transport.send_to(&ctx.buffer, dst).await;
            }
        }
        Ok(false) => {}
        Err(_) => {}
    }
}

#[cfg(feature = "dhcpv6")]
async fn handle_v6_server(
    data: Vec<u8>,
    src: std::net::SocketAddr,
    iface_name: String,
    vss_cfg: Option<config::VssConfig>,
    stats: &RelayStats,
    transport: &impl transport::Transport,
) {
    let mut ctx = pipeline::PipelineContext::new(data, src, iface_name);
    let mut pipeline = dhcp::v6::pipeline::build_reply(
        src, vss_cfg,
    );
    match pipeline.execute(&mut ctx) {
        Ok(true) => {
            stats.packets_forwarded.fetch_add(1, Ordering::Relaxed);
            if let Some(dst) = ctx.dst_addr {
                let _ = transport.send_to(&ctx.buffer, dst).await;
            }
        }
        Ok(false) => {}
        Err(_) => {}
    }
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

        let mut handles = Vec::new();
        let shutdown_rx = self.inner.shutdown_tx.subscribe();
        let spawn_ctx = V4SpawnContext::from_inner(&self.inner);
        let default_server = self.inner.config.dhcpv4.server_addrs.first().copied();

        for iface in &self.inner.config.interfaces {
            if !iface.enabled {
                continue;
            }

            let bind_addr: std::net::SocketAddr = iface.ip_addr
                .parse()
                .map_err(|e| RelayError::Config(format!("invalid IP: {e}")))?;

            let mut transport = transport::udp::UdpTransport::bind(bind_addr)
                .await
                .map_err(|e| RelayError::Transport(format!("bind: {e}")))?;

            let iface_name = iface.name.clone();
            let iface_ip: Ipv4Addr = iface.ip_addr
                .split(':').next()
                .unwrap_or("0.0.0.0")
                .parse()
                .unwrap_or(Ipv4Addr::UNSPECIFIED);
            let server_addr = default_server.unwrap_or(bind_addr);

            let ctx = spawn_ctx.clone();
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
                                ctx.inner.stats.packets_received.fetch_add(1, Ordering::Relaxed);

                                if let Ok(msg) = v4::Message::decode(
                                    &mut dhcproto::Decoder::new(&data)
                                ) {
                                    let is_client = msg.opts().msg_type().map(|t| {
                                        matches!(t,
                                            v4::MessageType::Discover
                                            | v4::MessageType::Request
                                            | v4::MessageType::Inform
                                            | v4::MessageType::Decline
                                            | v4::MessageType::Release
                                        )
                                    }).unwrap_or(false);

                                    if is_client {
                                        handle_v4_client(
                                            data, src, iface_name.clone(), iface_ip,
                                            ctx.local_addrs.clone(), ctx.circuit_id.clone(),
                                            ctx.remote_id.clone(), server_addr,
                                            ctx.vss_enabled.then(|| ctx.vss_cfg.clone()),
                                            ctx.enable_option82,
                                            &ctx.inner.stats, &transport,
                                        ).await;
                                    } else {
                                        let expected_sub_opts = msg.opts()
                                            .get(v4::OptionCode::RelayAgentInformation)
                                            .and_then(|opt| {
                                                if let v4::DhcpOption::RelayAgentInformation(info) = opt {
                                                    Some(info.iter()
                                                        .map(|(_, ri)| dhcp::v4::option82::relay_info_to_sub_opt(ri))
                                                        .collect::<Vec<_>>())
                                                } else {
                                                    None
                                                }
                                            });

                                        handle_v4_server(
                                            data, src, iface_name.clone(),
                                            expected_sub_opts,
                                            ctx.vss_enabled.then(|| ctx.vss_cfg.clone()),
                                            ctx.enable_option82,
                                            &ctx.inner.stats, &transport,
                                        ).await;
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
    #[cfg(feature = "dhcpv6")]
    async fn spawn_v6_tasks(&self) -> RelayResult<Vec<tokio::task::JoinHandle<()>>> {
        use dhcproto::{v6, Decodable};

        let mut handles = Vec::new();
        let shutdown_rx = self.inner.shutdown_tx.subscribe();
        let spawn_ctx = V6SpawnContext::from_inner(&self.inner);
        let default_server = self.inner.config.dhcpv6.server_addrs.first().copied();

        for iface in &self.inner.config.interfaces {
            if !iface.enabled {
                continue;
            }

            let iface_ip_str = iface.ip_addr.split(':').next().unwrap_or("::");
            let bind_addr: std::net::SocketAddr = format!("{iface_ip_str}:547")
                .parse()
                .map_err(|e| RelayError::Config(format!("invalid v6 IP: {e}")))?;

            let mut transport = transport::udp::UdpTransport::bind(bind_addr)
                .await
                .map_err(|e| RelayError::Transport(format!("v6 bind: {e}")))?;

            let iface_name = iface.name.clone();
            let server_addr = default_server.unwrap_or(bind_addr);

            let ctx = spawn_ctx.clone();
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
                                ctx.inner.stats.packets_received.fetch_add(1, Ordering::Relaxed);

                                let first_byte = data.first().copied().unwrap_or(0);

                                if first_byte == dhcp::v6::relay_fwd::RELAY_REPL {
                                    handle_v6_server(
                                        data, src, iface_name.clone(),
                                        ctx.vss_enabled.then(|| ctx.vss_cfg.clone()),
                                        &ctx.inner.stats, &transport,
                                    ).await;
                                } else if let Ok(msg) = v6::Message::decode(
                                    &mut dhcproto::Decoder::new(&data)
                                ) {
                                    let is_client = matches!(
                                        msg.msg_type(),
                                        v6::MessageType::Solicit
                                            | v6::MessageType::Request
                                            | v6::MessageType::Confirm
                                            | v6::MessageType::Renew
                                            | v6::MessageType::Rebind
                                            | v6::MessageType::Decline
                                            | v6::MessageType::Release
                                            | v6::MessageType::InformationRequest
                                    );

                                    if is_client {
                                        handle_v6_client(
                                            data, src, iface_name.clone(),
                                            ctx.remote_id.clone(), server_addr,
                                            ctx.vss_enabled.then(|| ctx.vss_cfg.clone()),
                                            ctx.enable_interface_id,
                                            ctx.enable_remote_id,
                                            &ctx.inner.stats, &transport,
                                        ).await;
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
    pub fn take_topology_provider(&self) -> Option<Box<dyn TopologyProvider>> {
        self.inner
            .topology_provider
            .lock()
            .expect("topology_provider mutex poisoned")
            .take()
    }

    /// Take the injected relay set selector for consumption by SMF engine.
    #[cfg(feature = "smf")]
    #[allow(dead_code)] // consumed by SMF integration (v0.3)
    pub fn take_relay_selector(&self) -> Option<Box<dyn RelaySetSelector>> {
        self.inner
            .relay_selector
            .lock()
            .expect("relay_selector mutex poisoned")
            .take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;

    fn test_config() -> RelayConfig {
        let mut cfg = RelayConfig::default();
        cfg.interfaces.push(config::InterfaceConfig {
            name: "eth0".into(),
            ip_addr: "10.0.0.1".into(),
            trusted: false,
            enabled: true,
        });
        cfg
    }

    #[test]
    fn relay_agent_new_defaults() {
        let agent = RelayAgent::new(test_config()).unwrap();
        assert_eq!(agent.stats().packets_received, 0);
    }

    #[test]
    fn config_requires_interface() {
        assert!(RelayAgent::new(RelayConfig::default()).is_err());
    }

    #[test]
    fn stats_snapshot_reflects_counters() {
        let agent = RelayAgent::new(test_config()).unwrap();
        agent.stats_raw().packets_received.fetch_add(5, Ordering::Relaxed);
        assert_eq!(agent.stats().packets_received, 5);
    }

    #[test]
    fn shutdown_sets_signal() {
        let agent = RelayAgent::new(test_config()).unwrap();
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

        let mut agent = RelayAgent::new(test_config()).unwrap();

        agent
            .with_topology_provider(Box::new(DummyTopology))
            .with_relay_selector(Box::new(DummySelector));

        assert!(agent.take_topology_provider().is_some());
        assert!(agent.take_relay_selector().is_some());

        // Second take returns None (already consumed)
        assert!(agent.take_topology_provider().is_none());
    }
}
