use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// Top-level configuration for the relay agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayConfig {
    /// Per-interface configuration.
    pub interfaces: Vec<InterfaceConfig>,
    /// DHCPv4-specific settings.
    #[serde(default)]
    pub dhcpv4: Dhcpv4Config,
    /// DHCPv6-specific settings.
    #[serde(default)]
    pub dhcpv6: Dhcpv6Config,
    /// SMF-specific settings.
    #[serde(default)]
    pub smf: SmfConfig,
    /// Maximum packet size in bytes (default: 1500).
    #[serde(default = "default_max_packet_size")]
    pub max_packet_size: usize,
}

fn default_max_packet_size() -> usize {
    1500
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            interfaces: Vec::new(),
            dhcpv4: Dhcpv4Config::default(),
            dhcpv6: Dhcpv6Config::default(),
            smf: SmfConfig::default(),
            max_packet_size: 1500,
        }
    }
}

/// Configuration for a single network interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceConfig {
    /// Interface name (e.g., "eth0", "enp0s1").
    pub name: String,
    /// IP address assigned to this interface.
    pub ip_addr: String,
    /// Whether this interface connects to trusted downstream clients.
    #[serde(default)]
    pub trusted: bool,
    /// Whether DHCP relay is enabled on this interface.
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

/// DHCPv4 relay configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dhcpv4Config {
    /// DHCP server addresses to forward client requests to.
    #[serde(default)]
    pub server_addrs: Vec<SocketAddr>,
    /// Whether Option 82 insertion is enabled.
    #[serde(default = "default_true")]
    pub enable_option82: bool,
    /// Circuit ID value (sub-option 1). None = use interface name.
    #[serde(default)]
    pub circuit_id: Option<String>,
    /// Remote ID value (sub-option 2). None = use relay agent's IP.
    #[serde(default)]
    pub remote_id: Option<String>,
    /// VSS (Virtual Subnet Selection) configuration (RFC 6607).
    #[serde(default)]
    pub vss: VssConfig,
}

impl Default for Dhcpv4Config {
    fn default() -> Self {
        Self {
            server_addrs: Vec::new(),
            enable_option82: true,
            circuit_id: None,
            remote_id: None,
            vss: VssConfig::default(),
        }
    }
}

/// DHCPv6 relay configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dhcpv6Config {
    /// DHCPv6 server addresses to forward client requests to.
    #[serde(default)]
    pub server_addrs: Vec<SocketAddr>,
    /// Whether Interface-ID option (18) insertion is enabled.
    #[serde(default = "default_true")]
    pub enable_interface_id: bool,
    /// Whether Remote-ID option (37) insertion is enabled.
    #[serde(default = "default_true")]
    pub enable_remote_id: bool,
    /// Remote ID value. None = use relay agent's DUID.
    #[serde(default)]
    pub remote_id: Option<Vec<u8>>,
    /// VSS (Virtual Subnet Selection) configuration (RFC 6607).
    #[serde(default)]
    pub vss: VssConfig,
}

impl Default for Dhcpv6Config {
    fn default() -> Self {
        Self {
            server_addrs: Vec::new(),
            enable_interface_id: true,
            enable_remote_id: true,
            remote_id: None,
            vss: VssConfig::default(),
        }
    }
}

/// Virtual Subnet Selection configuration (RFC 6607).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VssConfig {
    /// Whether VSS is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// VSS type: 0 = NVT ASCII, 1 = RFC 2685 VPN-ID (7 bytes), 255 = Global/Default.
    pub vss_type: u8,
    /// VSS info bytes (ASCII string for type 0, 7-byte OUI+index for type 1, empty for type 255).
    #[serde(default)]
    pub vss_info: Vec<u8>,
    /// VPN name for local matching when server specifies a different VSS.
    #[serde(default)]
    pub vpn_name: Option<String>,
}

impl Default for VssConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            vss_type: 255,
            vss_info: Vec::new(),
            vpn_name: None,
        }
    }
}

/// SMF (Simplified Multicast Forwarding) configuration (RFC 6621).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmfConfig {
    /// Whether SMF is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// DPD cache entry time-to-live in seconds.
    #[serde(default = "default_dpd_window_secs")]
    pub dpd_window_secs: u64,
    /// DPD mode: "i-dpd" or "h-dpd".
    #[serde(default = "default_dpd_mode")]
    pub dpd_mode: String,
    /// Hash function for H-DPD: "murmur3" only for now.
    #[serde(default = "default_hash_fn")]
    pub hash_function: String,
}

fn default_dpd_window_secs() -> u64 {
    10
}

fn default_dpd_mode() -> String {
    "i-dpd".to_string()
}

fn default_hash_fn() -> String {
    "murmur3".to_string()
}

impl Default for SmfConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            dpd_window_secs: 10,
            dpd_mode: "i-dpd".to_string(),
            hash_function: "murmur3".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        let cfg = RelayConfig::default();
        assert_eq!(cfg.max_packet_size, 1500);
        assert!(cfg.interfaces.is_empty());
        assert!(cfg.dhcpv4.enable_option82);
        assert!(!cfg.smf.enabled);
    }

    #[test]
    fn config_serialize_deserialize() {
        let cfg = RelayConfig::default();
        let json = serde_json::to_string_pretty(&cfg).unwrap();
        let cfg2: RelayConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg2.max_packet_size, 1500);
    }
}
