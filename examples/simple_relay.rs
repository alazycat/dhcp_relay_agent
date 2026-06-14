//! Minimal DHCPv4 relay agent example.
//!
//! Usage: `cargo run --example simple_relay`
//! Note: binding to port 67 requires root/administrator privileges.

use dhcp_relay_agent::config::{InterfaceConfig, RelayConfig};
use dhcp_relay_agent::RelayAgent;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = RelayConfig {
        interfaces: vec![InterfaceConfig {
            name: "eth0".into(),
            ip_addr: "0.0.0.0:67".into(),
            trusted: false,
            enabled: true,
        }],
        ..Default::default()
    };

    let agent = RelayAgent::new(config)?;

    println!("DHCPv4 relay agent starting...");
    println!("Stats: {:?}", agent.stats());

    // Run the relay loop (blocks until shutdown)
    if let Err(e) = agent.run().await {
        eprintln!("Relay agent error: {e}");
    }

    Ok(())
}
