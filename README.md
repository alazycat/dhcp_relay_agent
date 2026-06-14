# dhcp-relay-agent

A DHCP Relay Agent library implementing [RFC 3046] (DHCPv4 Relay Agent Information Option),
[RFC 6607] (Virtual Subnet Selection), and [RFC 6621] (Simplified Multicast Forwarding).

[RFC 3046]: https://datatracker.ietf.org/doc/html/rfc3046
[RFC 6607]: https://datatracker.ietf.org/doc/html/rfc6607
[RFC 6621]: https://datatracker.ietf.org/doc/html/rfc6621

## Feature Flags

| Flag      | Default | Description                      |
|-----------|:-------:|----------------------------------|
| `dhcpv4`  |   yes   | DHCPv4 relay (RFC 3046 + VSS)    |
| `dhcpv6`  |   no    | DHCPv6 relay (RFC 3315 + VSS)    |
| `smf`     |   no    | Simplified Multicast Forwarding (RFC 6621) |
| `full`    |   —     | Enables all three                |

```toml
[dependencies]
dhcp-relay-agent = { version = "0.1", features = ["dhcpv4", "dhcpv6", "smf"] }
```

## Quick Start

```rust
use dhcp_relay_agent::config::{InterfaceConfig, RelayConfig};
use dhcp_relay_agent::RelayAgent;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = RelayConfig {
        interfaces: vec![InterfaceConfig {
            name: "eth0".into(),
            ip_addr: "10.0.0.1:67".into(),
            trusted: false,
            enabled: true,
        }],
        ..Default::default()
    };

    let agent = RelayAgent::new(config)?;
    println!("Stats: {:?}", agent.stats());

    // Blocks until agent.shutdown() is called
    agent.run().await?;
    Ok(())
}
```

Run the bundled example (requires admin/root for port 67):
```bash
cargo run --example simple_relay
```

## Architecture

```
Public API Layer     RelayAgent, RelayConfig, RelayEvent, RelayStats
Service Layer        Dhcpv4Pipeline, Dhcpv6Pipeline, SmfEngine
Protocol Layer       dhcp/v4/*, dhcp/v6/*, smf/*
Transport Layer      UdpTransport (tokio async UDP)
```

Every DHCP message flows through an ordered **pipeline** of `PipelineStage` trait objects.
Each stage's `process(&mut PipelineContext) -> Result<bool, RelayError>` returns `Ok(false)`
to drop the packet or `Ok(true)` to continue to the next stage. `PipelineContext` carries the
raw buffer, source/destination addresses, interface name, and a metadata bag for inter-stage
communication.

### DHCPv4 Client→Server Pipeline
```
Parse → Validate → Option82 (insert) → VSS (insert) → Giaddr (set) → Forward
```

### DHCPv4 Server→Client Pipeline
```
Parse → Validate (echo check) → VSS (check removal) → Option82 (strip) → Forward
```

### DHCPv6 Client→Server Pipeline
```
Parse → Validate → Interface-ID (insert) → Remote-ID (insert) → VSS (insert) → Encapsulate in RELAY_FORW → Forward
```

### DHCPv6 Server→Client Pipeline
```
Decapsulate RELAY_REPL → Validate → VSS (check removal) → Remote-ID (check) → Interface-ID (check) → Forward
```

### SMF Forwarding Engine
```
Recv → DPD (duplicate detection) → 7 forwarding rules → DPD insert → Send
```

## Configuration

```rust
use dhcp_relay_agent::config::{
    RelayConfig, InterfaceConfig, Dhcpv4Config, Dhcpv6Config, VssConfig, SmfConfig,
};

let config = RelayConfig {
    interfaces: vec![InterfaceConfig {
        name: "eth0".into(),
        ip_addr: "10.0.0.1:67".into(),
        trusted: false,       // true = downstream trusted circuit
        enabled: true,
    }],
    dhcpv4: Dhcpv4Config {
        server_addrs: vec!["192.168.1.10:67".parse().unwrap()],
        enable_option82: true,
        circuit_id: Some("rack-3-slot-7".into()),
        remote_id: None,      // defaults to relay IP
    },
    dhcpv6: Dhcpv6Config {
        server_addrs: vec!["[2001:db8::1]:547".parse().unwrap()],
        enable_interface_id: true,
        enable_remote_id: true,
        remote_id: None,      // defaults to relay DUID
    },
    smf: SmfConfig {
        enabled: false,
        dpd_window_secs: 10,
        dpd_mode: "i-dpd".into(),   // or "h-dpd"
        hash_function: "murmur3".into(),
    },
    max_packet_size: 1500,
};
```

Configuration supports serde serialization/deserialization (JSON, YAML, etc.).

## API Overview

### `RelayAgent`

| Method | Description |
|--------|-------------|
| `new(config)` | Create from validated `RelayConfig` |
| `run()` | Start the main relay loop (async, blocks until shutdown) |
| `shutdown()` | Signal graceful shutdown |
| `config()` | Return reference to current config |
| `stats()` | Snapshot of runtime counters (`RelayStatsSnapshot`) |
| `stats_raw()` | Direct access to atomic counters (`&RelayStats`) |

### `RelayStats`

| Counter | Description |
|---------|-------------|
| `packets_received` | Total packets received |
| `packets_forwarded` | Total packets forwarded |
| `packets_dropped_parse_error` | Packets dropped due to parse failure |
| `packets_dropped_spoof` | Packets dropped as spoofed (giaddr check) |
| `option82_inserted` | Option 82 sub-options inserted |
| `option82_stripped` | Option 82 sub-options stripped |
| `vss_not_supported` | Server responses without VSS support |
| `smf_duplicates_detected` | SMF duplicate packets detected |
| `smf_forwarded` | SMF packets forwarded |

### Extensibility Traits (SMF)

- **`TopologyProvider`** — supplies 1-hop and 2-hop neighbor discovery for relay set selection
- **`RelaySetSelector`** — decides whether to forward a multicast packet out a given interface

## Security Invariants

- Packets with `giaddr == local_addr` are dropped as spoofed (RFC 3046 §2.1)
- Untrusted circuits (giaddr=0 + Option 82 present) are dropped
- Server replies must echo Option 82 exactly — mismatch causes drop
- Reforwarded packets (giaddr != 0) never get Option 82 added
- DPD TTL-based DoS protection: larger TTL accepted (pre-play countermeasure), smaller TTL rejected

## Development

```bash
cargo build                           # default features (dhcpv4)
cargo build --features full           # all features
cargo test                            # default features
cargo test --features full            # all features (114 tests)
cargo clippy -- -D warnings           # zero-warning policy
cargo doc --no-deps                   # must produce zero warnings
```

## License

MIT
