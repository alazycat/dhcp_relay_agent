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
Pipeline Layer       dhcp/v4/pipeline, dhcp/v6/pipeline, SmfEngine
Protocol Layer       dhcp/v4/*, dhcp/v6/*, smf/*
Transport Layer      Transport trait + UdpTransport adapter (tokio async UDP)
```

Every DHCP message flows through an ordered **pipeline** of `PipelineStage` trait objects.
Each stage's `process(&mut PipelineContext) -> Result<bool, RelayError>` returns `Ok(false)`
to drop the packet or `Ok(true)` to continue to the next stage. `PipelineContext` carries the
working buffer, source/destination addresses, interface name, and a metadata bag for inter-stage
communication.

### DHCPv4 Client→Server Pipeline

```
Parse → Validate → [Option82 insert] → [VSS insert] → Giaddr (set) → Forward
```

Stages in brackets are conditional — controlled by `enable_option82` and `vss.enabled` config flags.
When disabled, basic relay (giaddr + forward) still works.

### DHCPv4 Server→Client Pipeline

```
Parse → [VSS check] → [Option82 strip+echo] → ReplyAddr → Forward
```

### DHCPv6 Client→Server Pipeline

```
Parse → [Interface-ID] → [Remote-ID] → [VSS insert] → RelayFwd (encapsulate) → Forward
```

Interface-ID and Remote-ID stages are controlled independently by `enable_interface_id` and
`enable_remote_id` flags. VSS is conditional on `vss.enabled`.

### DHCPv6 Server→Client Pipeline

```
Parse → [VSS extract] → RelayReply (decapsulate) → InterfaceIdExtract → Forward
```

### SMF Forwarding Engine

```
Recv → 7 forwarding rules → Relay set selection → DPD check → TTL decrement → Send
```

The `SmfEngine` integrates DPD duplicate detection, forwarding rule checks, and relay set
selection behind a single `process_packet()` entry point.

## Configuration

```rust
use dhcp_relay_agent::config::{
    RelayConfig, InterfaceConfig, Dhcpv4Config, Dhcpv6Config,
    VssConfig, SmfConfig, DpdMode, HashFunction,
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
        vss: VssConfig {
            enabled: false,
            vss_type: 0,
            vss_info: b"vpn-sales".to_vec(),
            vpn_name: Some("sales".into()),
        },
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
        dpd_mode: DpdMode::IDpd,
        hash_function: HashFunction::Murmur3,
    },
    max_packet_size: 1500,
};
```

Configuration supports serde serialization/deserialization (JSON, YAML, etc.).
`DpdMode` serializes as `"i-dpd"` / `"h-dpd"`; `HashFunction` as `"murmur3"`.

### VSS Configuration (RFC 6607)

`VssConfig` is shared between DHCPv4 and DHCPv6. Validation is centralized in
`VssConfig::validate_vss()` and runs at `RelayAgent::new()` time (fail-fast):

| `vss_type` | Description | `vss_info` constraint |
|-----------|-------------|----------------------|
| 0 | NVT ASCII VPN name | Any length |
| 1 | RFC 2685 VPN-ID | Exactly 7 bytes (3-byte OUI + 4-byte index) |
| 255 | Global / default | Must be empty |

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

All counters are `AtomicU64` fields on `RelayStats`. `RelayStatsSnapshot` (obtained via
`stats()`) is a serializable snapshot with plain `u64` values. Counters are declared via
the `define_stats!` macro — adding a new counter requires only one line.

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

### `Transport` trait

The `Transport` trait provides a seam for the UDP layer — `UdpTransport` is the default
adapter backed by `tokio::UdpSocket`. Handler functions accept `&impl Transport`, allowing
mock transports for testing without binding real sockets.

### Extensibility Traits (SMF)

- **`TopologyProvider`** — supplies 1-hop and 2-hop neighbor discovery for relay set selection
- **`RelaySetSelector`** — decides whether to forward a multicast packet out a given interface
- **`ClassicFlooding`** — built-in relay set selector (always forward)

## Security Invariants

- Packets with `giaddr == local_addr` are dropped as spoofed (RFC 3046 §2.1)
- Untrusted circuits (giaddr=0 + Option 82 present) are dropped
- Server replies must echo Option 82 exactly — mismatch causes drop
- Reforwarded packets (giaddr != 0) never get Option 82 added
- DPD TTL-based DoS protection: larger TTL accepted (pre-play countermeasure), smaller TTL rejected
- Client→server message types (Discover, Request, Inform, Decline, Release) are classified
  correctly; server→client types are routed to the reply pipeline with echo validation

## Module Map

```
src/
├── lib.rs              RelayAgent, RelayEvent, RelayStats, handler functions, spawn tasks
├── config.rs           RelayConfig, InterfaceConfig, Dhcpv4Config, Dhcpv6Config,
│                       VssConfig (with validate_vss), SmfConfig, DpdMode, HashFunction
├── error.rs            RelayError enum, RelayResult type alias
├── pipeline.rs         Pipeline, PipelineStage trait, PipelineContext (with modify_v4/v6)
├── traits.rs           TopologyProvider, RelaySetSelector traits
├── transport/
│   ├── mod.rs          Transport trait (async_trait)
│   └── udp.rs          UdpTransport adapter
├── dhcp/
│   ├── v4/
│   │   ├── pipeline.rs build_request, build_reply, all v4 stage implementations
│   │   ├── option82.rs SubOption type, insert, strip, validate_echo
│   │   ├── giaddr.rs   GiaddrDecision enum, validate
│   │   └── vss.rs      VSS sub-option encoding, server support check
│   └── v6/
│       ├── pipeline.rs build_request, build_reply, all v6 stage implementations
│       ├── relay_fwd.rs RelayFwdCodec (encapsulate/decapsulate), RELAY_FORW/RELAY_REPL
│       ├── interface_id.rs encode/decode Interface-ID option (18)
│       ├── remote_id.rs    encode/decode Remote-ID option (37)
│       └── vss.rs      VSS option (68) encode/extract
└── smf/
    ├── engine.rs       SmfEngine (process_packet entry point, decrement_ttl helper)
    ├── dpd.rs          DpdCache, DpdKey, h_dpd_hash, spawn_eviction_task
    ├── dpd_ipv4.rs     i_dpd_packet_id, h_dpd_packet_id (thin wrapper)
    ├── dpd_ipv6.rs     i_dpd_packet_id_from_option, h_dpd_packet_id (thin wrapper)
    ├── dpd_option.rs   SmfDpdOption encode/decode
    ├── forwarding.rs   check_forwarding_rules (7 rules from RFC 6621 §5)
    └── relay_set.rs    ClassicFlooding relay set selector
```

## Development

```bash
cargo build                           # default features (dhcpv4)
cargo build --features full           # all features
cargo test                            # default features
cargo test --features full            # all features (118 tests)
cargo clippy -- -D warnings           # zero-warning policy
cargo doc --no-deps                   # must produce zero warnings
```

## License

MIT
