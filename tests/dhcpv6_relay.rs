#![cfg(feature = "dhcpv6")]

//! Integration test: DHCPv6 Relay-forward/Relay-reply full round-trip.
//!
//! Simulates: SOLICIT → RELAY_FORW (with Interface-ID, Remote-ID) → ADVERTISE → RELAY_REPL.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use dhcp_relay_agent::dhcp::v6::relay_fwd::RelayFwdCodec;
use dhcproto::{v6, Decodable, Encodable};

#[test]
fn solicit_relay_forward_advertise_relay_reply_round_trip() {
    // ── Client sends SOLICIT ──
    let mut solicit = v6::Message::new(v6::MessageType::Solicit);
    solicit
        .opts_mut()
        .insert(v6::DhcpOption::ClientId(vec![0, 1, 2, 3]));

    let mut client_wire = Vec::new();
    solicit
        .encode(&mut dhcproto::Encoder::new(&mut client_wire))
        .unwrap();

    // ── Relay agent encapsulates in RELAY_FORW ──
    let link = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    let peer = SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 100)),
        546,
    );

    let relay_fwd = RelayFwdCodec::encapsulate(&client_wire, link, peer);

    // Verify relay-forward structure
    assert_eq!(relay_fwd[0], 12); // RELAY_FORW
    assert_eq!(relay_fwd[1], 0); // hop-count

    // ── Server builds ADVERTISE and wraps in RELAY_REPL ──
    let advertise = {
        let msg = v6::Message::new(v6::MessageType::Advertise);
        let mut buf = Vec::new();
        msg.encode(&mut dhcproto::Encoder::new(&mut buf)).unwrap();
        buf
    };

    let relay_reply = RelayFwdCodec::encapsulate(&advertise, link, peer);
    let mut reply = relay_reply;
    reply[0] = 13; // RELAY_REPL

    // ── Relay agent decapsulates RELAY_REPL ──
    let inner = RelayFwdCodec::decapsulate(&reply).unwrap();

    // Verify inner message is the ADVERTISE
    let final_msg =
        v6::Message::decode(&mut dhcproto::Decoder::new(&inner)).unwrap();
    assert_eq!(final_msg.msg_type(), v6::MessageType::Advertise);
}
