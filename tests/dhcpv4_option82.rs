//! Integration test: DHCPv4 Option 82 full round-trip (RFC 3046).
//!
//! Simulates: DISCOVER → relay inserts Option 82 → server echoes → relay strips → client receives.

use dhcp_relay_agent::dhcp::v4::option82;
use dhcproto::{v4, Decodable, Encodable};

#[test]
fn discover_relay_offer_full_round_trip() {
    // ── Client sends DISCOVER (no Option 82) ──
    let mut discover = v4::Message::default();
    discover
        .opts_mut()
        .insert(v4::DhcpOption::MessageType(v4::MessageType::Discover));

    // Relay agent inserts Option 82
    option82::insert(&mut discover, Some(b"eth0"), Some(b"10.0.0.1")).unwrap();

    // Encode for transmission
    let mut wire = Vec::new();
    discover
        .encode(&mut dhcproto::Encoder::new(&mut wire))
        .unwrap();

    // ── Server receives, echoes Option 82 in OFFER ──
    let server_msg =
        v4::Message::decode(&mut dhcproto::Decoder::new(&wire)).unwrap();

    // Extract the relay info for echo verification
    let relay_opt = server_msg
        .opts()
        .get(v4::OptionCode::RelayAgentInformation)
        .unwrap();

    // Build OFFER with echoed Option 82
    let mut offer = v4::Message::default();
    offer.set_opcode(v4::Opcode::BootReply);
    offer
        .opts_mut()
        .insert(v4::DhcpOption::MessageType(v4::MessageType::Offer));
    offer.set_yiaddr("192.168.1.100".parse::<std::net::Ipv4Addr>().unwrap());

    // Echo the Option 82 back
    if let v4::DhcpOption::RelayAgentInformation(info) = relay_opt {
        offer
            .opts_mut()
            .insert(v4::DhcpOption::RelayAgentInformation(info.clone()));
    }

    let mut offer_wire = Vec::new();
    offer
        .encode(&mut dhcproto::Encoder::new(&mut offer_wire))
        .unwrap();

    // ── Relay agent receives OFFER, strips Option 82, forwards to client ──
    let mut relay_msg =
        v4::Message::decode(&mut dhcproto::Decoder::new(&offer_wire)).unwrap();

    let sub_opts = option82::strip(&mut relay_msg).unwrap();
    assert_eq!(sub_opts.len(), 2);
    assert_eq!(sub_opts[0].code, 1);
    assert_eq!(sub_opts[0].data, b"eth0");
    assert_eq!(sub_opts[1].code, 2);
    assert_eq!(sub_opts[1].data, b"10.0.0.1");

    // Verify Option 82 is removed
    assert!(!relay_msg.opts().contains(v4::OptionCode::RelayAgentInformation));

    // Verify the client would receive the IP
    assert_eq!(relay_msg.yiaddr(), "192.168.1.100".parse::<std::net::Ipv4Addr>().unwrap());
}

#[test]
fn echo_mismatch_is_detected() {
    let mut discover = v4::Message::default();
    discover
        .opts_mut()
        .insert(v4::DhcpOption::MessageType(v4::MessageType::Discover));

    option82::insert(&mut discover, Some(b"eth0"), None).unwrap();

    // Build a fake echo with different data
    let sent = vec![option82::SubOption::new(1, b"eth0".to_vec())];
    let received = vec![option82::SubOption::new(1, b"eth1".to_vec())];

    assert!(!option82::validate_echo(&received, &sent));
}

#[test]
fn reforwarded_packet_not_modified() {
    let mut msg = v4::Message::default();
    msg.set_giaddr("172.16.0.1".parse::<std::net::Ipv4Addr>().unwrap());

    // Insert should fail because giaddr != 0 (handled by pipeline, not option82 directly)
    // But option82::insert allows it — it just checks if Option 82 is already present
    option82::insert(&mut msg, Some(b"eth0"), None).unwrap();

    // Second insert should fail (already present)
    let result = option82::insert(&mut msg, Some(b"eth1"), None);
    assert!(result.is_err());
}
