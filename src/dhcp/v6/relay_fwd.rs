use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use crate::error::RelayError;

/// DHCPv6 message types.
pub const RELAY_FORW: u8 = 12;
pub const RELAY_REPL: u8 = 13;

/// DHCPv6 option code for relay-message.
const OPTION_RELAY_MSG: u16 = 9;

/// Fixed header size of a DHCPv6 relay message:
/// msg-type (1) + hop-count (1) + link-addr (16) + peer-addr (16) = 34 bytes.
const RELAY_HDR_LEN: usize = 34;

/// Minimum option TLV size: option-code (2) + option-len (2) = 4 bytes.
const OPTION_TLV_HDR: usize = 4;

/// Codec for DHCPv6 Relay-forward and Relay-reply messages (RFC 3315 / RFC 8415).
///
/// dhcproto v0.14 can decode/encode `RelayMessage` from bytes but cannot construct
/// one programmatically (all fields are private with no setters). This codec builds
/// and parses relay messages directly on the wire format.
pub struct RelayFwdCodec;

impl RelayFwdCodec {
    /// Encapsulate a client DHCPv6 message into a Relay-forward message.
    ///
    /// Returns the binary Relay-forward message ready to send to the DHCPv6 server.
    /// The hop-count is set to 0 (first relay). For subsequent hops, the caller
    /// must decode, increment hop-count, and re-encode.
    pub fn encapsulate(
        client_msg: &[u8],
        link_addr: Ipv6Addr,
        peer_addr: SocketAddr,
    ) -> Vec<u8> {
        let peer_ip = match peer_addr.ip() {
            IpAddr::V6(ip) => ip,
            IpAddr::V4(_) => Ipv6Addr::UNSPECIFIED,
        };

        // Header: msg-type + hop-count + link-addr + peer-addr
        let mut buf = Vec::with_capacity(RELAY_HDR_LEN + OPTION_TLV_HDR + client_msg.len());

        buf.push(RELAY_FORW);
        buf.push(0); // hop-count = 0
        buf.extend_from_slice(&link_addr.octets());
        buf.extend_from_slice(&peer_ip.octets());

        // Relay-message option (code 9)
        buf.extend_from_slice(&OPTION_RELAY_MSG.to_be_bytes());
        buf.extend_from_slice(&(client_msg.len() as u16).to_be_bytes());
        buf.extend_from_slice(client_msg);

        buf
    }

    /// Decapsulate a Relay-reply message, extracting the innermost client message.
    ///
    /// Handles nested Relay-reply (multi-hop relay) by recursively unwrapping until
    /// a non-relay message is found.
    pub fn decapsulate(relay_reply: &[u8]) -> Result<Vec<u8>, RelayError> {
        if relay_reply.len() < RELAY_HDR_LEN {
            return Err(RelayError::Parse(format!(
                "relay message too short: {} bytes (minimum {})",
                relay_reply.len(),
                RELAY_HDR_LEN
            )));
        }

        let msg_type = relay_reply[0];

        if msg_type != RELAY_REPL {
            return Err(RelayError::Parse(format!(
                "expected RELAY_REPL (13), got msg_type {}",
                msg_type
            )));
        }

        let inner = Self::extract_relay_msg(&relay_reply[RELAY_HDR_LEN..])?;

        // If the inner message is itself a Relay-reply, recurse (nested relay).
        if !inner.is_empty() && inner[0] == RELAY_REPL {
            return Self::decapsulate(&inner);
        }

        Ok(inner)
    }

    /// Extract the relay-message option (code 9) from a sequence of DHCPv6 options.
    fn extract_relay_msg(options: &[u8]) -> Result<Vec<u8>, RelayError> {
        let mut pos = 0;

        while pos + OPTION_TLV_HDR <= options.len() {
            let code =
                u16::from_be_bytes([options[pos], options[pos + 1]]);
            let len =
                u16::from_be_bytes([options[pos + 2], options[pos + 3]]) as usize;
            pos += OPTION_TLV_HDR;

            if pos + len > options.len() {
                return Err(RelayError::Parse(format!(
                    "truncated option: code {} length {} exceeds remaining {} bytes",
                    code,
                    len,
                    options.len() - pos
                )));
            }

            if code == OPTION_RELAY_MSG {
                return Ok(options[pos..pos + len].to_vec());
            }

            pos += len;
        }

        Err(RelayError::Parse(
            "no relay-message option (9) found in relay reply".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv6Addr, SocketAddr};

    /// A minimal DHCPv6 SOLICIT-like message: msg_type=1, xid=[0,0,1], no options.
    fn make_client_solicit() -> Vec<u8> {
        vec![1, 0, 0, 1] // SOLICIT (1), xid 0x000001
    }

    /// A minimal DHCPv6 ADVERTISE-like message: msg_type=2, xid=[0,0,1], no options.
    fn make_server_advertise() -> Vec<u8> {
        vec![2, 0, 0, 1] // ADVERTISE (2), xid 0x000001
    }

    fn peer_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)), 546)
    }

    // ── encapsulate tests ──

    #[test]
    fn encapsulate_produces_valid_relay_forward() {
        let client = make_client_solicit();
        let link = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let peer = peer_addr();

        let relay = RelayFwdCodec::encapsulate(&client, link, peer);

        // Verify header
        assert_eq!(relay[0], RELAY_FORW); // msg-type
        assert_eq!(relay[1], 0); // hop-count
        assert_eq!(&relay[2..18], &link.octets()); // link-addr
        assert_eq!(&relay[18..34], &Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets()); // peer-addr

        // Verify relay-message option
        let opt_code = u16::from_be_bytes([relay[34], relay[35]]);
        let opt_len = u16::from_be_bytes([relay[36], relay[37]]) as usize;
        assert_eq!(opt_code, OPTION_RELAY_MSG);
        assert_eq!(opt_len, client.len());
        assert_eq!(&relay[38..38 + opt_len], &client[..]);
    }

    #[test]
    fn encapsulate_hop_count_is_zero() {
        let client = make_client_solicit();
        let relay = RelayFwdCodec::encapsulate(
            &client,
            Ipv6Addr::LOCALHOST,
            peer_addr(),
        );
        assert_eq!(relay[1], 0);
    }

    // ── decapsulate tests ──

    #[test]
    fn decapsulate_single_layer_relay_reply() {
        let advertise = make_server_advertise();

        // Build a single-layer RELAY_REPL wrapping the advertise
        let mut reply = Vec::new();
        reply.push(RELAY_REPL);
        reply.push(0); // hop-count
        reply.extend_from_slice(&Ipv6Addr::LOCALHOST.octets()); // link-addr
        reply.extend_from_slice(&Ipv6Addr::LOCALHOST.octets()); // peer-addr
        reply.extend_from_slice(&OPTION_RELAY_MSG.to_be_bytes());
        reply.extend_from_slice(&(advertise.len() as u16).to_be_bytes());
        reply.extend_from_slice(&advertise);

        let inner = RelayFwdCodec::decapsulate(&reply).unwrap();
        assert_eq!(inner, advertise);
    }

    #[test]
    fn decapsulate_double_nested_relay_reply() {
        let advertise = make_server_advertise();

        // Inner relay-reply (hop 2)
        let mut inner_reply = Vec::new();
        inner_reply.push(RELAY_REPL);
        inner_reply.push(1); // hop-count
        inner_reply.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        inner_reply.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        inner_reply.extend_from_slice(&OPTION_RELAY_MSG.to_be_bytes());
        inner_reply.extend_from_slice(&(advertise.len() as u16).to_be_bytes());
        inner_reply.extend_from_slice(&advertise);

        // Outer relay-reply (hop 1)
        let mut outer_reply = Vec::new();
        outer_reply.push(RELAY_REPL);
        outer_reply.push(0); // hop-count
        outer_reply.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        outer_reply.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        outer_reply.extend_from_slice(&OPTION_RELAY_MSG.to_be_bytes());
        outer_reply.extend_from_slice(&(inner_reply.len() as u16).to_be_bytes());
        outer_reply.extend_from_slice(&inner_reply);

        let inner = RelayFwdCodec::decapsulate(&outer_reply).unwrap();
        assert_eq!(inner, advertise);
    }

    #[test]
    fn decapsulate_too_short_errors() {
        let result = RelayFwdCodec::decapsulate(&[RELAY_REPL, 0]);
        assert!(result.is_err());
    }

    #[test]
    fn decapsulate_wrong_msg_type_errors() {
        let mut buf = vec![0u8; RELAY_HDR_LEN];
        buf[0] = 1; // not RELAY_REPL
        let result = RelayFwdCodec::decapsulate(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn decapsulate_no_relay_msg_option_errors() {
        let mut buf = vec![0u8; RELAY_HDR_LEN];
        buf[0] = RELAY_REPL;
        let result = RelayFwdCodec::decapsulate(&buf);
        assert!(result.is_err());
    }

    // ── round-trip test ──

    #[test]
    fn relay_forward_decoded_by_custom_parser() {
        let client = make_client_solicit();
        let link = Ipv6Addr::new(0xfe80, 0, 0, 0, 1, 2, 3, 4);
        let peer = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 100)),
            546,
        );

        let relay_fwd = RelayFwdCodec::encapsulate(&client, link, peer);

        // Parse the relay-forward manually and verify all fields
        assert_eq!(relay_fwd[0], RELAY_FORW);
        assert_eq!(relay_fwd[1], 0);
        assert_eq!(&relay_fwd[2..18], &link.octets());
        assert_eq!(
            &relay_fwd[18..34],
            &Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 100).octets()
        );

        let opt_code = u16::from_be_bytes([relay_fwd[34], relay_fwd[35]]);
        assert_eq!(opt_code, OPTION_RELAY_MSG);

        let opt_len = u16::from_be_bytes([relay_fwd[36], relay_fwd[37]]) as usize;
        assert_eq!(&relay_fwd[38..38 + opt_len], &client[..]);
    }

    #[test]
    fn encapsulate_with_ipv4_peer_uses_unspecified() {
        let client = make_client_solicit();
        let ipv4_peer = SocketAddr::new(IpAddr::V4("10.0.0.1".parse().unwrap()), 67);
        let relay = RelayFwdCodec::encapsulate(&client, Ipv6Addr::LOCALHOST, ipv4_peer);

        // peer-address should be :: (UNSPECIFIED) for IPv4 peer
        assert_eq!(&relay[18..34], &[0u8; 16]);
    }
}
