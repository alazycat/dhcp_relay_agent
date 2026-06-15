use dhcproto::v4::{self, relay, DhcpOption, OptionCode};

use crate::error::RelayError;

/// A decoded Option 82 sub-option.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubOption {
    pub code: u8,
    pub data: Vec<u8>,
}

impl SubOption {
    pub fn new(code: u8, data: Vec<u8>) -> Self {
        Self { code, data }
    }
}

/// Convert dhcproto `RelayInfo` variants into our `SubOption`.
pub(crate) fn relay_info_to_sub_opt(info: &relay::RelayInfo) -> SubOption {
    match info {
        relay::RelayInfo::AgentCircuitId(data) => SubOption::new(1, data.clone()),
        relay::RelayInfo::AgentRemoteId(data) => SubOption::new(2, data.clone()),
        relay::RelayInfo::DocsisDeviceClass(d) => SubOption::new(4, d.to_be_bytes().to_vec()),
        relay::RelayInfo::LinkSelection(addr) => SubOption::new(5, addr.octets().to_vec()),
        relay::RelayInfo::SubscriberId(data) => SubOption::new(6, data.clone()),
        relay::RelayInfo::RelayAgentFlags(_flags) => SubOption::new(10, vec![0]),
        relay::RelayInfo::ServerIdentifierOverride(addr) => {
            SubOption::new(11, addr.octets().to_vec())
        }
        relay::RelayInfo::Unknown(unk) => {
            SubOption::new(u8::from(unk.code()), unk.data().to_vec())
        }
    }
}

/// Insert an Option 82 (Relay Agent Information) into the DHCPv4 message.
///
/// At least one of `circuit_id` or `remote_id` must be provided. The option
/// is inserted before the End option (code 255). If Option 82 is already
/// present, this function returns an error (reforwarded packets must not
/// have Option 82 re-added per RFC 3046 §2.1.1).
pub fn insert(
    msg: &mut v4::Message,
    circuit_id: Option<&[u8]>,
    remote_id: Option<&[u8]>,
) -> Result<(), RelayError> {
    if circuit_id.is_none() && remote_id.is_none() {
        return Err(RelayError::Config(
            "Option 82 requires at least one sub-option (circuit_id or remote_id)".into(),
        ));
    }

    if msg.opts().contains(OptionCode::RelayAgentInformation) {
        return Err(RelayError::Config(
            "Option 82 already present — reforwarded packets must not be modified".into(),
        ));
    }

    let mut agent_info = relay::RelayAgentInformation::default();

    if let Some(id) = circuit_id {
        agent_info.insert(relay::RelayInfo::AgentCircuitId(id.to_vec()));
    }
    if let Some(id) = remote_id {
        agent_info.insert(relay::RelayInfo::AgentRemoteId(id.to_vec()));
    }

    msg.opts_mut()
        .insert(DhcpOption::RelayAgentInformation(agent_info));

    Ok(())
}

/// Strip Option 82 from the message and return its sub-options.
///
/// Returns `None` if the message had no Option 82.
pub fn strip(msg: &mut v4::Message) -> Option<Vec<SubOption>> {
    let removed = msg.opts_mut().remove(OptionCode::RelayAgentInformation)?;

    match removed {
        DhcpOption::RelayAgentInformation(info) => {
            let sub_opts: Vec<SubOption> = info.iter().map(|(_, ri)| relay_info_to_sub_opt(ri)).collect();
            Some(sub_opts)
        }
        _ => None,
    }
}

/// Validate that the server correctly echoed the sent Option 82 sub-options.
///
/// Per RFC 3046 §3.2, the server MUST echo the Relay Agent Information option
/// exactly as received. This function performs a strict byte-level comparison.
pub fn validate_echo(received: &[SubOption], sent: &[SubOption]) -> bool {
    if received.len() != sent.len() {
        return false;
    }
    received
        .iter()
        .zip(sent.iter())
        .all(|(r, s)| r.code == s.code && r.data == s.data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dhcproto::{v4::MessageType, Decodable, Encodable};

    fn make_discover() -> v4::Message {
        let mut msg = v4::Message::default();
        msg.opts_mut()
            .insert(DhcpOption::MessageType(MessageType::Discover));
        msg
    }

    // ── insert tests ──

    #[test]
    fn insert_option82_with_both_sub_options() {
        let mut msg = make_discover();
        insert(&mut msg, Some(b"eth0"), Some(b"10.0.0.1")).unwrap();

        let opt = msg.opts().get(OptionCode::RelayAgentInformation).unwrap();
        if let DhcpOption::RelayAgentInformation(info) = opt {
            assert!(info.get(relay::RelayCode::AgentCircuitId).is_some());
            assert!(info.get(relay::RelayCode::AgentRemoteId).is_some());
        } else {
            panic!("expected RelayAgentInformation");
        }
    }

    #[test]
    fn insert_option82_with_circuit_id_only() {
        let mut msg = make_discover();
        insert(&mut msg, Some(b"eth0"), None).unwrap();

        let opt = msg.opts().get(OptionCode::RelayAgentInformation).unwrap();
        if let DhcpOption::RelayAgentInformation(info) = opt {
            assert!(info.get(relay::RelayCode::AgentCircuitId).is_some());
            assert!(info.get(relay::RelayCode::AgentRemoteId).is_none());
        } else {
            panic!("expected RelayAgentInformation");
        }
    }

    #[test]
    fn insert_option82_with_remote_id_only() {
        let mut msg = make_discover();
        insert(&mut msg, None, Some(b"10.0.0.1")).unwrap();

        let opt = msg.opts().get(OptionCode::RelayAgentInformation).unwrap();
        if let DhcpOption::RelayAgentInformation(info) = opt {
            assert!(info.get(relay::RelayCode::AgentCircuitId).is_none());
            assert!(info.get(relay::RelayCode::AgentRemoteId).is_some());
        } else {
            panic!("expected RelayAgentInformation");
        }
    }

    #[test]
    fn insert_option82_no_sub_options_is_error() {
        let mut msg = make_discover();
        let result = insert(&mut msg, None, None);
        assert!(result.is_err());
    }

    #[test]
    fn insert_option82_already_present_is_error() {
        let mut msg = make_discover();
        insert(&mut msg, Some(b"eth0"), None).unwrap();
        let result = insert(&mut msg, Some(b"eth1"), None);
        assert!(result.is_err());
    }

    // ── strip tests ──

    #[test]
    fn strip_option82_returns_sub_options() {
        let mut msg = make_discover();
        insert(&mut msg, Some(b"eth0"), Some(b"10.0.0.1")).unwrap();

        let sub_opts = strip(&mut msg).unwrap();
        assert_eq!(sub_opts.len(), 2);
        assert_eq!(sub_opts[0].code, 1); // AgentCircuitId
        assert_eq!(sub_opts[0].data, b"eth0");
        assert_eq!(sub_opts[1].code, 2); // AgentRemoteId
        assert_eq!(sub_opts[1].data, b"10.0.0.1");

        // Option 82 should no longer be in the message
        assert!(!msg.opts().contains(OptionCode::RelayAgentInformation));
    }

    #[test]
    fn strip_no_option82_returns_none() {
        let mut msg = make_discover();
        assert!(strip(&mut msg).is_none());
    }

    #[test]
    fn strip_zero_length_sub_option() {
        let mut msg = make_discover();
        let mut agent_info = relay::RelayAgentInformation::default();
        agent_info.insert(relay::RelayInfo::AgentCircuitId(vec![]));
        msg.opts_mut()
            .insert(DhcpOption::RelayAgentInformation(agent_info));

        let sub_opts = strip(&mut msg).unwrap();
        assert_eq!(sub_opts.len(), 1);
        assert_eq!(sub_opts[0].code, 1);
        assert!(sub_opts[0].data.is_empty());
    }

    // ── validate_echo tests ──

    #[test]
    fn validate_echo_exact_match() {
        let sent = vec![
            SubOption::new(1, b"eth0".to_vec()),
            SubOption::new(2, b"10.0.0.1".to_vec()),
        ];
        let received = vec![
            SubOption::new(1, b"eth0".to_vec()),
            SubOption::new(2, b"10.0.0.1".to_vec()),
        ];
        assert!(validate_echo(&received, &sent));
    }

    #[test]
    fn validate_echo_mismatch_data() {
        let sent = vec![SubOption::new(1, b"eth0".to_vec())];
        let received = vec![SubOption::new(1, b"eth1".to_vec())];
        assert!(!validate_echo(&received, &sent));
    }

    #[test]
    fn validate_echo_mismatch_length() {
        let sent = vec![
            SubOption::new(1, b"eth0".to_vec()),
            SubOption::new(2, b"10.0.0.1".to_vec()),
        ];
        let received = vec![SubOption::new(1, b"eth0".to_vec())];
        assert!(!validate_echo(&received, &sent));
    }

    #[test]
    fn validate_echo_empty_both() {
        assert!(validate_echo(&[], &[]));
    }

    // ── round-trip test (encode → decode) ──

    #[test]
    fn option82_round_trip() {
        let mut msg = make_discover();
        insert(&mut msg, Some(b"eth0"), Some(b"10.0.0.1")).unwrap();

        // Encode to bytes
        let mut buf = Vec::new();
        {
            let mut enc = dhcproto::Encoder::new(&mut buf);
            msg.encode(&mut enc).unwrap();
        }

        // Decode back
        let decoded = v4::Message::decode(&mut dhcproto::Decoder::new(&buf)).unwrap();

        let opt = decoded
            .opts()
            .get(OptionCode::RelayAgentInformation)
            .unwrap();
        if let DhcpOption::RelayAgentInformation(info) = opt {
            if let relay::RelayInfo::AgentCircuitId(data) =
                info.get(relay::RelayCode::AgentCircuitId).unwrap()
            {
                assert_eq!(data, b"eth0");
            } else {
                panic!("expected AgentCircuitId");
            }
            if let relay::RelayInfo::AgentRemoteId(data) =
                info.get(relay::RelayCode::AgentRemoteId).unwrap()
            {
                assert_eq!(data, b"10.0.0.1");
            } else {
                panic!("expected AgentRemoteId");
            }
        } else {
            panic!("expected RelayAgentInformation");
        }
    }
}
