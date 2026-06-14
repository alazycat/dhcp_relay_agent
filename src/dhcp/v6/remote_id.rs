use dhcproto::v6::{DhcpOption, OptionCode};

/// Encode a remote identifier into a DHCPv6 Remote-ID option (code 37).
///
/// dhcproto v0.14 has `OptionCode::RemoteId` but no dedicated `DhcpOption::RemoteId`
/// variant, so we construct the option manually.
pub fn encode(id: &[u8]) -> DhcpOption {
    DhcpOption::Unknown(dhcproto::v6::UnknownOption::new(
        OptionCode::RemoteId,
        id.to_vec(),
    ))
}

/// Decode a DHCPv6 Remote-ID option (code 37).
///
/// Returns `None` if the option code is not RemoteId (37).
pub fn decode(opt: &DhcpOption) -> Option<Vec<u8>> {
    match opt {
        DhcpOption::Unknown(unk) if unk.code() == OptionCode::RemoteId => {
            Some(unk.data().to_vec())
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_round_trip() {
        let opt = encode(b"remote-agent-1");
        let data = decode(&opt).unwrap();
        assert_eq!(data, b"remote-agent-1");
    }

    #[test]
    fn decode_wrong_code_returns_none() {
        let opt = DhcpOption::ElapsedTime(1000);
        assert!(decode(&opt).is_none());
    }

    #[test]
    fn remote_id_empty_data() {
        let opt = encode(b"");
        let data = decode(&opt).unwrap();
        assert!(data.is_empty());
    }
}
