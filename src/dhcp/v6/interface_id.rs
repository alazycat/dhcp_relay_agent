use dhcproto::v6::DhcpOption;

/// Encode an interface name into a DHCPv6 Interface-ID option (code 18).
pub fn encode(name: &str) -> DhcpOption {
    DhcpOption::InterfaceId(name.as_bytes().to_vec())
}

/// Decode a DHCPv6 Interface-ID option (code 18) into an interface name.
///
/// Returns `None` if the option is not InterfaceId or the data is not valid UTF-8.
pub fn decode(opt: &DhcpOption) -> Option<String> {
    match opt {
        DhcpOption::InterfaceId(data) => String::from_utf8(data.clone()).ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_round_trip() {
        let opt = encode("eth0");
        let name = decode(&opt).unwrap();
        assert_eq!(name, "eth0");
    }

    #[test]
    fn decode_non_interface_id_returns_none() {
        let opt = DhcpOption::ElapsedTime(1000);
        assert!(decode(&opt).is_none());
    }

    #[test]
    fn decode_invalid_utf8_returns_none() {
        let opt = DhcpOption::InterfaceId(vec![0xFF, 0xFE, 0x00]);
        assert!(decode(&opt).is_none());
    }
}
