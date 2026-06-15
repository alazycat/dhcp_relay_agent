use dhcproto::v6::DhcpOption;

use crate::config::VssConfig;
use crate::error::RelayError;

/// DHCPv6 VSS option code (RFC 6607).
pub const VSS_OPTION_CODE: u16 = 68;

/// Encode a DHCPv6 VSS option (code 68).
///
/// Wire format: type(1) + info(variable)
pub fn encode(vss: &VssConfig) -> Result<DhcpOption, RelayError> {
    vss.validate_vss()?;

    let mut data = Vec::with_capacity(1 + vss.vss_info.len());
    data.push(vss.vss_type);
    data.extend_from_slice(&vss.vss_info);

    Ok(DhcpOption::Unknown(dhcproto::v6::UnknownOption::new(
        dhcproto::v6::OptionCode::Unknown(68),
        data,
    )))
}

/// Extract VSS info from a server reply.
///
/// Returns the VSS type and info if a VSS option (68) is found.
pub fn extract(opts: &[DhcpOption]) -> Option<(u8, Vec<u8>)> {
    for opt in opts {
        if let DhcpOption::Unknown(unk) = opt {
            if u16::from(unk.code()) == VSS_OPTION_CODE {
                let data = unk.data();
                if data.is_empty() {
                    return None;
                }
                let vss_type = data[0];
                let vss_info = data[1..].to_vec();
                return Some((vss_type, vss_info));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_type0_round_trip() {
        let cfg = VssConfig {
            enabled: true,
            vss_type: 0,
            vss_info: b"vpn-abc".to_vec(),
            vpn_name: None,
        };
        let opt = encode(&cfg).unwrap();
        let opts = vec![opt];
        let (t, info) = extract(&opts).unwrap();
        assert_eq!(t, 0);
        assert_eq!(info, b"vpn-abc");
    }

    #[test]
    fn encode_type1_vpn_id() {
        let cfg = VssConfig {
            enabled: true,
            vss_type: 1,
            vss_info: vec![0, 0, 0, 0, 0, 0, 1],
            vpn_name: None,
        };
        assert!(encode(&cfg).is_ok());
    }

    #[test]
    fn encode_type255_global() {
        let cfg = VssConfig {
            enabled: true,
            vss_type: 255,
            vss_info: vec![],
            vpn_name: None,
        };
        assert!(encode(&cfg).is_ok());
    }

    #[test]
    fn extract_no_vss_option_returns_none() {
        assert!(extract(&[]).is_none());
    }
}
