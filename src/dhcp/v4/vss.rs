use crate::config::VssConfig;
use crate::error::RelayError;

/// VSS sub-option codes inside Option 82 (RFC 6607).
pub const VSS_SUBOPT_CODE: u8 = 151;
pub const VSS_CONTROL_SUBOPT_CODE: u8 = 152;

/// VSS type constants.
pub const VSS_TYPE_NVT_ASCII: u8 = 0;
pub const VSS_TYPE_RFC2685_VPN_ID: u8 = 1;
pub const VSS_TYPE_GLOBAL: u8 = 255;

/// Encode VSS + VSS-Control as raw sub-option bytes for insertion into Option 82.
///
/// Returns (vss_bytes, vss_control_bytes) — each is a complete sub-option TLV.
pub fn encode_sub_opts(vss: &VssConfig) -> Result<(Vec<u8>, Vec<u8>), RelayError> {
    validate_vss_config(vss)?;

    // VSS sub-option (151): code(1) + len(1) + type(1) + info(variable)
    let mut vss_opt = Vec::with_capacity(3 + vss.vss_info.len());
    vss_opt.push(VSS_SUBOPT_CODE);
    vss_opt.push((1 + vss.vss_info.len()) as u8); // len = type + info
    vss_opt.push(vss.vss_type);
    vss_opt.extend_from_slice(&vss.vss_info);

    // VSS-Control sub-option (152): code(1) + len(0)
    let vss_control = vec![VSS_CONTROL_SUBOPT_CODE, 0];

    Ok((vss_opt, vss_control))
}

/// Check whether the server supports VSS by examining the echoed sub-options.
///
/// Returns true if the server removed VSS-Control (supports VSS), false if
/// VSS-Control is still present (server does not support VSS).
pub fn check_server_support(sub_opts_raw: &[u8]) -> bool {
    let mut pos = 0;
    while pos + 2 <= sub_opts_raw.len() {
        let code = sub_opts_raw[pos];
        let len = sub_opts_raw[pos + 1] as usize;
        if code == VSS_CONTROL_SUBOPT_CODE {
            return false; // Server does not support VSS
        }
        pos += 2 + len;
    }
    true // No VSS-Control found → server supports VSS
}

/// Validate VSS configuration constraints.
fn validate_vss_config(vss: &VssConfig) -> Result<(), RelayError> {
    match vss.vss_type {
        VSS_TYPE_NVT_ASCII => {
            // NVT ASCII: any length is valid
        }
        VSS_TYPE_RFC2685_VPN_ID => {
            if vss.vss_info.len() != 7 {
                return Err(RelayError::Config(format!(
                    "VPN-ID (type 1) requires exactly 7 bytes, got {}",
                    vss.vss_info.len()
                )));
            }
        }
        VSS_TYPE_GLOBAL => {
            if !vss.vss_info.is_empty() {
                return Err(RelayError::Config(
                    "Global VSS (type 255) requires empty vss_info".into(),
                ));
            }
        }
        _ => {
            return Err(RelayError::Config(format!(
                "unsupported VSS type: {}",
                vss.vss_type
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_type0_nvt_ascii() {
        let cfg = VssConfig {
            enabled: true,
            vss_type: VSS_TYPE_NVT_ASCII,
            vss_info: b"vpn-abc".to_vec(),
            vpn_name: None,
        };
        let (vss_opt, ctrl_opt) = encode_sub_opts(&cfg).unwrap();

        assert_eq!(vss_opt[0], VSS_SUBOPT_CODE);
        assert_eq!(vss_opt[1], 8); // len = 1 (type) + 7 ("vpn-abc")
        assert_eq!(vss_opt[2], VSS_TYPE_NVT_ASCII);
        assert_eq!(&vss_opt[3..], b"vpn-abc");

        assert_eq!(ctrl_opt, vec![VSS_CONTROL_SUBOPT_CODE, 0]);
    }

    #[test]
    fn encode_type1_vpn_id_valid() {
        let cfg = VssConfig {
            enabled: true,
            vss_type: VSS_TYPE_RFC2685_VPN_ID,
            vss_info: vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
            vpn_name: None,
        };
        assert!(encode_sub_opts(&cfg).is_ok());
    }

    #[test]
    fn encode_type1_vpn_id_invalid_length() {
        let cfg = VssConfig {
            enabled: true,
            vss_type: VSS_TYPE_RFC2685_VPN_ID,
            vss_info: vec![0x00, 0x01], // only 2 bytes, need 7
            vpn_name: None,
        };
        assert!(encode_sub_opts(&cfg).is_err());
    }

    #[test]
    fn encode_type255_global_valid() {
        let cfg = VssConfig {
            enabled: true,
            vss_type: VSS_TYPE_GLOBAL,
            vss_info: vec![],
            vpn_name: None,
        };
        assert!(encode_sub_opts(&cfg).is_ok());
    }

    #[test]
    fn encode_type255_global_nonempty_is_error() {
        let cfg = VssConfig {
            enabled: true,
            vss_type: VSS_TYPE_GLOBAL,
            vss_info: vec![1],
            vpn_name: None,
        };
        assert!(encode_sub_opts(&cfg).is_err());
    }

    #[test]
    fn server_support_true_when_no_vss_control() {
        // Create a sub-option blob with only VSS (151), no VSS-Control
        let sub_opts = [VSS_SUBOPT_CODE, 3, 0, b'a', b'b']; // VSS Type 0, info="ab"
        assert!(check_server_support(&sub_opts));
    }

    #[test]
    fn server_support_false_when_vss_control_present() {
        // VSS-Control present → server does NOT support VSS
        let sub_opts = [VSS_CONTROL_SUBOPT_CODE, 0, VSS_SUBOPT_CODE, 1, 0];
        assert!(!check_server_support(&sub_opts));
    }

    #[test]
    fn server_support_empty_sub_opts() {
        assert!(check_server_support(&[]));
    }
}
