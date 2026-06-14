//! Integration test: DHCPv4 VSS Virtual Subnet Selection (RFC 6607).

use dhcp_relay_agent::{config::VssConfig, dhcp::v4::vss};

#[test]
fn server_supports_vss_detected() {
    let cfg = VssConfig {
        enabled: true,
        vss_type: 0,
        vss_info: b"vpn-sales".to_vec(),
        vpn_name: Some("sales".into()),
    };

    let (vss_opt, _ctrl_opt) = vss::encode_sub_opts(&cfg).unwrap();

    // Simulate server response: VSS present, VSS-Control removed (server supports VSS)
    let server_echo: Vec<u8> = vss_opt.iter().chain(&[]).copied().collect();
    assert!(vss::check_server_support(&server_echo));
}

#[test]
fn server_does_not_support_vss_detected() {
    let cfg = VssConfig {
        enabled: true,
        vss_type: 0,
        vss_info: b"vpn-sales".to_vec(),
        vpn_name: Some("sales".into()),
    };

    let (vss_opt, ctrl_opt) = vss::encode_sub_opts(&cfg).unwrap();

    // Simulate server response: both VSS and VSS-Control present (no VSS support)
    let mut server_echo = vss_opt.clone();
    server_echo.extend_from_slice(&ctrl_opt);
    assert!(!vss::check_server_support(&server_echo));
}

#[test]
fn all_vss_types_encode() {
    // Type 0: NVT ASCII
    let cfg0 = VssConfig {
        enabled: true,
        vss_type: 0,
        vss_info: b"vpn-abc".to_vec(),
        vpn_name: None,
    };
    assert!(vss::encode_sub_opts(&cfg0).is_ok());

    // Type 1: VPN-ID (7 bytes)
    let cfg1 = VssConfig {
        enabled: true,
        vss_type: 1,
        vss_info: vec![0, 0, 0, 0, 0, 0, 1],
        vpn_name: None,
    };
    assert!(vss::encode_sub_opts(&cfg1).is_ok());

    // Type 255: Global
    let cfg255 = VssConfig {
        enabled: true,
        vss_type: 255,
        vss_info: vec![],
        vpn_name: None,
    };
    assert!(vss::encode_sub_opts(&cfg255).is_ok());
}
