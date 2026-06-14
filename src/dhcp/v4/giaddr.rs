use std::net::Ipv4Addr;

use dhcproto::v4;

/// Outcome of giaddr validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GiaddrDecision {
    /// giaddr = 0, no Option 82 — normal first relay.
    FirstRelay,
    /// giaddr = 0, Option 82 present, trusted downstream circuit.
    TrustedCircuit,
    /// giaddr = 0, Option 82 present, untrusted — drop packet.
    UntrustedCircuit,
    /// giaddr matches a local interface address — spoof attempt.
    Spoof,
    /// giaddr != 0, valid (not local) — reforwarded packet, do not modify.
    Reforwarded,
}

/// Validate the giaddr field of a DHCPv4 message against local interface addresses.
///
/// Per RFC 3046 §2.1.1:
/// - If giaddr = 0 and no Option 82: normal first relay (the relay agent will set giaddr).
/// - If giaddr = 0 and Option 82 present: check trusted circuit configuration.
/// - If giaddr != 0 and matches a local interface: spoof — drop.
/// - If giaddr != 0 and valid (non-local): reforwarded — do not modify.
pub fn validate(
    msg: &v4::Message,
    local_addrs: &[Ipv4Addr],
    is_trusted_circuit: bool,
) -> GiaddrDecision {
    let giaddr = msg.giaddr();
    let has_opt82 = msg.opts().contains(v4::OptionCode::RelayAgentInformation);

    if giaddr == Ipv4Addr::UNSPECIFIED {
        // giaddr = 0
        if has_opt82 {
            if is_trusted_circuit {
                GiaddrDecision::TrustedCircuit
            } else {
                GiaddrDecision::UntrustedCircuit
            }
        } else {
            GiaddrDecision::FirstRelay
        }
    } else if local_addrs.contains(&giaddr) {
        // giaddr matches a local interface — spoof
        GiaddrDecision::Spoof
    } else {
        // giaddr != 0 and not local — reforwarded
        GiaddrDecision::Reforwarded
    }
}

/// Set the giaddr field to the given interface IP address.
pub fn set_giaddr(msg: &mut v4::Message, iface_ip: Ipv4Addr) {
    msg.set_giaddr(iface_ip);
}

/// Check whether adding an Option 82 with `option_len` bytes would exceed `max_size`.
///
/// Returns true if the option can be safely added without exceeding the limit.
pub fn check_packet_size(current_size: usize, option_len: usize, max_size: usize) -> bool {
    current_size + option_len <= max_size
}

#[cfg(test)]
mod tests {
    use super::*;
    use dhcproto::v4::{self, DhcpOption, MessageType};

    fn local_addrs() -> Vec<Ipv4Addr> {
        vec![Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(192, 168, 1, 1)]
    }

    fn make_msg(giaddr: Ipv4Addr) -> v4::Message {
        let mut msg = v4::Message::default();
        msg.set_giaddr(giaddr);
        msg.opts_mut()
            .insert(DhcpOption::MessageType(MessageType::Discover));
        msg
    }

    #[test]
    fn first_relay_when_giaddr_zero_no_opt82() {
        let msg = make_msg(Ipv4Addr::UNSPECIFIED);
        assert_eq!(
            validate(&msg, &local_addrs(), false),
            GiaddrDecision::FirstRelay
        );
    }

    #[test]
    fn trusted_circuit_when_giaddr_zero_with_opt82_trusted() {
        let mut msg = make_msg(Ipv4Addr::UNSPECIFIED);
        msg.opts_mut().insert(DhcpOption::RelayAgentInformation(
            v4::relay::RelayAgentInformation::default(),
        ));
        assert_eq!(
            validate(&msg, &local_addrs(), true),
            GiaddrDecision::TrustedCircuit
        );
    }

    #[test]
    fn untrusted_circuit_when_giaddr_zero_with_opt82_untrusted() {
        let mut msg = make_msg(Ipv4Addr::UNSPECIFIED);
        msg.opts_mut().insert(DhcpOption::RelayAgentInformation(
            v4::relay::RelayAgentInformation::default(),
        ));
        assert_eq!(
            validate(&msg, &local_addrs(), false),
            GiaddrDecision::UntrustedCircuit
        );
    }

    #[test]
    fn spoof_when_giaddr_matches_local() {
        let msg = make_msg(Ipv4Addr::new(10, 0, 0, 1)); // matches local
        assert_eq!(
            validate(&msg, &local_addrs(), false),
            GiaddrDecision::Spoof
        );
    }

    #[test]
    fn reforwarded_when_giaddr_nonzero_not_local() {
        let msg = make_msg(Ipv4Addr::new(172, 16, 0, 1)); // not local
        assert_eq!(
            validate(&msg, &local_addrs(), false),
            GiaddrDecision::Reforwarded
        );
    }

    #[test]
    fn check_packet_size_within_limit() {
        assert!(check_packet_size(300, 50, 1500));
    }

    #[test]
    fn check_packet_size_exceeds_limit() {
        assert!(!check_packet_size(1480, 50, 1500));
    }

    #[test]
    fn set_giaddr_updates_field() {
        let mut msg = make_msg(Ipv4Addr::UNSPECIFIED);
        set_giaddr(&mut msg, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(msg.giaddr(), Ipv4Addr::new(10, 0, 0, 1));
    }
}
