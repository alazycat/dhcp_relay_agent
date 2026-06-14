use std::net::IpAddr;

use crate::traits::RelaySetSelector;

/// Classic Flooding relay set selector: always forward.
///
/// This is the simplest relay set algorithm — every neighbor that is not the
/// previous hop receives a copy of the packet (RFC 6621 §7.1).
pub struct ClassicFlooding;

impl RelaySetSelector for ClassicFlooding {
    fn should_forward(
        &self,
        _ingress_iface: &str,
        _prev_hop: IpAddr,
        _src_addr: IpAddr,
        _dst_group: IpAddr,
    ) -> bool {
        true
    }
}
