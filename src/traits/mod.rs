use std::net::IpAddr;

/// Provides neighbor topology information for SMF relay set selection.
pub trait TopologyProvider: Send + Sync {
    /// Return the list of 1-hop neighbors on the given interface.
    fn neighbors(&self, interface: &str) -> Vec<IpAddr>;

    /// Return the list of 2-hop neighbors on the given interface (optional).
    fn two_hop_neighbors(&self, interface: &str) -> Vec<IpAddr> {
        let _ = interface;
        vec![]
    }
}

/// Decides whether to forward a multicast packet out a given interface.
pub trait RelaySetSelector: Send + Sync {
    /// Return true if the packet should be forwarded via the egress interface.
    fn should_forward(
        &self,
        ingress_iface: &str,
        prev_hop: IpAddr,
        src_addr: IpAddr,
        dst_group: IpAddr,
    ) -> bool;
}
