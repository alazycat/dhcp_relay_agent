pub mod udp;

use std::io;
use std::net::SocketAddr;

use async_trait::async_trait;

/// Transport abstraction — a seam that allows substituting the UDP layer
/// (e.g. for mock testing without binding real sockets).
#[async_trait]
pub trait Transport: Send + Sync {
    /// Receive a datagram from the network.
    async fn recv_from(&mut self) -> io::Result<(Vec<u8>, SocketAddr)>;

    /// Send a datagram to the given destination.
    async fn send_to(&self, buf: &[u8], dst: SocketAddr) -> io::Result<usize>;

    /// Return the local socket address.
    fn local_addr(&self) -> io::Result<SocketAddr>;
}
