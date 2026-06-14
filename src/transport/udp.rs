use std::io;
use std::net::SocketAddr;

use tokio::net::UdpSocket;

pub struct UdpTransport {
    socket: UdpSocket,
    buf: Vec<u8>,
}

impl UdpTransport {
    pub async fn bind(addr: SocketAddr) -> io::Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        Ok(Self {
            socket,
            buf: vec![0u8; 65535],
        })
    }

    pub async fn recv_from(&mut self) -> io::Result<(Vec<u8>, SocketAddr)> {
        let (len, src) = self.socket.recv_from(&mut self.buf).await?;
        Ok((self.buf[..len].to_vec(), src))
    }

    pub async fn send_to(&self, buf: &[u8], dst: SocketAddr) -> io::Result<usize> {
        self.socket.send_to(buf, dst).await
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
}
