use std::net::{SocketAddr, SocketAddrV4};

pub mod auth;
pub mod dns;
pub mod fragment;
pub mod frames;
pub mod h11c;
pub mod http;
pub mod socks;
pub mod tls;
pub mod udp;

#[cfg(feature = "quic")]
pub mod quic;

#[cfg(windows)]
pub mod windows;

// map v6 socket addr into v4 if possible
pub fn try_map_v4_addr(addr: SocketAddr) -> SocketAddr {
    if let SocketAddr::V6(v6) = addr {
        if let Some(v4a) = v6.ip().to_ipv4() {
            SocketAddr::V4(SocketAddrV4::new(v4a, v6.port()))
        } else {
            addr
        }
    } else {
        addr
    }
}

#[cfg(not(windows))]
pub fn set_keepalive(stream: &tokio::net::TcpStream) -> Result<(), easy_error::Error> {
    use easy_error::ResultExt;
    use nix::sys::socket::{setsockopt, sockopt::KeepAlive};
    use std::os::unix::prelude::AsRawFd;
    setsockopt(stream.as_raw_fd(), KeepAlive, &true).context("setsockopt")
}

#[cfg(windows)]
pub fn set_keepalive(stream: &tokio::net::TcpStream) -> Result<(), easy_error::Error> {
    use easy_error::ResultExt;
    use std::os::windows::prelude::AsRawSocket;
    windows::set_keepalive(stream.as_raw_socket() as _, true).context("setsockopt")
}
