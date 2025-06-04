use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};

pub mod auth;
pub mod dns;
pub mod fragment;
pub mod frames;
pub mod http;
pub mod http_proxy;
pub mod socks;
pub mod tls;
pub mod udp;

#[cfg(feature = "quic")]
pub mod quic;

#[cfg(windows)]
pub mod windows;

#[cfg(target_os = "linux")]
pub mod splice;

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
    setsockopt(stream, KeepAlive, &true).context("setsockopt")
}

#[cfg(windows)]
pub fn set_keepalive(stream: &tokio::net::TcpStream) -> Result<(), easy_error::Error> {
    use easy_error::ResultExt;
    use std::os::windows::prelude::AsRawSocket;
    windows::set_keepalive(stream.as_raw_socket() as _, true).context("setsockopt")
}

pub fn into_unspecified(source: SocketAddr) -> SocketAddr {
    if source.is_ipv4() {
        SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0)
    } else {
        SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0)
    }
}
