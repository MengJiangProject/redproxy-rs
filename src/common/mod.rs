use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};

pub mod auth;
pub mod dns;
pub mod fragment;
pub mod frames;
pub mod http;
pub mod http_proxy;
pub mod socket_ops;
pub mod socks;
pub mod tls;
pub mod udp;

#[cfg(test)]
mod rfc9298_tests;

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

pub fn into_unspecified(source: SocketAddr) -> SocketAddr {
    if source.is_ipv4() {
        SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0)
    } else {
        SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0)
    }
}
