use std::net::{SocketAddr, SocketAddrV4};

pub mod h11c;
pub mod http;

#[cfg(not(target_os = "windows"))]
#[path = "keepalive-unix.rs"]
pub mod keepalive;

#[cfg(target_os = "windows")]
#[path = "keepalive-windows.rs"]
pub mod keepalive;

#[cfg(feature = "quic")]
pub mod quic;

pub mod auth;
pub mod dns;
pub mod socks;
pub mod tls;

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
