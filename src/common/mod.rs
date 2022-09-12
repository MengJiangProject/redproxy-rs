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
pub mod fragment;
pub mod frames;
pub mod socks;
pub mod tls;
pub mod udp;

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

#[cfg(unix)]
pub fn set_nonblocking(fd: i32) -> std::io::Result<()> {
    use nix::fcntl::{fcntl, FcntlArg, OFlag};
    let mut flags = fcntl(fd, FcntlArg::F_GETFD)?;
    flags |= libc::O_NONBLOCK;
    fcntl(fd, FcntlArg::F_SETFL(OFlag::from_bits_truncate(flags)))?;
    Ok(())
}
