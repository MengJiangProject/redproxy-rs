use std::net::{SocketAddr, SocketAddrV4};

use log::warn;
use tokio::process::Command;

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

pub mod socks;
pub mod tls;

pub mod dns;

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

pub async fn auth_cmd(cmd: &[String], user: &str, pass: &str) -> bool {
    if cmd.is_empty() {
        warn!("auth_cmd is empty");
        return false;
    }
    let cmd = cmd
        .iter()
        .map(|s| s.replace("$USER", user).replace("$PASS", pass))
        .collect::<Vec<_>>();
    let mut child = Command::new(&cmd[0]);
    if cmd.len() > 1 {
        child.args(&cmd[1..]);
    }
    let child = child.spawn();
    if let Ok(mut child) = child {
        let status = child.wait().await.unwrap();
        return status.success();
    }
    false
}
