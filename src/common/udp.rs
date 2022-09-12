use async_trait::async_trait;
use std::io::Result as IoResult;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

use super::frames::{Frame, FrameIO, FrameReader, FrameWriter};
use crate::context::TargetAddress;

// udp socket() with SO_REUSEADDR, IP_TRANSPARENT if transparent, bind() to local and connect() to remote if provided,
pub fn udp_socket(
    local: SocketAddr,
    remote: Option<SocketAddr>,
    transparent: bool,
) -> IoResult<UdpSocket> {
    #[cfg(unix)]
    let socket = {
        use nix::sys::socket::sockopt::ReuseAddr;
        use nix::sys::socket::{bind, connect, setsockopt, socket, SockaddrLike, SockaddrStorage};
        use nix::sys::socket::{SockFlag, SockProtocol, SockType};
        use std::os::unix::prelude::FromRawFd;

        log::trace!("udp_socket local: {:?} remote: {:?}", local, remote);
        let local: SockaddrStorage = local.into();
        let remote: Option<SockaddrStorage> = remote.map(Into::into);
        let fd = socket(
            local.family().unwrap(),
            SockType::Datagram,
            SockFlag::empty(),
            SockProtocol::Udp,
        )?;
        setsockopt(fd, ReuseAddr, &true)?;
        if transparent {
            #[cfg(target_os = "linux")]
            {
                use nix::sys::socket::sockopt::IpTransparent;
                setsockopt(fd, IpTransparent, &true)?;
            }
            #[cfg(not(target_os = "linux"))]
            {
                log::warn!("ip transparent not implemented")
            }
        }
        bind(fd, &local)?;
        if let Some(remote) = remote {
            connect(fd, &remote)?;
        }

        unsafe { std::net::UdpSocket::from_raw_fd(fd) }
    };

    #[cfg(windows)]
    let socket = {
        use crate::common::windows::{bind, connect, set_reuse_addr, socket};
        use std::os::windows::prelude::FromRawSocket;
        use winapi::um::winsock2::SOCK_DGRAM;

        log::trace!("setup_udp_session local: {:?} remote: {:?}", local, remote);
        let fd = socket(local, SOCK_DGRAM)?;
        set_reuse_addr(fd, true)?;
        if transparent {
            log::warn!("ip transparent not implemented")
        }
        bind(fd, local)?;
        if let Some(remote) = remote {
            connect(fd, remote)?;
        }

        unsafe { std::net::UdpSocket::from_raw_socket(fd as _) }
    };
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket)
}

pub fn setup_udp_session(
    target: TargetAddress,
    local: SocketAddr,
    remote: SocketAddr,
    first_frame: Option<Frame>,
    transparent: bool,
) -> IoResult<FrameIO> {
    let socket = udp_socket(local, Some(remote), transparent)?;
    let socket = Arc::new(socket);
    Ok((
        UdpFrameReader::new(target, socket.clone(), first_frame),
        UdpFrameWriter::new(socket),
    ))
}

struct UdpFrameReader {
    socket: Arc<UdpSocket>,
    target: TargetAddress,
    first_frame: Option<Frame>,
}

impl UdpFrameReader {
    fn new(target: TargetAddress, socket: Arc<UdpSocket>, first_frame: Option<Frame>) -> Box<Self> {
        Self {
            target,
            socket,
            first_frame,
        }
        .into()
    }
}

#[async_trait]
impl FrameReader for UdpFrameReader {
    async fn read(&mut self) -> IoResult<Option<Frame>> {
        if self.first_frame.is_some() {
            return Ok(self.first_frame.take());
        }
        let mut buf = Frame::new();
        buf.recv_from(&self.socket).await?;
        buf.addr = Some(self.target.clone());
        Ok(Some(buf))
    }
}

struct UdpFrameWriter {
    socket: Arc<UdpSocket>,
}

impl UdpFrameWriter {
    fn new(socket: Arc<UdpSocket>) -> Box<Self> {
        Self { socket }.into()
    }
}

#[async_trait]
impl FrameWriter for UdpFrameWriter {
    async fn write(&mut self, frame: Frame) -> IoResult<usize> {
        self.socket.send(frame.body()).await
    }
    async fn shutdown(&mut self) -> IoResult<()> {
        Ok(())
    }
}
