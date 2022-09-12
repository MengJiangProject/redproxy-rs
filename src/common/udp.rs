use async_trait::async_trait;
use std::io::Result as IoResult;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

use super::frames::{Frame, FrameIO, FrameReader, FrameWriter};
use crate::context::TargetAddress;

#[cfg(unix)]
pub fn setup_udp_session(
    target: TargetAddress,
    local: SocketAddr,
    remote: SocketAddr,
    first_frame: Frame,
    transparent: bool,
) -> IoResult<FrameIO> {
    use super::set_nonblocking;
    use nix::sys::socket::sockopt::ReuseAddr;
    use nix::sys::socket::{bind, connect, setsockopt, socket, SockaddrLike, SockaddrStorage};
    use nix::sys::socket::{SockFlag, SockProtocol, SockType};
    use std::os::unix::prelude::FromRawFd;

    log::trace!("setup_udp_session local: {:?} remote: {:?}", local, remote);
    let local: SockaddrStorage = local.into();
    let remote: SockaddrStorage = remote.into();
    let fd = socket(
        local.family().unwrap(),
        SockType::Datagram,
        SockFlag::empty(),
        SockProtocol::Udp,
    )?;
    set_nonblocking(fd)?;
    setsockopt(fd, ReuseAddr, &true)?;
    #[cfg(any(target_os = "android", target_os = "linux"))]
    {
        use nix::sys::socket::sockopt::IpTransparent;
        if transparent {
            setsockopt(fd, IpTransparent, &true)?;
        }
    }
    bind(fd, &local)?;
    connect(fd, &remote)?;

    let socket = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
    let socket = UdpSocket::from_std(socket)?;
    let socket = Arc::new(socket);
    Ok((
        UdpFrameReader::new(target, socket.clone(), first_frame),
        UdpFrameWriter::new(socket),
    ))
}

#[cfg(windows)]
pub fn setup_udp_session(
    target: TargetAddress,
    local: SocketAddr,
    remote: SocketAddr,
    first_frame: Frame,
    _transparent: bool,
) -> IoResult<FrameIO> {
    use std::os::windows::prelude::FromRawSocket;

    use winapi::um::winsock2::SOCK_DGRAM;

    use crate::common::windows::{bind, connect, new_ip_socket, set_reuse_addr};

    log::trace!("setup_udp_session local: {:?} remote: {:?}", local, remote);
    let fd = new_ip_socket(local, SOCK_DGRAM)?;
    set_reuse_addr(fd, true)?;
    bind(fd, local)?;
    connect(fd, remote)?;

    let socket = unsafe { std::net::UdpSocket::from_raw_socket(fd as _) };
    let socket = UdpSocket::from_std(socket)?;
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
    fn new(target: TargetAddress, socket: Arc<UdpSocket>, first_frame: Frame) -> Box<Self> {
        Self {
            target,
            socket,
            first_frame: Some(first_frame),
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
