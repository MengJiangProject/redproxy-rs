use async_trait::async_trait;
use std::io::Result as IoResult;
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::sync::Arc;
use tokio::{net::UdpSocket, sync::mpsc};

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

        tracing::trace!("udp_socket local: {:?} remote: {:?}", local, remote);
        let local: SockaddrStorage = local.into();
        let remote: Option<SockaddrStorage> =
            remote.filter(|x| !x.ip().is_unspecified()).map(Into::into);
        let fd = socket(
            local.family().unwrap(),
            SockType::Datagram,
            SockFlag::empty(),
            SockProtocol::Udp,
        )?;
        setsockopt(&fd, ReuseAddr, &true)?;
        if transparent {
            #[cfg(target_os = "linux")]
            {
                use nix::sys::socket::sockopt::IpTransparent;
                setsockopt(&fd, IpTransparent, &true)?;
            }
            #[cfg(not(target_os = "linux"))]
            {
                tracing::warn!("ip transparent not implemented")
            }
        }
        tracing::trace!("bind({})", local);
        bind(fd.as_raw_fd(), &local)?;
        if let Some(remote) = remote {
            tracing::trace!("connect({})", remote);
            connect(fd.as_raw_fd(), &remote)?;
        }

        unsafe { std::net::UdpSocket::from_raw_fd(fd.as_raw_fd()) }
    };

    #[cfg(windows)]
    let socket = {
        use crate::common::windows::{bind, connect, set_reuse_addr, socket};
        use std::os::windows::prelude::FromRawSocket;
        use winapi::um::winsock2::SOCK_DGRAM;

        tracing::trace!("setup_udp_session local: {:?} remote: {:?}", local, remote);
        let fd = socket(local, SOCK_DGRAM)?;
        set_reuse_addr(fd, true)?;
        if transparent {
            tracing::warn!("ip transparent not implemented")
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

pub type Receiver = mpsc::Receiver<Frame>;
pub type Sender = mpsc::Sender<Frame>;

pub fn setup_udp_session(
    target: TargetAddress,
    local: SocketAddr,
    remote: SocketAddr,
    extra_frame: Receiver,
    transparent: bool,
) -> IoResult<FrameIO> {
    let socket = udp_socket(local, Some(remote), transparent)?;
    let socket = Arc::new(socket);
    Ok((
        UdpFrameReader::new(target, socket.clone(), extra_frame),
        UdpFrameWriter::new(socket),
    ))
}

struct UdpFrameReader {
    socket: Arc<UdpSocket>,
    target: TargetAddress,
    extra_frame: Receiver,
}

impl UdpFrameReader {
    fn new(target: TargetAddress, socket: Arc<UdpSocket>, extra_frame: Receiver) -> Box<Self> {
        Self {
            target,
            socket,
            extra_frame,
        }
        .into()
    }
}

#[async_trait]
impl FrameReader for UdpFrameReader {
    async fn read(&mut self) -> IoResult<Option<Frame>> {
        let mut buf = Frame::new();
        tokio::select! {
            Some(f) = self.extra_frame.recv() => Ok(Some(f)),
            _ = buf.recv_from(&self.socket) => {
                buf.addr = Some(self.target.clone());
                Ok(Some(buf))
            }
        }
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
