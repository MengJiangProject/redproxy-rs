use async_trait::async_trait;
use bytes::BytesMut;
use easy_error::{Error, ResultExt};
use log::{debug, error, info, trace};
use nix::{
    cmsg_space,
    sys::socket::{
        bind, getsockopt, recvmsg, setsockopt, socket,
        sockopt::{
            Ip6tOriginalDst, IpTransparent, Ipv4OrigDstAddr, Ipv6OrigDstAddr, OriginalDst,
            ReuseAddr,
        },
        AddressFamily, ControlMessageOwned, MsgFlags, SockFlag, SockProtocol, SockType, SockaddrIn,
        SockaddrIn6, SockaddrLike, SockaddrStorage,
    },
};
use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use std::{
    io::IoSliceMut,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    os::unix::prelude::{AsRawFd, RawFd},
    sync::Arc,
};
use tokio::{io::unix::AsyncFd, net::TcpListener, sync::mpsc::Sender};

use crate::{
    common::{frames::Frame, set_keepalive, try_map_v4_addr, udp::setup_udp_session},
    context::{make_buffered_stream, ContextRef, ContextRefOps, Feature, TargetAddress},
    GlobalState,
};

use super::Listener;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TProxyListener {
    name: String,
    bind: SocketAddr,
    #[serde(default = "default_protocol")]
    protocol: Protocol,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
#[serde(rename_all = "camelCase")]
pub enum Protocol {
    Tcp,
    Udp,
}

fn default_protocol() -> Protocol {
    Protocol::Tcp
}

pub fn from_value(value: &Value) -> Result<Box<dyn Listener>, Error> {
    let ret: TProxyListener = serde_yaml::from_value(value.clone()).context("parse config")?;
    Ok(Box::new(ret))
}

#[async_trait]
impl Listener for TProxyListener {
    async fn listen(
        self: Arc<Self>,
        state: Arc<GlobalState>,
        queue: Sender<ContextRef>,
    ) -> Result<(), Error> {
        info!(
            "{} listening on {} protocol: {:?}",
            self.name, self.bind, self.protocol
        );
        match self.protocol {
            Protocol::Tcp => {
                let listener = TcpListener::bind(&self.bind).await.context("bind")?;
                tokio::spawn(async move {
                    loop {
                        self.clone()
                            .tcp_accept(&listener, &state, &queue)
                            .await
                            .map_err(|e| {
                                error!("{}: accept error: {} \ncause: {:?}", self.name, e, e.cause)
                            })
                            .unwrap_or(());
                    }
                });
            }
            Protocol::Udp => {
                let listener = TproxyUdpSocket::bind(self.bind).context("bind")?;
                tokio::spawn(async move {
                    loop {
                        self.clone()
                            .udp_accept(&listener, &state, &queue)
                            .await
                            .map_err(|e| {
                                error!("{}: accept error: {} \ncause: {:?}", self.name, e, e.cause)
                            })
                            .unwrap_or(());
                    }
                });
            }
        }
        Ok(())
    }

    fn name(&self) -> &str {
        &self.name
    }
}

impl TProxyListener {
    async fn tcp_accept(
        self: Arc<Self>,
        listener: &TcpListener,
        state: &Arc<GlobalState>,
        queue: &Sender<ContextRef>,
    ) -> Result<(), Error> {
        let (socket, source) = listener.accept().await.context("accept")?;
        debug!("connected from {:?}", source);
        set_keepalive(&socket)?;
        let source = crate::common::try_map_v4_addr(source);

        let target = if source.is_ipv4() {
            let dst = getsockopt(socket.as_raw_fd(), OriginalDst).context("getsockopt")?;
            let addr = Ipv4Addr::from(ntohl(dst.sin_addr.s_addr));
            let port = ntohs(dst.sin_port);
            TargetAddress::from((addr, port))
        } else {
            let dst = getsockopt(socket.as_raw_fd(), Ip6tOriginalDst).context("getsockopt")?;
            let addr = Ipv6Addr::from(dst.sin6_addr.s6_addr);
            let port = ntohs(dst.sin6_port);
            TargetAddress::from((addr, port))
        };

        trace!("{}: target={}", self.name, target);
        let ctx = state
            .contexts
            .create_context(self.name.to_owned(), source)
            .await;
        ctx.write()
            .await
            .set_target(target)
            .set_client_stream(make_buffered_stream(socket));
        ctx.enqueue(queue).await?;
        Ok(())
    }
    async fn udp_accept(
        self: &Arc<Self>,
        listener: &TproxyUdpSocket,
        state: &Arc<GlobalState>,
        queue: &Sender<ContextRef>,
    ) -> Result<(), Error> {
        let mut buf = BytesMut::zeroed(65536);
        let (size, src, dst) = listener.recv_msg(&mut buf).await.context("accept")?;
        let src = try_map_v4_addr(src);
        let dst = try_map_v4_addr(dst);
        buf.truncate(size);
        let mut buf = Frame::from_body(buf.freeze());
        buf.addr = Some(dst.into());
        debug!("{}: recv from {:?} length: {}", self.name, src, size);

        let ctx = state
            .contexts
            .create_context(self.name.to_owned(), src)
            .await;
        let frames =
            setup_udp_session(dst.into(), dst, src, Some(buf), true).context("setup session")?;
        ctx.write()
            .await
            .set_target(dst.into())
            .set_feature(Feature::UdpBind)
            .set_idle_timeout(state.timeouts.udp)
            .set_extra("udp-bind-source", src)
            .set_client_frames(frames);
        ctx.enqueue(queue).await?;
        Ok(())
    }
}

#[inline]
fn ntohl(x: u32) -> u32 {
    u32::from_be(x)
}

#[inline]
fn ntohs(x: u16) -> u16 {
    u16::from_be(x)
}

pub struct TproxyUdpSocket {
    inner: AsyncFd<RawFd>,
}

impl TproxyUdpSocket {
    pub fn bind(addr: SocketAddr) -> std::io::Result<Self> {
        let ss: SockaddrStorage = addr.into();

        let fd = socket(
            ss.family().unwrap(),
            SockType::Datagram,
            SockFlag::empty(),
            SockProtocol::Udp,
        )?;
        set_nonblocking(fd)?;
        setsockopt(fd, ReuseAddr, &true)?;
        setsockopt(fd, IpTransparent, &true)?;
        if addr.is_ipv4() {
            setsockopt(fd, Ipv4OrigDstAddr, &true)?;
        } else {
            setsockopt(fd, Ipv6OrigDstAddr, &true)?;
        }

        bind(fd, &ss)?;

        Ok(Self {
            inner: AsyncFd::new(fd)?,
        })
    }

    pub async fn recv_msg(
        &self,
        out: &mut [u8],
    ) -> std::io::Result<(usize, SocketAddr, SocketAddr)> {
        loop {
            let mut guard = self.inner.readable().await?;
            let mut iov = [IoSliceMut::new(out)];
            let mut cmsg_buffer = cmsg_space!(libc::sockaddr);
            let flags = MsgFlags::empty();
            match guard.try_io(|inner| {
                let fd = *inner.get_ref();
                recvmsg(fd, &mut iov, Some(&mut cmsg_buffer), flags)
                    .map_err(|errno| std::io::Error::from_raw_os_error(errno as i32))
            }) {
                Ok(result) => {
                    return result.map(|ret| {
                        let src: SockaddrStorage = ret.address.unwrap();
                        let src = match src.family() {
                            Some(AddressFamily::Inet) => {
                                SocketAddr::V4(src.as_sockaddr_in().cloned().unwrap().into())
                            }
                            Some(AddressFamily::Inet6) => {
                                SocketAddr::V6(src.as_sockaddr_in6().cloned().unwrap().into())
                            }
                            _ => panic!("unknown address family"),
                        };
                        let dst: SocketAddr = match ret.cmsgs().next() {
                            Some(ControlMessageOwned::Ipv4OrigDstAddr(addr)) => unsafe {
                                SocketAddr::V4(
                                    SockaddrIn::from_raw(
                                        &addr as *const _ as *const libc::sockaddr,
                                        None,
                                    )
                                    .unwrap()
                                    .into(),
                                )
                            },
                            Some(ControlMessageOwned::Ipv6OrigDstAddr(addr)) => unsafe {
                                SocketAddr::V6(
                                    SockaddrIn6::from_raw(
                                        &addr as *const _ as *const libc::sockaddr,
                                        None,
                                    )
                                    .unwrap()
                                    .into(),
                                )
                            },
                            Some(_) => panic!("Unexpected control message"),
                            None => panic!("No control message"),
                        };

                        (ret.bytes, src, dst)
                    })
                }
                Err(_would_block) => continue,
            }
        }
    }
}

pub fn set_nonblocking(fd: i32) -> std::io::Result<()> {
    use nix::fcntl::{fcntl, FcntlArg, OFlag};
    let mut flags = fcntl(fd, FcntlArg::F_GETFD)?;
    flags |= libc::O_NONBLOCK;
    fcntl(fd, FcntlArg::F_SETFL(OFlag::from_bits_truncate(flags)))?;
    Ok(())
}
