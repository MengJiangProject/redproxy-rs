use async_trait::async_trait;
use bytes::BytesMut;
use chashmap_async::CHashMap;
use easy_error::{err_msg, Error, ResultExt};
use lru::LruCache;
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
use std::{io::Result as IoResult, os::fd::AsFd};
use std::{
    io::IoSliceMut,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    num::NonZeroUsize,
    os::unix::prelude::{AsRawFd, RawFd},
    sync::Arc,
};
use tokio::{
    io::unix::AsyncFd,
    net::{TcpListener, UdpSocket},
    sync::{
        mpsc::{channel, Receiver, Sender},
        Mutex,
    },
};
use tracing::{debug, error, info, trace};

use crate::{
    common::{
        frames::{Frame, FrameReader, FrameWriter},
        into_unspecified, set_keepalive, try_map_v4_addr,
        udp::{setup_udp_session, udp_socket},
    },
    context::{
        make_buffered_stream, Context, ContextCallback, ContextRef, ContextRefOps, Feature,
        TargetAddress,
    },
    GlobalState,
};

use super::Listener;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TProxyListener {
    name: String,
    bind: SocketAddr,
    #[serde(default = "default_protocol")]
    protocol: Protocol,
    #[serde(default = "default_max_udp_socket")]
    max_udp_socket: usize,
    #[serde(default)]
    udp_full_cone: bool,
    #[serde(skip)]
    inner: Option<Arc<Internals>>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
#[serde(rename_all = "camelCase")]
pub enum Protocol {
    Tcp,
    Udp,
}

struct Internals {
    sessions: CHashMap<(SocketAddr, SocketAddr), Session>,
    sockets: Mutex<LruCache<SocketAddr, UdpSocket>>,
}

fn default_protocol() -> Protocol {
    Protocol::Tcp
}

fn default_max_udp_socket() -> usize {
    128
}

pub fn from_value(value: &Value) -> Result<Box<dyn Listener>, Error> {
    let ret: TProxyListener = serde_yaml::from_value(value.clone()).context("parse config")?;
    Ok(Box::new(ret))
}

#[async_trait]
impl Listener for TProxyListener {
    async fn init(&mut self) -> Result<(), Error> {
        self.inner = Some(
            Internals {
                sessions: Default::default(),
                sockets: Mutex::new(LruCache::new(
                    NonZeroUsize::new(self.max_udp_socket)
                        .ok_or_else(|| err_msg("max_udp_socket must greater than zero"))?,
                )),
            }
            .into(),
        );
        Ok(())
    }
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
            let dst = getsockopt(&socket, OriginalDst).context("getsockopt")?;
            let addr = Ipv4Addr::from(ntohl(dst.sin_addr.s_addr));
            let port = ntohs(dst.sin_port);
            TargetAddress::from((addr, port))
        } else {
            let dst = getsockopt(&socket, Ip6tOriginalDst).context("getsockopt")?;
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
        if match dst.ip() {
            IpAddr::V4(ip) => ip.is_multicast() || ip.is_broadcast(),
            IpAddr::V6(ip) => ip.is_multicast() || is_link_local(ip),
        } {
            return Ok(());
        }
        buf.truncate(size);
        let mut buf = Frame::from_body(buf.freeze());
        buf.addr = Some(dst.into());

        trace!("{}: recv from {:?} length: {}", self.name, src, size);
        let inner = self.inner.as_ref().unwrap();
        let key = if self.udp_full_cone {
            (src, src)
        } else {
            (src, dst)
        };
        if let Some(mut session) = inner.sessions.get_mut(&key).await {
            session
                .add_frame(buf)
                .await
                .context("setup session failed")?;
        } else {
            let ctx = state
                .contexts
                .create_context(self.name.to_owned(), src)
                .await;
            let (tx, rx) = channel(100);
            let mut session = Session::new(src, tx);
            session
                .add_frame(buf)
                .await
                .context("setup session failed")?;
            inner.sessions.insert(key, session).await;
            if self.udp_full_cone {
                let r = TproxyReader::new(rx);
                let w = TproxyWriter::new(src, inner.clone());
                let target = into_unspecified(dst).into();
                ctx.write()
                    .await
                    .set_target(target)
                    .set_feature(Feature::UdpBind)
                    .set_extra("udp-bind-source", src)
                    .set_client_frames((r, w));
            } else {
                let frames =
                    setup_udp_session(dst.into(), dst, src, rx, true).context("setup session")?;
                ctx.write()
                    .await
                    .set_target(dst.into())
                    .set_feature(Feature::UdpForward)
                    .set_client_frames(frames);
            }
            ctx.write()
                .await
                .set_callback(TproxyCallback::new(key, inner.clone()))
                .set_idle_timeout(state.timeouts.udp);
            ctx.enqueue(queue).await?;
        }

        Ok(())
    }
}

fn is_link_local(ip: Ipv6Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 0xfe && octets[1] & 0xc0 == 0x80
}

#[inline]
fn ntohl(x: u32) -> u32 {
    u32::from_be(x)
}

#[inline]
fn ntohs(x: u16) -> u16 {
    u16::from_be(x)
}

pub fn set_nonblocking<T: AsFd>(fd: T) -> std::io::Result<()> {
    use nix::fcntl::{fcntl, FcntlArg, OFlag};
    let mut flags = fcntl(&fd, FcntlArg::F_GETFD)?;
    flags |= libc::O_NONBLOCK;
    fcntl(&fd, FcntlArg::F_SETFL(OFlag::from_bits_truncate(flags)))?;
    Ok(())
}

struct TproxyUdpSocket {
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
        set_nonblocking(&fd)?;
        setsockopt(&fd, ReuseAddr, &true)?;
        setsockopt(&fd, IpTransparent, &true)?;
        if addr.is_ipv4() {
            setsockopt(&fd, Ipv4OrigDstAddr, &true)?;
        } else {
            setsockopt(&fd, Ipv6OrigDstAddr, &true)?;
        }

        bind(fd.as_raw_fd(), &ss)?;

        Ok(Self {
            inner: AsyncFd::new(fd.as_raw_fd())?,
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
                        let mut cmsgs = ret.cmsgs().expect("cmsgs");
                        let dst: SocketAddr = match cmsgs.next() {
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

struct Session {
    source: SocketAddr,
    queue: Sender<Frame>,
}

impl Session {
    fn new(source: SocketAddr, queue: Sender<Frame>) -> Self {
        Self { source, queue }
    }
    async fn add_frame(&mut self, frame: Frame) -> IoResult<()> {
        if self.queue.try_send(frame).is_err() {
            tracing::warn!("buffer overflow: src={}, dropping.", self.source)
        }
        Ok(())
    }
}

struct TproxyReader {
    queue: Receiver<Frame>,
}

impl TproxyReader {
    fn new(queue: Receiver<Frame>) -> Box<Self> {
        Self { queue }.into()
    }
}

impl Drop for TproxyReader {
    fn drop(&mut self) {
        trace!("Tproxy reader dropped");
    }
}

#[async_trait]
impl FrameReader for TproxyReader {
    async fn read(&mut self) -> IoResult<Option<Frame>> {
        Ok(self.queue.recv().await)
    }
}

struct TproxyWriter {
    client: SocketAddr,
    inner: Arc<Internals>,
}

impl TproxyWriter {
    fn new(client: SocketAddr, inner: Arc<Internals>) -> Box<Self> {
        Self { inner, client }.into()
    }
}

#[async_trait]
impl FrameWriter for TproxyWriter {
    async fn write(&mut self, frame: Frame) -> IoResult<usize> {
        let src = frame
            .addr
            .as_ref()
            .and_then(|x| x.as_socket_addr())
            .unwrap();
        let mut sockets = self.inner.sockets.lock().await;
        let socket = if let Some(socket) = sockets.get(&src) {
            socket
        } else {
            let socket = udp_socket(src, None, true)?;
            sockets.get_or_insert(src, || socket)
        };
        socket.send_to(frame.body(), self.client).await?;
        Ok(frame.len())
    }
    async fn shutdown(&mut self) -> IoResult<()> {
        let key = (self.client, self.client);
        self.inner.sessions.remove(&key).await;
        Ok(())
    }
}

struct TproxyCallback {
    key: (SocketAddr, SocketAddr),
    inner: Arc<Internals>,
}

impl TproxyCallback {
    fn new(key: (SocketAddr, SocketAddr), inner: Arc<Internals>) -> Self {
        Self { key, inner }
    }
}

#[async_trait]
impl ContextCallback for TproxyCallback {
    async fn on_error(&self, _ctx: &mut Context, _error: Error) {
        self.inner.sessions.remove(&self.key).await;
    }
    async fn on_finish(&self, _ctx: &mut Context) {
        self.inner.sessions.remove(&self.key).await;
    }
}
