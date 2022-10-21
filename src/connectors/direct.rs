use std::{
    io::ErrorKind,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use async_trait::async_trait;
use chashmap_async::CHashMap;
use easy_error::{bail, Error, ResultExt};
use log::{debug, trace};
use serde::{Deserialize, Serialize};
use tokio::net::{TcpSocket, UdpSocket};

use super::ConnectorRef;
use crate::{
    common::{
        dns::{AddressFamily, DnsConfig},
        frames::{Frame, FrameIO, FrameReader, FrameWriter},
        into_unspecified, set_keepalive,
        udp::udp_socket,
    },
    context::{make_buffered_stream, ContextRef, Feature, TargetAddress},
    GlobalState,
};

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectConnector {
    name: String,
    bind: Option<IpAddr>,
    #[serde(default)]
    dns: Arc<DnsConfig>,
    fwmark: Option<u32>,
    #[serde(default = "default_keepalive")]
    keepalive: bool,
    #[serde(skip)]
    udp_binds: Arc<CHashMap<String, SocketAddr>>,
}

fn default_keepalive() -> bool {
    true
}

pub fn from_value(value: &serde_yaml::Value) -> Result<ConnectorRef, Error> {
    let ret: DirectConnector = serde_yaml::from_value(value.clone()).context("parse config")?;
    Ok(Box::new(ret))
}

#[async_trait]
impl super::Connector for DirectConnector {
    async fn init(&mut self) -> Result<(), Error> {
        let dns = Arc::get_mut(&mut self.dns).unwrap();
        dns.init()?;
        if let Some(addr) = self.bind {
            debug!("bind address set, overriding dns family");
            if addr.is_ipv4() {
                dns.family = AddressFamily::V4Only;
            } else {
                dns.family = AddressFamily::V6Only;
            }
        }
        Ok(())
    }

    fn name(&self) -> &str {
        self.name.as_str()
    }

    fn features(&self) -> &[Feature] {
        &[Feature::TcpForward, Feature::UdpForward, Feature::UdpBind]
    }

    async fn connect(
        self: Arc<Self>,
        _state: Arc<GlobalState>,
        ctx: ContextRef,
    ) -> Result<(), Error> {
        let target = ctx.read().await.target();
        trace!("connecting to {}", target);
        let remote = match &target {
            TargetAddress::SocketAddr(addr) => *addr,
            TargetAddress::DomainPort(domain, port) => {
                self.dns.lookup_host(domain.as_str(), *port).await?
            }
            _ => unreachable!(),
        };

        trace!("target resolved to {}", remote);

        let feature = ctx.read().await.feature();
        match feature {
            Feature::TcpForward => {
                let server = if remote.is_ipv4() {
                    TcpSocket::new_v4().context("socket")?
                } else {
                    TcpSocket::new_v6().context("socket")?
                };
                if let Some(bind) = self.bind {
                    server.bind(SocketAddr::new(bind, 0)).context("bind")?;
                }
                let server = server.connect(remote).await.context("connect")?;
                let local = server.local_addr().context("local_addr")?;
                let remote = server.peer_addr().context("peer_addr")?;
                if self.keepalive {
                    set_keepalive(&server)?;
                }
                set_fwmark(&server, self.fwmark)?;
                ctx.write()
                    .await
                    .set_server_stream(make_buffered_stream(server))
                    .set_local_addr(local)
                    .set_server_addr(remote);
                trace!("connected to {:?}", target);
            }
            Feature::UdpForward | Feature::UdpBind => {
                let local = if let Some(bind) = self.bind {
                    SocketAddr::new(bind, 0)
                } else {
                    into_unspecified(remote)
                };
                let source = ctx
                    .read()
                    .await
                    .extra("udp-bind-source")
                    .unwrap_or("")
                    .to_owned();
                let local = if source.is_empty() {
                    local
                } else {
                    self.udp_binds
                        .get(&source)
                        .await
                        .map(|x| x.to_owned())
                        .unwrap_or(local)
                };

                let server = udp_socket(local, Some(remote), false).context("setup socket")?;
                let local = server.local_addr().context("local_addr")?;
                set_fwmark(&server, self.fwmark)?;
                ctx.write()
                    .await
                    .set_server_frames(setup_session(server, remote, self.dns.clone()))
                    .set_local_addr(local)
                    .set_server_addr(remote)
                    .set_extra("udp-bind-address", local.to_string());

                if !source.is_empty() {
                    self.udp_binds.insert(source, local).await;
                }
                trace!("connected to {:?}", target);
            }
            x => bail!("not supported feature {:?}", x),
        }
        Ok(())
    }
}

use std::io::Result as IoResult;
fn setup_session(socket: UdpSocket, target: SocketAddr, dns: Arc<DnsConfig>) -> FrameIO {
    let socket = Arc::new(socket);
    let frames = DirectFrames {
        socket,
        target,
        dns,
    };
    (Box::new(frames.clone()), Box::new(frames))
}

#[derive(Clone)]
struct DirectFrames {
    socket: Arc<UdpSocket>,
    target: SocketAddr,
    dns: Arc<DnsConfig>,
}

#[async_trait]
impl FrameReader for DirectFrames {
    async fn read(&mut self) -> IoResult<Option<Frame>> {
        // loop {
        let mut frame = Frame::new();
        let (_, _source) = frame.recv_from(&self.socket).await?;
        log::trace!("read udp frame: {:?}", frame);
        // if self.target.ip().is_unspecified() || self.target == source {
        return Ok(Some(frame));
        // } else {
        //     log::debug!("received unexpected udp frame from {:?}, dropping", source)
        // }
        // }
    }
}

#[async_trait]
impl FrameWriter for DirectFrames {
    async fn write(&mut self, frame: Frame) -> IoResult<usize> {
        let target = if self.target.ip().is_unspecified() {
            match frame.addr.as_ref() {
                Some(TargetAddress::SocketAddr(addr)) => *addr,
                Some(TargetAddress::DomainPort(domain, port)) => self
                    .dns
                    .lookup_host(domain.as_str(), *port)
                    .await
                    .map_err(|x| {
                        log::warn!("dns error: {}", x);
                        std::io::Error::new(ErrorKind::InvalidInput, "dns error")
                    })?,
                _ => return Err(std::io::Error::new(ErrorKind::InvalidInput, "bad target")),
            }
        } else {
            self.target
        };
        log::trace!("send udp frame: {:?}", frame);
        self.socket.send_to(frame.body(), target).await?;
        Ok(frame.len())
    }
    async fn shutdown(&mut self) -> IoResult<()> {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub fn set_fwmark<T: std::os::unix::prelude::AsRawFd>(
    sk: &T,
    mark: Option<u32>,
) -> Result<(), Error> {
    use nix::sys::socket::setsockopt;
    use nix::sys::socket::sockopt::Mark;
    if mark.is_none() {
        return Ok(());
    }
    let mark = mark.unwrap();
    setsockopt(sk.as_raw_fd(), Mark, &mark).context("setsockopt")
}

#[cfg(not(target_os = "linux"))]
pub fn set_fwmark<T>(_sk: &T, _mark: Option<u32>) -> Result<(), Error> {
    log::warn!("fwmark not supported on this platform");
    Ok(())
}
