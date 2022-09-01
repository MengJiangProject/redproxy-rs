use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::unix::prelude::AsRawFd,
    sync::Arc,
};

use async_trait::async_trait;
use bytes::BytesMut;
use easy_error::{bail, Error, ResultExt};
use log::{debug, trace, warn};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{duplex, split, AsyncReadExt, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf},
    net::{TcpSocket, UdpSocket},
    spawn,
};

use super::{ConnectorRef, Feature};
use crate::{
    common::{
        dns::{AddressFamily, DnsConfig},
        keepalive::set_keepalive,
        udp_buffer::UdpBuffer,
    },
    context::{make_buffered_stream, ContextRef, TargetAddress},
    GlobalState,
};

#[derive(Serialize, Deserialize, Debug)]
pub struct DirectConnector {
    name: String,
    bind: Option<IpAddr>,
    #[serde(default)]
    dns: DnsConfig,
    fwmark: Option<u32>,
    #[serde(default = "default_keepalive")]
    keepalive: bool,
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
        self.dns.init()?;
        if let Some(addr) = self.bind {
            debug!("bind address set, overriding dns family");
            if addr.is_ipv4() {
                self.dns.family = AddressFamily::V4Only;
            } else {
                self.dns.family = AddressFamily::V6Only;
            }
        }
        Ok(())
    }

    fn name(&self) -> &str {
        self.name.as_str()
    }

    fn features(&self) -> &[Feature] {
        &[Feature::TcpForward, Feature::UdpForward]
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
            Feature::UdpForward => {
                let local = if let Some(bind) = self.bind {
                    bind
                } else if remote.is_ipv4() {
                    IpAddr::V4(Ipv4Addr::UNSPECIFIED)
                } else {
                    IpAddr::V6(Ipv6Addr::UNSPECIFIED)
                };
                let local = SocketAddr::new(local, 0);
                let server = UdpSocket::bind(local).await.context("bind")?;
                server.connect(remote).await.context("connect")?;
                let local = server.local_addr().context("local_addr")?;
                set_fwmark(&server, self.fwmark)?;
                ctx.write()
                    .await
                    .set_server_stream(make_buffered_stream(setup_session(server)))
                    .set_local_addr(local)
                    .set_server_addr(remote);
                trace!("connected to {:?}", target);
            }
            x => bail!("not supported feature {:?}", x),
        }
        Ok(())
    }
}

fn setup_session(socket: UdpSocket) -> DuplexStream {
    let (mine, yours) = duplex(65536 * 10);
    let (read, write) = split(mine);
    let socket = Arc::new(socket);
    spawn(async move {
        let tx = tx_loop(read, socket.clone());
        let rx = rx_loop(write, socket.clone());
        // if any one finished, session closed
        tokio::select! {
            _ = rx => (),
            _ = tx => (),
        }
    });
    yours
}

async fn tx_loop(read: ReadHalf<DuplexStream>, socket: Arc<UdpSocket>) -> Result<(), Error> {
    let mut read = read;
    let mut buf = BytesMut::with_capacity(65536 * 10);
    loop {
        let mut pktbuf = buf.split();
        unsafe {
            pktbuf.set_len(pktbuf.capacity());
        }
        let size = read.read_buf(&mut pktbuf).await.context("read_buf")?;
        if size == 0 {
            return Ok(());
        }
        pktbuf.truncate(size);
        buf.unsplit(pktbuf);
        let mut offset = 0;
        while let Some(pkt) = UdpBuffer::try_from_buffer(&buf[offset..]) {
            if let Err(e) = socket.send(&pkt).await {
                warn!("unexpected error while sending udp packet: {:?}", e);
            }
            offset += pkt.len() + 8;
        }
        if offset > 0 && offset < buf.len() {
            let range = offset..buf.len();
            buf.copy_within(range.clone(), 0);
            buf.truncate(range.len())
        }
    }
}

async fn rx_loop(mut write: WriteHalf<DuplexStream>, socket: Arc<UdpSocket>) -> Result<(), Error> {
    loop {
        let mut buf = UdpBuffer::new();
        let rbuf = buf.as_read_buf();
        let size = socket.recv(rbuf).await.context("recv")?;
        let buf = buf.finialize(size);
        write.write_all(&buf).await.context("write_buf")?;
    }
}

fn set_fwmark<T: AsRawFd>(sk: &T, mark: Option<u32>) -> Result<(), Error> {
    #[cfg(target_os = "linux")]
    {
        use nix::sys::socket::setsockopt;
        use nix::sys::socket::sockopt::Mark;
        if mark.is_none() {
            return Ok(());
        }
        let mark = mark.unwrap();
        setsockopt(sk.as_raw_fd(), Mark, &mark).context("setsockopt")
    }
    #[cfg(not(target_os = "linux"))]
    {
        log::warn!("fwmark not supported on this platform");
        Ok(())
    }
}
