use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use async_trait::async_trait;
use easy_error::{Error, ResultExt};
use log::{debug, trace};
use serde::{Deserialize, Serialize};
use tokio::net::TcpSocket;

use super::ConnectorRef;
use crate::{
    common::{
        dns::{AddressFamily, DnsConfig},
        keepalive::set_keepalive,
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
        set_keepalive(&server)?;
        ctx.write()
            .await
            .set_server_stream(make_buffered_stream(server))
            .set_local_addr(local)
            .set_server_addr(remote);
        trace!("connected to {:?}", target);
        Ok(())
    }
}
