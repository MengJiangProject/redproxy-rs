use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use async_trait::async_trait;
use easy_error::{err_msg, Error, ResultExt};
use log::trace;
use serde::{Deserialize, Serialize};
use tokio::net::TcpSocket;

use super::ConnectorRef;
use crate::{
    common::keepalive::set_keepalive,
    context::{make_buffered_stream, ContextRef},
    GlobalState,
};

#[derive(Serialize, Deserialize, Debug)]
pub struct DirectConnector {
    name: String,
    bind: Option<IpAddr>,
}

pub fn from_value(value: &serde_yaml::Value) -> Result<ConnectorRef, Error> {
    let ret: DirectConnector = serde_yaml::from_value(value.clone()).context("parse config")?;
    Ok(Box::new(ret))
}

#[async_trait]
impl super::Connector for DirectConnector {
    fn name(&self) -> &str {
        self.name.as_str()
    }
    async fn connect(
        self: Arc<Self>,
        _state: Arc<GlobalState>,
        ctx: ContextRef,
    ) -> Result<(), Error> {
        let target = ctx.read().await.target();
        trace!("connecting to {:?}", target);
        let remote = target.resolve().await.context("resolve")?;
        trace!("target resolved to {:?}", remote);
        let mut remote = if let Some(bind) = self.bind {
            let is_v4 = bind.is_ipv4();
            remote
                .into_iter()
                .filter(|r| r.is_ipv4() == is_v4)
                .collect()
        } else {
            remote
        };
        let remote = remote.pop().ok_or(err_msg("failed to resolve"))?;
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
