use std::sync::Arc;

use async_trait::async_trait;
use easy_error::{Error, ResultExt};
use log::trace;
use serde::{Deserialize, Serialize};

use super::ConnectorRef;
use crate::{
    context::{make_buffered_stream, ContextRef},
    GlobalState,
};

#[derive(Serialize, Deserialize, Debug)]
pub struct DirectConnector {
    name: String,
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
        let server = target.connect_tcp().await.context("connect")?;
        let local = server.local_addr().context("local_addr")?;
        let remote = server.peer_addr().context("peer_addr")?;
        ctx.write()
            .await
            .set_server_stream(make_buffered_stream(server))
            .set_local_addr(local)
            .set_server_addr(remote);
        trace!("connected to {:?}", target);
        Ok(())
    }
}
