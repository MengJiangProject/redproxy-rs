use std::sync::Arc;

use async_trait::async_trait;
use easy_error::{Error, ResultExt};
use log::trace;
use serde::{Deserialize, Serialize};

use super::ConnectorRef;
use crate::context::{make_buffered_stream, ContextRef, IOBufStream};

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

    async fn init(&mut self) -> Result<(), Error> {
        Ok(())
    }

    async fn connect(self: Arc<Self>, ctx: ContextRef) -> Result<IOBufStream, Error> {
        let target = ctx.read().await.target();
        trace!("connecting to {:?}", target);
        let server = make_buffered_stream(target.connect_tcp().await.context("connect")?);
        trace!("connected to {:?}", target);
        Ok(server)
    }
}
