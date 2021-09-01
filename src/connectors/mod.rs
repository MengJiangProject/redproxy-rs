use std::sync::Arc;

use crate::context::ContextRef;
use async_trait::async_trait;
use easy_error::{bail, err_msg, Error};
use serde_yaml::Value;

mod direct;
mod http;
#[cfg(feature = "quic")]
mod quic;
mod socks;

#[async_trait]
pub trait Connector {
    async fn init(&mut self) -> Result<(), Error>;
    // async fn connect(&self, ctx: Context) -> Result<(), Error>;
    async fn connect(self: Arc<Self>, ctx: ContextRef) -> Result<(), Error>;
    fn name(&self) -> &str;
}

pub type ConnectorRef = Box<dyn Connector + Send + Sync>;
pub fn config(connectors: &[Value]) -> Result<Vec<ConnectorRef>, Error> {
    let mut ret = Vec::with_capacity(connectors.len());
    for c in connectors {
        let c = from_value(c)?;
        ret.push(c);
    }
    Ok(ret)
}

pub fn from_value(value: &Value) -> Result<ConnectorRef, Error> {
    let name = value
        .get("name")
        .ok_or_else(|| err_msg("missing connector name"))?;
    if name == "deny" {
        bail!("connector name \"deny\" is reserved")
    }
    let tname = value.get("type").or(Some(name)).unwrap().as_str().unwrap();
    match tname {
        "direct" => direct::from_value(value),
        "http" => http::from_value(value),
        "socks" => socks::from_value(value),
        #[cfg(feature = "quic")]
        "quic" => quic::from_value(value),

        name => bail!("unknown connector type: {:?}", name),
    }
}
