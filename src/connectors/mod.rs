use crate::context::{Context, IOBufStream};
use async_trait::async_trait;
use easy_error::{err_msg, Error};
use serde_yaml::Value;

pub mod direct;
pub mod http;
#[async_trait]
pub trait Connector {
    async fn init(&mut self) -> Result<(), Error>;
    // async fn connect(&self, ctx: Context) -> Result<(), Error>;
    async fn connect(&self, ctx: &Context) -> Result<IOBufStream, Error>;
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
    let tname = value.get("type").or(Some(name)).unwrap();
    match tname.as_str() {
        Some("direct") => direct::from_value(value),
        Some("http") => http::from_value(value),
        _ => Err(err_msg("not implemented")),
    }
}
