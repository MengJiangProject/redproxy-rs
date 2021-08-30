use std::sync::Arc;

use async_trait::async_trait;
use easy_error::{err_msg, Error};
use serde_yaml::Value;
use tokio::sync::mpsc::Sender;

use crate::context::Context;

mod http;
mod socks;

#[cfg(feature = "quic")]
mod quic;

#[cfg(any(target_os = "android", target_os = "linux"))]
mod tproxy;

#[async_trait]
pub trait Listener: std::fmt::Debug {
    async fn init(&mut self) -> Result<(), Error>;
    async fn listen(self: Arc<Self>, queue: Sender<Arc<Context>>) -> Result<(), Error>;
    fn name(&self) -> &str;
}

pub fn config(listeners: &[Value]) -> Result<Vec<Box<dyn Listener>>, Error> {
    let mut ret = Vec::with_capacity(listeners.len());
    for l in listeners {
        let ll = from_value(l)?;
        ret.push(ll);
    }
    Ok(ret)
}

pub fn from_value(value: &Value) -> Result<Box<dyn Listener>, Error> {
    let name = value
        .get("name")
        .ok_or_else(|| err_msg("missing listener name"))?;
    let tname = value.get("type").or(Some(name)).unwrap();
    match tname.as_str() {
        Some("http") => http::from_value(value),
        Some("socks") => socks::from_value(value),

        #[cfg(feature = "quic")]
        Some("quic") => quic::from_value(value),

        #[cfg(any(target_os = "android", target_os = "linux"))]
        Some("tproxy") => tproxy::from_value(value),

        _ => Err(err_msg("not implemented")),
    }
}
