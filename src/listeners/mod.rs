use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use easy_error::{bail, err_msg, Error};
use serde_yaml::Value;
use tokio::sync::mpsc::Sender;

use crate::{context::ContextRef, GlobalState};

mod http;
mod reverse;
mod socks;

#[cfg(feature = "quic")]
mod quic;

#[cfg(any(target_os = "android", target_os = "linux"))]
mod tproxy;

#[async_trait]
pub trait Listener: Send + Sync {
    async fn init(&mut self) -> Result<(), Error> {
        Ok(())
    }
    async fn verify(&self, _state: Arc<GlobalState>) -> Result<(), Error> {
        Ok(())
    }
    async fn listen(
        self: Arc<Self>,
        state: Arc<GlobalState>,
        queue: Sender<ContextRef>,
    ) -> Result<(), Error>;
    fn name(&self) -> &str;
}

pub fn from_config(cfg: &[Value]) -> Result<HashMap<String, Arc<dyn Listener>>, Error> {
    let mut ret: HashMap<String, Arc<dyn Listener>> = Default::default();
    for val in cfg {
        let r = from_value(val)?;
        ret.insert(r.name().to_owned(), r.into());
    }
    Ok(ret)
}

pub fn from_value(value: &Value) -> Result<Box<dyn Listener>, Error> {
    let name = value
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| err_msg("missing listener name"))?;
    let tname = value.get("type").and_then(Value::as_str).unwrap_or(name);
    match tname {
        "http" => http::from_value(value),
        "socks" => socks::from_value(value),
        "reverse" => reverse::from_value(value),

        #[cfg(feature = "quic")]
        "quic" => quic::from_value(value),

        #[cfg(any(target_os = "android", target_os = "linux"))]
        "tproxy" => tproxy::from_value(value),

        name => bail!("unknown listener type: {:?}", name),
    }
}
