use std::{collections::HashMap, sync::Arc};

use anyhow::{Result, anyhow, bail};
use async_trait::async_trait;
use serde_yaml_ng::Value;
use tokio::sync::mpsc::Sender;

use crate::{
    config::Timeouts,
    context::{ContextManager, ContextRef},
};

mod http;
mod reverse;
mod socks;

#[cfg(feature = "quic")]
mod quic;

#[cfg(any(target_os = "android", target_os = "linux"))]
mod tproxy;

#[async_trait]
pub trait Listener: Send + Sync {
    async fn init(&mut self) -> Result<()> {
        Ok(())
    }
    async fn verify(&self) -> Result<()> {
        Ok(())
    }
    async fn listen(
        self: Arc<Self>,
        contexts: Arc<ContextManager>,
        timeouts: Timeouts,
        queue: Sender<ContextRef>,
    ) -> Result<()>;
    fn name(&self) -> &str;
}

pub fn from_config(cfg: &[Value]) -> Result<HashMap<String, Arc<dyn Listener>>> {
    let mut ret: HashMap<String, Arc<dyn Listener>> = Default::default();
    for val in cfg {
        let r = from_value(val)?;
        let old = ret.insert(r.name().to_owned(), r.into());
        if let Some(old) = old {
            bail!("duplicate listener name: {}", old.name());
        }
    }
    Ok(ret)
}

pub fn from_value(value: &Value) -> Result<Box<dyn Listener>> {
    let name = value
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing listener name"))?;
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
