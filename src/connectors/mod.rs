use crate::context::{ContextRef, Feature};
use anyhow::{Result, bail};
use async_trait::async_trait;
use serde_yaml_ng::Value;
use std::{collections::HashMap, sync::Arc};

mod direct;
pub mod http;
pub mod httpx;
pub mod loadbalance;
#[cfg(feature = "quic")]
mod quic;
mod socks;
#[cfg(feature = "ssh")]
pub mod ssh;

#[async_trait]
pub trait Connector: Send + Sync + std::any::Any {
    async fn init(&mut self) -> Result<()> {
        Ok(())
    }
    async fn verify(&self) -> Result<()> {
        Ok(())
    }
    async fn connect(self: Arc<Self>, ctx: ContextRef) -> Result<()>;
    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }
    fn name(&self) -> &str;
    fn features(&self) -> &[Feature] {
        &[Feature::TcpForward]
    }
    fn has_feature(&self, feature: Feature) -> bool {
        self.features().contains(&feature)
    }
}

pub type ConnectorRef = Box<dyn Connector>;
pub type ConnectorRegistry = HashMap<String, Arc<dyn Connector>>;

pub fn from_config(cfg: &[Value]) -> Result<ConnectorRegistry> {
    let mut ret: HashMap<String, Arc<dyn Connector>> = Default::default();
    for val in cfg {
        let r = from_value(val)?;
        let old = ret.insert(r.name().to_owned(), r.into());
        if let Some(old) = old {
            bail!("duplicate connector name: {}", old.name());
        }
    }
    Ok(ret)
}

pub fn from_value(value: &Value) -> Result<ConnectorRef> {
    let name = value
        .get("name")
        .ok_or_else(|| anyhow::anyhow!("missing connector name"))?;
    if name == "deny" {
        bail!("connector name \"deny\" is reserved")
    }
    let tname = value.get("type").unwrap_or(name).as_str().unwrap();
    match tname {
        "direct" => direct::from_value(value),
        "http" => http::from_value(value),
        "httpx" => httpx::from_value(value),
        "socks" => socks::from_value(value),
        "loadbalance" => loadbalance::from_value(value),
        #[cfg(feature = "quic")]
        "quic" => quic::from_value(value),
        #[cfg(feature = "ssh")]
        "ssh" => ssh::from_value(value),

        name => bail!("unknown connector type: {:?}", name),
    }
}
