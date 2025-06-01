use async_trait::async_trait;
use cidr::AnyIpCidr;
use easy_error::{bail, Error};
use milu::script::{Call, ScriptContext};
use milu::{
    function,
    script::{Accessible, Callable, Evaluatable, NativeObject, ScriptContextRef, Type, Value},
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::{convert::TryInto, net::IpAddr};
use tracing::warn;

use crate::context::{ContextProps, TargetAddress};

pub fn create_context(props: Arc<ContextProps>) -> ScriptContext {
    let mut ctx = ScriptContext::new(Some(Default::default()));
    let adapter = ContextAdaptor::new(props);
    ctx.set("request".to_string(), adapter.into());
    ctx.set("cidr_match".to_string(), CidrMatch::stub().into());
    ctx
}

#[derive(Clone, Hash)]
struct ContextAdaptor {
    req: Arc<ContextProps>,
}

impl ContextAdaptor {
    fn new(req: Arc<ContextProps>) -> Self {
        Self { req }
    }
}

#[async_trait]
impl Accessible for ContextAdaptor {
    fn names(&self) -> Vec<&str> {
        vec!["listener", "connector", "source", "target", "feature"]
    }

    fn get(&self, name: &str) -> Result<Value, Error> {
        match name {
            "listener" => Ok(self.req.listener.clone().into()),
            "connector" => Ok(self.req.connector.as_deref().unwrap_or("").into()),
            "target" => Ok(self.req.target.clone().into()),
            "source" => Ok(SocketAddress(self.req.source).into()),
            "feature" => Ok(self.req.request_feature.to_string().into()),
            _ => bail!("property undefined: {}", name),
        }
    }

    async fn type_of(&self, name: &str, ctx: ScriptContextRef) -> Result<Type, Error> {
        // Made async
        match name {
            "listener" | "connector" | "feature" => Ok(Type::String),
            "target" | "source" => self.get(name)?.type_of(ctx).await, // Added await
            _ => bail!("undefined field: {}", name),
        }
    }
}

impl NativeObject for ContextAdaptor {
    fn as_accessible(&self) -> Option<&dyn Accessible> {
        Some(self)
    }
}

impl std::fmt::Display for ContextAdaptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ContextAdaptor(id={})", self.req.id)
    }
}

impl std::fmt::Debug for ContextAdaptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ContextAdaptor(id={})", self.req.id)
    }
}

impl NativeObject for TargetAddress {
    fn as_evaluatable(&self) -> Option<&dyn Evaluatable> {
        Some(self)
    }
    fn as_accessible(&self) -> Option<&dyn Accessible> {
        Some(self)
    }
}

#[async_trait]
impl Evaluatable for TargetAddress {
    async fn type_of(&self, _ctx: ScriptContextRef) -> Result<Type, Error> {
        // Made async
        Ok(Type::String)
    }

    async fn value_of(&self, _ctx: ScriptContextRef) -> Result<Value, Error> {
        Ok(self.to_string().into())
    }
}

#[async_trait]
impl Accessible for TargetAddress {
    fn names(&self) -> Vec<&str> {
        vec!["host", "port", "type"]
    }

    fn get(&self, name: &str) -> Result<Value, Error> {
        match name {
            "host" => Ok(self.host().into()),
            "port" => Ok(self.port().into()),
            "type" => Ok(self.r#type().into()),
            _ => bail!("property undefined: {}", name),
        }
    }

    async fn type_of(&self, name: &str, _ctx: ScriptContextRef) -> Result<Type, Error> {
        // Made async
        match name {
            "host" | "port" | "type" => Ok(Type::String),
            _ => bail!("undefined"),
        }
    }
}

#[derive(Debug, Hash)]
struct SocketAddress(SocketAddr);
impl SocketAddress {
    pub fn host(&self) -> String {
        match &self.0 {
            SocketAddr::V4(x) => x.ip().to_string(),
            SocketAddr::V6(x) => x.ip().to_string(),
        }
    }
    pub fn port(&self) -> u16 {
        match &self.0 {
            SocketAddr::V4(x) => x.port(),
            SocketAddr::V6(x) => x.port(),
        }
    }
    pub fn r#type(&self) -> &str {
        if self.0.is_ipv4() {
            "ipv4"
        } else {
            "ipv6"
        }
    }
}

impl NativeObject for SocketAddress {
    fn as_evaluatable(&self) -> Option<&dyn Evaluatable> {
        Some(self)
    }
    fn as_accessible(&self) -> Option<&dyn Accessible> {
        Some(self)
    }
}

#[async_trait]
impl Evaluatable for SocketAddress {
    async fn type_of(&self, _ctx: ScriptContextRef) -> Result<Type, Error> {
        // Made async
        Ok(Type::String)
    }

    async fn value_of(&self, _ctx: ScriptContextRef) -> Result<Value, Error> {
        Ok(self.0.to_string().into())
    }
}

#[async_trait]
impl Accessible for SocketAddress {
    fn names(&self) -> Vec<&str> {
        vec!["host", "port", "type"]
    }

    fn get(&self, name: &str) -> Result<Value, Error> {
        match name {
            "host" => Ok(self.host().into()),
            "port" => Ok(self.port().into()),
            "type" => Ok(self.r#type().into()),
            _ => bail!("property undefined: {}", name),
        }
    }

    async fn type_of(&self, name: &str, _ctx: ScriptContextRef) -> Result<Type, Error> {
        // Made async
        match name {
            "host" | "port" | "type" => Ok(Type::String),
            _ => bail!("undefined"),
        }
    }
}

function!(CidrMatch(ip: String, cidr: String)=>Boolean, {
    let s_ip:String = ip.try_into()?;
    let s_cidr:String = cidr.try_into()?;
    let ip = s_ip.parse();
    if ip.is_err() {
        warn!("can not parse ip: {}", s_ip);
        return Ok(false.into())
    }
    let cidr = s_cidr.parse();
    if cidr.is_err() {
        warn!("can not parse cidr: {}", s_cidr);
        return Ok(false.into())
    }
    let ip: IpAddr = ip.unwrap();
    let cidr: AnyIpCidr = cidr.unwrap();
    Ok(cidr.contains(&ip).into())
});
