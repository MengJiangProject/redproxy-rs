use std::{
    hash::Hash,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
};

use anyhow::{Context, Error, Result, anyhow, ensure, bail};
use async_trait::async_trait;
use milu::{
    parser::parse,
    script::{ScriptContext, Type, Value},
};
use rand::{rng, seq::IndexedRandom};
use serde::{Deserialize, Serialize};
use tracing::debug;

use super::{Connector, ConnectorRef, ConnectorRegistry};
use crate::{context::ContextRef, rules::script_ext::create_context};

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoadBalanceConnector {
    name: String,
    connectors: Vec<String>,

    #[serde(
        alias = "algo",
        default,
        with = "serde_yaml_ng::with::singleton_map_recursive"
    )]
    algorithm: Algorithm,

    // for RoundRobin selection,
    #[serde(skip)]
    idx: AtomicUsize,

    #[serde(skip)]
    hash_by: Option<Value>,

    #[serde(skip)]
    pub registry: OnceLock<ConnectorRegistry>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub enum Algorithm {
    Random,
    #[serde(alias = "rr")]
    RoundRobin,
    #[serde(alias = "hash")]
    HashBy(String),
    // TODO: Those Algorithms are not yet ready as i had to find a good way to collect data.
    // LeastConnection,
    // LeastRTT,
}

impl Default for Algorithm {
    fn default() -> Algorithm {
        Self::RoundRobin
    }
}

impl Default for LoadBalanceConnector {
    fn default() -> Self {
        Self {
            name: String::new(),
            connectors: Vec::new(),
            algorithm: Algorithm::default(),
            idx: AtomicUsize::new(0),
            hash_by: None,
            registry: OnceLock::new(),
        }
    }
}

pub fn from_value(value: &serde_yaml_ng::Value) -> Result<ConnectorRef> {
    let ret: LoadBalanceConnector =
        serde_yaml_ng::from_value(value.clone()).context("parse config")?;
    Ok(Box::new(ret))
}

#[async_trait]
impl Connector for LoadBalanceConnector {
    fn name(&self) -> &str {
        self.name.as_str()
    }

    async fn init(&mut self) -> Result<()> {
        // Basic initialization without resolver
        Ok(())
    }

    async fn verify(&self) -> Result<()> {
        ensure!(!self.connectors.is_empty(), "connectors must not be empty");
        
        if let Some(registry) = self.registry.get() {
            for n in &self.connectors {
                ensure!(registry.contains_key(n), "connector not defined: {}", n);
                
                // Disallow LoadBalance connectors as targets to prevent recursion
                if let Some(target_connector) = registry.get(n) {
                    if (target_connector.as_ref() as &dyn std::any::Any)
                        .downcast_ref::<LoadBalanceConnector>()
                        .is_some()
                    {
                        bail!("LoadBalance connector '{}' cannot use another LoadBalance connector '{}' as target", self.name, n);
                    }
                }
            }
        }
        Ok(())
    }

    async fn connect(self: Arc<Self>, ctx: ContextRef) -> Result<(), Error> {
        let registry = self
            .registry
            .get()
            .ok_or_else(|| anyhow!("Connector registry not initialized"))?;
        let conn = match self.algorithm {
            Algorithm::RoundRobin => self.round_robin(registry)?,
            Algorithm::Random => self.random(registry)?,
            Algorithm::HashBy(_) => self.hash_by(registry, &ctx).await?,
        };
        let next = conn.name().to_owned();
        debug!("{}: selected connector: {}", self.name, next);
        ctx.write().await.set_connector(next);
        conn.connect(ctx).await
    }
}

impl std::fmt::Debug for LoadBalanceConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadBalanceConnector")
            .field("name", &self.name)
            .field("connectors", &self.connectors)
            .field("algorithm", &self.algorithm)
            .field("idx", &self.idx)
            .field("hash_by", &self.hash_by.as_ref().map(|_| "Some(Value)"))
            .field(
                "registry",
                &self
                    .registry
                    .get()
                    .map(|_| "ConnectorRegistry")
                    .unwrap_or("None"),
            )
            .finish()
    }
}

impl LoadBalanceConnector {
    fn random(self: &Arc<Self>, registry: &ConnectorRegistry) -> Result<Arc<dyn Connector>> {
        let next = self
            .connectors
            .choose(&mut rng())
            .ok_or_else(|| anyhow!("No connectors available for random selection"))?;
        registry
            .get(next)
            .cloned()
            .ok_or_else(|| anyhow!("Connector '{}' not found in registry", next))
    }

    fn round_robin(
        self: &Arc<Self>,
        registry: &ConnectorRegistry,
    ) -> Result<Arc<dyn Connector>, Error> {
        if self.connectors.is_empty() {
            return Err(anyhow!("No connectors available for round robin selection"));
        }
        let next = self.idx.fetch_add(1, Ordering::Relaxed);
        let next = &self.connectors[next % self.connectors.len()];
        registry
            .get(next)
            .cloned()
            .ok_or_else(|| anyhow!("Connector '{}' not found in registry", next))
    }

    async fn hash_by(
        self: &Arc<Self>,
        registry: &ConnectorRegistry,
        ctx: &ContextRef,
    ) -> Result<Arc<dyn Connector>, Error> {
        let script_ctx = create_context(ctx.read().await.props().clone());

        // Handle lazy compilation if hash_by is not set
        let result = if let Some(ref hash_func) = self.hash_by {
            hash_func.real_value_of(script_ctx.into()).await?
        } else if let Algorithm::HashBy(ref script) = self.algorithm {
            // Compile on-demand
            let value = parse(script).context("unable to compile hash script")?;
            let type_ctx: Arc<ScriptContext> = create_context(Default::default()).into();
            let rtype = value
                .real_type_of(type_ctx)
                .await
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            ensure!(
                rtype == Type::String,
                "hash script type mismatch: required string, got {}\nsnippet: {}",
                rtype,
                script
            );
            value.real_value_of(script_ctx.into()).await?
        } else {
            return Err(anyhow!("Hash function not available"));
        };
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        use std::hash::Hasher;
        result.hash(&mut hasher);
        let hash = hasher.finish() as usize;
        debug!("result: {:?} hash: {:?}", result, hash);
        if self.connectors.is_empty() {
            return Err(anyhow!("No connectors available for hash selection"));
        }
        let next = &self.connectors[hash % self.connectors.len()];
        registry
            .get(next)
            .cloned()
            .ok_or_else(|| anyhow!("Connector '{}' not found in registry", next))
    }
}
