use std::{
    hash::Hash,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use async_trait::async_trait;
use anyhow::{Error, Context, Result, ensure};
use milu::{
    parser::parse,
    script::{ScriptContext, Type, Value},
};
use rand::{rng, seq::IndexedRandom};
use serde::{Deserialize, Serialize};
use tracing::debug;

use super::{Connector, ConnectorRef};
use crate::{GlobalState, context::ContextRef, rules::script_ext::create_context};

#[derive(Serialize, Deserialize, Debug)]
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
        if let Algorithm::HashBy(str) = &self.algorithm {
            let value = parse(str).context("unable to compile hash script")?;
            let ctx: Arc<ScriptContext> = create_context(Default::default()).into();
            let rtype = value.real_type_of(ctx).await.map_err(|e| anyhow::anyhow!("{}", e))?;
            ensure!(
                rtype == Type::String,
                "hash script type mismatch: required string, got {}\nsnippet: {}",
                rtype,
                str
            );
            self.hash_by = Some(value);
        }
        Ok(())
    }

    async fn verify(&self, state: Arc<GlobalState>) -> Result<()> {
        ensure!(!self.connectors.is_empty(), "connectors must not be empty");
        for n in &self.connectors {
            ensure!(
                state.connectors.contains_key(n),
                "connector not defined: {}",
                n
            );
        }
        Ok(())
    }

    async fn connect(
        self: Arc<Self>,
        state: Arc<GlobalState>,
        ctx: ContextRef,
    ) -> Result<(), Error> {
        let conn = match self.algorithm {
            Algorithm::RoundRobin => self.round_robin(&state)?,
            Algorithm::Random => self.random(&state)?,
            Algorithm::HashBy(_) => self.hash_by(&state, &ctx).await?,
        };
        let next = conn.name().to_owned();
        debug!("{}: selected connector: {}", self.name, next);
        ctx.write().await.set_connector(next);
        conn.connect(state, ctx).await
    }
}

impl LoadBalanceConnector {
    fn random(self: &Arc<Self>, state: &Arc<GlobalState>) -> Result<Arc<dyn Connector>> {
        let next = self.connectors.choose(&mut rng()).unwrap();
        Ok(state.connectors.get(next).unwrap().clone())
    }

    fn round_robin(
        self: &Arc<Self>,
        state: &Arc<GlobalState>,
    ) -> Result<Arc<dyn Connector>, Error> {
        let next = self.idx.fetch_add(1, Ordering::Relaxed);
        let next = &self.connectors[next % self.connectors.len()];
        Ok(state.connectors.get(next).unwrap().clone())
    }

    async fn hash_by(
        self: &Arc<Self>,
        state: &Arc<GlobalState>,
        ctx: &ContextRef,
    ) -> Result<Arc<dyn Connector>, Error> {
        let ctx = create_context(ctx.read().await.props().clone());
        let result = self
            .hash_by
            .as_ref()
            .unwrap()
            .real_value_of(ctx.into())
            .await?;
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        use std::hash::Hasher;
        result.hash(&mut hasher);
        let hash = hasher.finish() as usize;
        debug!("result: {:?} hash: {:?}", result, hash);
        let next = &self.connectors[hash % self.connectors.len()];
        Ok(state.connectors.get(next).unwrap().clone())
    }
}
