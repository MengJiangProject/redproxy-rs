use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use async_trait::async_trait;
use easy_error::{ensure, Error, ResultExt};
use log::trace;
use serde::{Deserialize, Serialize};

use super::ConnectorRef;
use crate::{context::ContextRef, GlobalState};

#[derive(Serialize, Deserialize, Debug)]
pub struct LoadBalanceConnector {
    name: String,
    connectors: Vec<String>,
    #[serde(skip)]
    idx: AtomicUsize,
}

pub fn from_value(value: &serde_yaml::Value) -> Result<ConnectorRef, Error> {
    let ret: LoadBalanceConnector =
        serde_yaml::from_value(value.clone()).context("parse config")?;
    Ok(Box::new(ret))
}

#[async_trait]
impl super::Connector for LoadBalanceConnector {
    fn name(&self) -> &str {
        self.name.as_str()
    }

    async fn verify(&self, state: Arc<GlobalState>) -> Result<(), Error> {
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
        let next = self.idx.fetch_add(1, Ordering::Relaxed);
        let next = self.connectors[next % self.connectors.len()].to_owned();
        trace!("{}: selected connector: {}", self.name, next);
        let conn = state.connectors.get(&next).unwrap().clone();
        ctx.write().await.set_connector(next);
        conn.connect(state, ctx).await
    }
}
