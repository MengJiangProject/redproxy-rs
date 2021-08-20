extern crate nom;

use std::{collections::HashMap, sync::Arc};

use easy_error::{err_msg, Terminator};
use log::trace;
use tokio::sync::mpsc::channel;

mod common;
mod config;
mod connectors;
mod context;
mod listeners;
mod milu;
mod rules;

#[tokio::main]
async fn main() -> Result<(), Terminator> {
    env_logger::init();

    let mut cfg = config::Config::load("config.yaml").await?;
    let rules = &mut cfg.rules;
    rules.iter_mut().try_for_each(rules::Rule::init)?;

    trace!("rules={:?}", rules);

    let (tx, mut rx) = channel(100);

    let mut listeners = listeners::config(&cfg.listeners)?;
    for l in listeners.iter_mut() {
        l.init().await?;
        l.listen(tx.clone()).await?;
    }

    let mut connectors = connectors::config(&cfg.connectors)?;
    for c in connectors.iter_mut() {
        c.init().await?;
    }

    let connectors: HashMap<String, _> = connectors
        .into_iter()
        .map(|c| (c.name().into(), Arc::new(c)))
        .collect();

    rules.iter_mut().try_for_each(|r| {
        if let Some(t) = connectors.get(r.target_name()) {
            r.set_target(t.clone());
            Ok(())
        } else {
            Err(err_msg(format!("target not found: {}", r.target_name())))
        }
    })?;

    loop {
        let ctx = rx.recv().await.unwrap();
        if let Some(hit) = rules.iter().find_map(|x| {
            if x.evaluate(&ctx) {
                Some(x.target())
            } else {
                None
            }
        }) {
            hit.connect(ctx).await?;
        } else {
            easy_error::bail!("empty target")
        }
    }
}
