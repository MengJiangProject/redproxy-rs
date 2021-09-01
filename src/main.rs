use context::{ContextRef, ContextStatus};
use easy_error::{err_msg, Terminator};
use log::{info, trace, warn};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::sync::mpsc::channel;

mod common;
mod config;
mod connectors;
mod context;
mod listeners;
mod metrics;
mod rules;

use crate::{
    common::copy::copy_bidi, config::Config, connectors::Connector, context::ContextRefOps,
    listeners::Listener,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[tokio::main]
async fn main() -> Result<(), Terminator> {
    let args = clap::App::new(env!("CARGO_BIN_NAME"))
        .version(VERSION)
        .arg(
            clap::Arg::with_name("config")
                .short("c")
                .long("config")
                .help("config filename")
                .default_value("config.yaml")
                .takes_value(true),
        )
        .arg(
            clap::Arg::with_name("log-level")
                .short("l")
                .long("log")
                .help("set log level")
                .possible_values(&["erro", "warn", "info", "debug", "trace"])
                .takes_value(true),
        )
        .arg(
            clap::Arg::with_name("config-check")
                .short("t")
                .long("test")
                .help("load and check config file then exits"),
        )
        .get_matches();
    let config = args.value_of("config").unwrap_or("config.yaml");
    let config_test = args.is_present("config-check");
    let log_level = args.value_of("log-level").unwrap_or("info");
    env_logger::init_from_env(env_logger::Env::default().default_filter_or(log_level));

    let mut cfg = config::Config::load(config).await?;
    let rules = &mut cfg.rules;
    rules.iter_mut().try_for_each(rules::Rule::init)?;

    trace!("rules={:?}", rules);

    let (tx, mut rx) = channel(100);

    let mut listeners = listeners::config(&cfg.listeners)?;
    for l in listeners.iter_mut() {
        l.init().await?;
    }

    let mut connectors = connectors::config(&cfg.connectors)?;
    for c in connectors.iter_mut() {
        c.init().await?;
    }

    let connectors: HashMap<String, Arc<dyn Connector + Send + Sync>> = connectors
        .into_iter()
        .map(|c| (c.name().into(), c.into()))
        .collect();

    rules.iter_mut().try_for_each(|r| {
        if r.target_name() == "deny" {
            Ok(())
        } else if let Some(t) = connectors.get(r.target_name()) {
            r.target = Some(t.clone());
            Ok(())
        } else {
            Err(err_msg(format!("target not found: {}", r.target_name())))
        }
    })?;

    if config_test {
        println!("redproxy: the configuration file {} is ok", config);
        return Ok(());
    }

    let listeners: Vec<Arc<dyn Listener>> = listeners.into_iter().map(|x| x.into()).collect();
    for l in listeners.iter() {
        l.clone().listen(tx.clone()).await?;
    }

    tokio::spawn(async {
        loop {
            tokio::time::sleep(Duration::from_secs(10)).await;
            let len = context::CONTEXT_LIST.lock().unwrap().len();
            info!("We have {} client alive now.", len);
        }
    });

    let cfg = Arc::new(cfg);
    loop {
        let ctx = rx.recv().await.unwrap();
        tokio::spawn(process_request(ctx, cfg.clone()));
    }
}

async fn process_request(ctx: ContextRef, cfg: Arc<Config>) {
    let connector = {
        let ctx = &ctx.clone().read_owned().await;
        cfg.rules.iter().find_map(|x| {
            if x.evaluate(ctx) {
                Some(x.target.clone())
            } else {
                None
            }
        })
    };

    // Outer Option is None means no filter matches request, thus implicitly denial
    if connector.is_none() {
        info!("implicitly denied: {:?}", ctx);
        return ctx.on_error(err_msg("access denied")).await;
    }
    let connector = connector.unwrap();

    // Inner Option is None means matching rule is explicitly denial
    if connector.is_none() {
        info!("explicitly denied: {:?}", ctx);
        return ctx.on_error(err_msg("access denied")).await;
    }
    let connector = connector.unwrap();

    ctx.write()
        .await
        .set_status(ContextStatus::ServerConnecting);
    if let Err(e) = connector.connect(ctx.clone()).await {
        warn!("failed to connect to upstream: {} cause: {:?}", e, e.cause);
        return ctx.on_error(e).await;
    }

    ctx.on_connect().await;
    if let Err(e) = copy_bidi(ctx.clone()).await {
        warn!(
            "error in io thread: {} \ncause: {:?} \nctx: {:?}",
            e, e.cause, ctx
        );
    }
    ctx.write().await.set_status(ContextStatus::Terminated);
}
