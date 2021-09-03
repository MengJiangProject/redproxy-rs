use context::{ContextRef, ContextStatus, GlobalState as ContextGlobalState};
use easy_error::{err_msg, Terminator};
use log::{info, warn};
use metrics::MetricsServer;
use rules::Rule;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::mpsc::channel;

mod common;
mod config;
mod connectors;
mod context;
mod listeners;
mod metrics;
mod rules;

use crate::{
    common::copy::copy_bidi, connectors::Connector, context::ContextRefOps, listeners::Listener,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Default)]
pub struct GlobalState {
    rules: Vec<Rule>,
    listeners: HashMap<String, Arc<dyn Listener>>,
    connectors: HashMap<String, Arc<dyn Connector>>,
    contexts: Arc<ContextGlobalState>,
    #[cfg(feature = "metrics")]
    metrics: Option<Arc<MetricsServer>>,
}
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

    let cfg = config::Config::load(config).await?;
    let mut state: Arc<GlobalState> = Default::default();
    {
        let st_mut = Arc::get_mut(&mut state).unwrap();

        st_mut.rules = rules::from_config(&cfg.rules)?;
        st_mut.listeners = listeners::from_config(&cfg.listeners)?;
        st_mut.connectors = connectors::from_config(&cfg.connectors)?;

        for r in st_mut.rules.iter_mut() {
            r.init()?;
        }

        for (_name, l) in st_mut.listeners.iter_mut() {
            Arc::get_mut(l).unwrap().init().await?;
        }

        for (_name, c) in st_mut.connectors.iter_mut() {
            Arc::get_mut(c).unwrap().init().await?;
        }

        let connectors = &st_mut.connectors;
        st_mut.rules.iter_mut().try_for_each(move |r| {
            if r.target_name() == "deny" {
                Ok(())
            } else if let Some(t) = connectors.get(r.target_name()) {
                r.target = Some(t.clone());
                Ok(())
            } else {
                Err(err_msg(format!("target not found: {}", r.target_name())))
            }
        })?;

        #[cfg(feature = "metrics")]
        if let Some(mut metrics) = cfg.metrics {
            metrics.init();
            st_mut.metrics = Some(Arc::new(metrics));
        }
    }

    if config_test {
        println!("redproxy: the configuration file {} is ok", config);
        return Ok(());
    }

    let (tx, mut rx) = channel(100);
    for l in state.listeners.values().cloned() {
        l.listen(state.clone(), tx.clone()).await?;
    }

    #[cfg(feature = "metrics")]
    if let Some(metrics) = state.metrics.clone() {
        metrics.listen(state.clone()).await?;
    }
    state.contexts.clone().gc_thread();

    loop {
        let ctx = rx.recv().await.unwrap();
        tokio::spawn(process_request(ctx, state.clone()));
    }
}

async fn process_request(ctx: ContextRef, state: Arc<GlobalState>) {
    let connector = {
        let ctx = &ctx.clone().read_owned().await;
        state.rules.iter().find_map(|x| {
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
        let ctx = ctx.read().await; //for better debug prrint
        warn!(
            "error in io thread: {} \ncause: {:?} \nctx: {:?}",
            e, e.cause, ctx
        );
    }
    ctx.write().await.set_status(ContextStatus::Terminated);
}
