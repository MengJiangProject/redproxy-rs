use clap::{builder::PossibleValuesParser, value_parser};
use config::{IoParams, Timeouts};
use context::{ContextRef, ContextState, GlobalState as ContextGlobalState};
use easy_error::{err_msg, Error, Terminator};
use rules::Rule;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{mpsc::channel, RwLock, RwLockReadGuard};
use tracing::{info, warn};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[cfg(feature = "metrics")]
use metrics::MetricsServer;

mod access_log;
mod common;
mod config;
mod connectors;
mod context;
mod copy;
mod listeners;
mod rules;

#[cfg(feature = "metrics")]
mod metrics;

use crate::{connectors::Connector, context::ContextRefOps, copy::copy_bidi, listeners::Listener};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Default)]
pub struct GlobalState {
    rules: RwLock<Vec<Arc<Rule>>>,
    listeners: HashMap<String, Arc<dyn Listener>>,
    connectors: HashMap<String, Arc<dyn Connector>>,
    contexts: Arc<ContextGlobalState>,
    timeouts: Timeouts,
    #[cfg(feature = "metrics")]
    metrics: Option<Arc<MetricsServer>>,
    io_params: IoParams,
}

impl GlobalState {
    async fn set_rules(&self, mut rules: Vec<Arc<Rule>>) -> Result<(), Error> {
        for r in rules.iter_mut() {
            Arc::get_mut(r).unwrap().init()?;
        }

        let connectors = &self.connectors;
        rules.iter_mut().try_for_each(move |r| {
            if r.target_name() == "deny" {
                Ok(())
            } else if let Some(t) = connectors.get(r.target_name()) {
                Arc::get_mut(r).unwrap().target = Some(t.clone());
                Ok(())
            } else {
                Err(err_msg(format!("target not found: {}", r.target_name())))
            }
        })?;
        *self.rules.write().await = rules;
        Ok(())
    }
    async fn rules(&self) -> RwLockReadGuard<'_, Vec<Arc<Rule>>> {
        self.rules.read().await
    }
}
#[tokio::main]
async fn main() -> Result<(), Terminator> {
    let args = clap::Command::new(env!("CARGO_BIN_NAME"))
        .version(VERSION)
        .arg(
            clap::Arg::new("config")
                .short('c')
                .long("config")
                .help("Config filename")
                .default_value("config.yaml")
                .value_parser(value_parser!(String))
                .num_args(1),
        )
        .arg(
            clap::Arg::new("log-level")
                .short('l')
                .long("log")
                .help("Set log level")
                .value_parser(PossibleValuesParser::new([
                    "erro", "warn", "info", "debug", "trace",
                ]))
                .num_args(1),
        )
        .arg(
            clap::Arg::new("config-check")
                .short('t')
                .long("test")
                .help("Load and check config file then exits"),
        )
        .get_matches();
    let config = args
        .get_one("config")
        .map(String::as_str)
        .unwrap_or("config.yaml");
    let config_test = args.contains_id("config-check");
    let log_level = args
        .get_one("log-level")
        .map(String::as_str)
        .unwrap_or("info");
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(log_level.parse()?)
                .from_env()?,
        )
        .init();

    let cfg = config::Config::load(config).await?;
    let mut state: Arc<GlobalState> = Default::default();
    {
        let st_mut = Arc::get_mut(&mut state).unwrap();
        let ctx_mut = Arc::get_mut(&mut st_mut.contexts).unwrap();
        ctx_mut.default_timeout = st_mut.timeouts.idle;

        st_mut.timeouts = cfg.timeouts;
        st_mut.listeners = listeners::from_config(&cfg.listeners)?;
        st_mut.connectors = connectors::from_config(&cfg.connectors)?;

        #[cfg(feature = "metrics")]
        if let Some(mut metrics) = cfg.metrics {
            metrics.init()?;
            ctx_mut.history_size = metrics.history_size;
            st_mut.metrics = Some(Arc::new(metrics));
        }

        if let Some(mut log) = cfg.access_log {
            log.init().await?;
            ctx_mut.access_log = Some(log);
        }

        for l in st_mut.listeners.values_mut() {
            Arc::get_mut(l).unwrap().init().await?;
        }

        for c in st_mut.connectors.values_mut() {
            Arc::get_mut(c).unwrap().init().await?;
        }

        st_mut.set_rules(rules::from_config(&cfg.rules)?).await?;
        st_mut.io_params = cfg.io_params;
    }

    for l in state.listeners.values() {
        l.verify(state.clone()).await?;
    }

    for c in state.connectors.values() {
        c.verify(state.clone()).await?;
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
        state.rules().await.iter().find_map(|x| {
            if x.evaluate(ctx) {
                Some(x.target.clone())
            } else {
                None
            }
        })
    };

    // Outer Option is None means no filter matches request, thus implicitly denial
    if connector.is_none() {
        info!("implicitly denied: {}", ctx.to_string().await);
        return ctx.on_error(err_msg("access denied")).await;
    }
    let connector = connector.unwrap();

    // Inner Option is None means matching rule is explicitly denial
    if connector.is_none() {
        info!("explicitly denied: {}", ctx.to_string().await);
        return ctx.on_error(err_msg("access denied")).await;
    }
    let connector = connector.unwrap();

    // Check if connector has requested feature
    let props = ctx.read().await.props().clone();
    let feature = props.request_feature;
    if !connector.has_feature(feature) {
        let e = err_msg(format!("unsupported connector feature: {:?}", feature));
        warn!(
            "failed to connect to upstream: {} \ncause: {:?} \nctx: {}",
            e,
            e.cause,
            props.to_string()
        );
        return ctx.on_error(e).await;
    }

    ctx.write()
        .await
        .set_state(ContextState::ServerConnecting)
        .set_connector(connector.name().to_owned());
    let props = ctx.read().await.props().clone();
    if let Err(e) = connector.connect(state.clone(), ctx.clone()).await {
        warn!(
            "failed to connect to upstream: {} cause: {:?} \nctx: {}",
            e,
            e.cause,
            props.to_string()
        );
        return ctx.on_error(e).await;
    }

    ctx.on_connect().await;
    if let Err(e) = copy_bidi(ctx.clone(), &state.io_params).await {
        warn!(
            "error in io thread: {} \ncause: {:?} \nctx: {}",
            e,
            e.cause,
            props.to_string()
        );
        ctx.on_error(e).await;
    } else {
        ctx.write().await.set_state(ContextState::Terminated);
        ctx.on_finish().await;
    }
}
