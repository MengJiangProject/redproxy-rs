use anyhow::{Context, Error, Result, anyhow};
use clap::{builder::PossibleValuesParser, value_parser};
use config::{IoParams, Timeouts};
use context::{ContextManager, ContextRef, ContextState};
use rules::Rule;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{RwLockReadGuard, mpsc::channel};
use tracing::{info, warn};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

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

use crate::{
    connectors::{Connector, ConnectorRegistry},
    context::ContextRefOps,
    copy::copy_bidi,
    listeners::Listener,
    rules::RulesManager,
};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Default)]
pub struct GlobalState {
    rules_manager: RulesManager,
    listeners: HashMap<String, Arc<dyn Listener>>,
    connectors: ConnectorRegistry,
    contexts: Arc<ContextManager>,
    timeouts: Timeouts,
    #[cfg(feature = "metrics")]
    metrics: Option<Arc<MetricsServer>>,
    io_params: IoParams,
}

impl GlobalState {
    async fn set_rules(&self, rules: Vec<Arc<Rule>>) -> Result<(), Error> {
        self.rules_manager.set_rules(rules, &self.connectors).await
    }
    async fn rules(&self) -> RwLockReadGuard<'_, Vec<Arc<Rule>>> {
        self.rules_manager.rules().await
    }
    async fn eval_rules(&self, ctx: &ContextRef) -> Option<Arc<dyn Connector>> {
        self.rules_manager.eval_rules(ctx).await
    }
}
#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to init rustls");
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

    // Build state safely without Arc::get_mut().unwrap() patterns
    let mut contexts = Arc::new(ContextManager::default());
    let mut listeners = listeners::from_config(&cfg.listeners)?;
    let mut connectors = connectors::from_config(&cfg.connectors)?;

    // Initialize contexts with timeout and access log
    if let Some(ctx_mut) = Arc::get_mut(&mut contexts) {
        ctx_mut.default_timeout = cfg.timeouts.idle;

        if let Some(mut log) = cfg.access_log {
            log.init().await?;
            ctx_mut.access_log = Some(log);
        }
    } else {
        return Err(anyhow!("Cannot initialize context state"));
    }

    // Initialize listeners
    for l in listeners.values_mut() {
        if let Some(listener_mut) = Arc::get_mut(l) {
            listener_mut.init().await.with_context(|| {
                format!("Failed to initialize listener {}", listener_mut.name())
            })?;
        } else {
            return Err(anyhow!(
                "Cannot get mutable reference to listener during initialization"
            ));
        }
    }

    // Initialize connectors (original approach from git history)
    for c in connectors.values_mut() {
        if let Some(connector_mut) = Arc::get_mut(c) {
            connector_mut.init().await.context(format!(
                "Failed to initialize connector {}",
                connector_mut.name()
            ))?;
        } else {
            return Err(anyhow!(
                "Cannot get mutable reference to connector during initialization"
            ));
        }
    }

    // After initialization, inject registry into LoadBalance connectors using OnceLock
    for connector in connectors.values() {
        if let Some(lb_connector) = (connector.as_ref() as &dyn std::any::Any)
            .downcast_ref::<crate::connectors::loadbalance::LoadBalanceConnector>(
        ) {
            // Use OnceLock to inject registry - works through shared reference
            lb_connector
                .registry
                .set(connectors.clone())
                .map_err(|_| anyhow!("LoadBalance connector registry already initialized"))?;
        }
    }

    // Handle metrics initialization
    #[cfg(feature = "metrics")]
    let metrics = if let Some(mut metrics_cfg) = cfg.metrics {
        metrics_cfg.init()?;
        if let Some(ctx_mut) = Arc::get_mut(&mut contexts) {
            ctx_mut.history_size = metrics_cfg.history_size;
        }
        Some(Arc::new(metrics_cfg))
    } else {
        None
    };

    // Build the global state
    let state = Arc::new(GlobalState {
        rules_manager: RulesManager::new(),
        listeners,
        connectors,
        contexts,
        timeouts: cfg.timeouts,
        #[cfg(feature = "metrics")]
        metrics,
        io_params: cfg.io_params,
    });

    // Initialize rules after state is fully constructed
    state.set_rules(rules::from_config(&cfg.rules)?).await?;

    for l in state.listeners.values() {
        l.verify().await?;
    }

    for c in state.connectors.values() {
        c.verify().await?;
    }

    if config_test {
        println!("redproxy: the configuration file {} is ok", config);
        return Ok(());
    }

    let (tx, mut rx) = channel(100);
    for l in state.listeners.values().cloned() {
        l.listen(state.contexts.clone(), state.timeouts.clone(), tx.clone())
            .await?;
    }

    #[cfg(feature = "metrics")]
    if let Some(metrics) = state.metrics.clone() {
        metrics.listen(state.clone()).await?;
    }
    state.contexts.clone().gc_thread();

    loop {
        let ctx = rx
            .recv()
            .await
            .ok_or_else(|| anyhow!("Channel closed unexpectedly"))?;
        tokio::spawn(process_request(ctx, state.clone()));
    }
}

async fn process_request(ctx: ContextRef, state: Arc<GlobalState>) {
    let connector = state.eval_rules(&ctx).await;

    let connector = match connector {
        Some(c) => c,
        None => {
            info!("denied: {}", ctx.to_string().await);
            return ctx.on_error(anyhow!("access denied")).await;
        }
    };

    // Check if connector has requested feature
    let props = ctx.read().await.props().clone();
    let feature = props.request_feature;
    if !connector.has_feature(feature) {
        let e = anyhow!("unsupported connector feature: {:?}", feature);
        warn!(
            "failed to connect to upstream: {} \ncause: {:?} \nctx: {}",
            e,
            e.source(),
            props.to_string()
        );
        return ctx.on_error(anyhow!("{}", e)).await;
    }

    ctx.write()
        .await
        .set_state(ContextState::ServerConnecting)
        .set_connector(connector.name().to_owned());
    let props = ctx.read().await.props().clone();
    if let Err(e) = connector.connect(ctx.clone()).await {
        warn!(
            "failed to connect to upstream: {} cause: {:?} \nctx: {}",
            e,
            e.source(),
            props.to_string()
        );
        return ctx.on_error(anyhow!("{}", e)).await;
    }

    ctx.on_connect().await;
    if let Err(e) = copy_bidi(ctx.clone(), &state.io_params).await {
        warn!(
            "error in io thread: {} \ncause: {:?} \nctx: {}",
            e,
            e.source(),
            props.to_string()
        );
        ctx.on_error(e).await;
    } else {
        ctx.write().await.set_state(ContextState::Terminated);
        ctx.on_finish().await;
    }
}
