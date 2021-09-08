use context::{ContextRef, ContextState, GlobalState as ContextGlobalState};
use easy_error::{err_msg, Error, Terminator};
use log::{info, warn};
use metrics::MetricsServer;
use rules::Rule;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{mpsc::channel, RwLock, RwLockReadGuard};

mod access_log;
mod common;
mod config;
mod connectors;
mod context;
mod copy;
mod listeners;
mod metrics;
mod rules;

use crate::{connectors::Connector, context::ContextRefOps, copy::copy_bidi, listeners::Listener};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Default)]
pub struct GlobalState {
    rules: RwLock<Vec<Arc<Rule>>>,
    listeners: HashMap<String, Arc<dyn Listener>>,
    connectors: HashMap<String, Arc<dyn Connector>>,
    contexts: Arc<ContextGlobalState>,
    #[cfg(feature = "metrics")]
    metrics: Option<Arc<MetricsServer>>,
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

        st_mut.listeners = listeners::from_config(&cfg.listeners)?;
        st_mut.connectors = connectors::from_config(&cfg.connectors)?;

        #[cfg(feature = "metrics")]
        if let Some(mut metrics) = cfg.metrics {
            let ctx_mut = Arc::get_mut(&mut st_mut.contexts).unwrap();
            metrics.init()?;
            ctx_mut.history_size = metrics.history_size;
            st_mut.metrics = Some(Arc::new(metrics));
        }

        if let Some(mut log) = cfg.access_log {
            let ctx_mut = Arc::get_mut(&mut st_mut.contexts).unwrap();
            log.init().await?;
            ctx_mut.access_log = Some(log);
        }

        for (_name, l) in st_mut.listeners.iter_mut() {
            Arc::get_mut(l).unwrap().init().await?;
        }

        for (_name, c) in st_mut.connectors.iter_mut() {
            Arc::get_mut(c).unwrap().init().await?;
        }
        st_mut.set_rules(rules::from_config(&cfg.rules)?).await?;
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

    ctx.write()
        .await
        .set_state(ContextState::ServerConnecting)
        .set_connector(connector.name().to_owned());
    if let Err(e) = connector.connect(ctx.clone()).await {
        let ctx_str = ctx.to_string().await;
        warn!(
            "failed to connect to upstream: {} cause: {:?} \nctx: {}",
            e, e.cause, ctx_str
        );
        return ctx.on_error(e).await;
    }

    ctx.on_connect().await;
    if let Err(e) = copy_bidi(ctx.clone()).await {
        let ctx_str = ctx.to_string().await;
        warn!(
            "error in io thread: {} \ncause: {:?} \nctx: {}",
            e, e.cause, ctx_str
        );
        ctx.on_error(e).await;
    } else {
        ctx.write().await.set_state(ContextState::Terminated);
    }
}
