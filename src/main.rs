extern crate nom;

use easy_error::{err_msg, Terminator};
use log::{info, trace, warn};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::mpsc::channel;

mod common;
mod config;
mod connectors;
mod context;
mod listeners;
mod rules;

use crate::{common::copy::copy_bidi, config::Config, context::Context};

const VERSION: &str = "v0.1.0";

#[tokio::main]
async fn main() -> Result<(), Terminator> {
    let args = clap::App::new("redproxy")
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

    let connectors: HashMap<String, _> = connectors
        .into_iter()
        .map(|c| (c.name().into(), Arc::new(c)))
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

    for l in listeners.iter() {
        l.listen(tx.clone()).await?;
    }

    let cfg = Arc::new(cfg);
    loop {
        let ctx = rx.recv().await.unwrap();
        tokio::spawn(process_request(ctx, cfg.clone()));
    }
}

async fn process_request(mut ctx: Context, cfg: Arc<Config>) {
    let connector = cfg.rules.iter().find_map(|x| {
        if x.evaluate(&ctx) {
            Some(x.target.as_ref())
        } else {
            None
        }
    });
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

    let server = connector.connect(&ctx).await;
    if let Err(e) = server {
        warn!("failed to connect to upstream: {}", e);
        return ctx.on_error(e).await;
    }
    ctx.on_connect().await;
    let mut server = server.unwrap();
    let client = &mut ctx.socket;
    if let Err(e) = copy_bidi(client, &mut server).await {
        warn!("error in io thread: {}", e);
    }
}
