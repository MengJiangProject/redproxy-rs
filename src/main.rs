use anyhow::Result;

mod access_log;
mod cli;
mod common;
mod config;
mod connectors;
mod context;
mod copy;
mod listeners;
mod rules;
mod server;

#[cfg(feature = "metrics")]
mod metrics;

use cli::parse_args;
use server::ProxyServer;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to init rustls");

    let args = parse_args()?;

    let server = ProxyServer::from_config_file(&args.config_file).await?;

    if args.config_test {
        println!(
            "redproxy: the configuration file {} is ok",
            args.config_file
        );
        return Ok(());
    }

    server.run().await
}
