use anyhow::Result;
use redproxy_rs::{cli::parse_args, server::ProxyServer};

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::aws_lc_rs::default_provider()
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
