use easy_error::{ResultExt, Terminator};
use log::trace;
use tokio::sync::mpsc::channel;

mod config;
mod connectors;
mod context;
mod listeners;
mod rules;

#[tokio::main]
async fn main() -> Result<(), Terminator> {
    env_logger::init();

    let cfg = config::Config::load("config.yaml").await?;
    // trace!("cfg={:?}", cfg);

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
    let c = connectors.remove(0);
    loop {
        let ctx = rx.recv().await.unwrap();
        c.connect(ctx).await?;
    }
}
