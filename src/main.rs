use connectors::Connector;
use listeners::Listener;
use tokio::sync::mpsc::channel;
mod connectors;
mod listeners;

use connectors::direct::DirectConnector;
use listeners::http::HttpListener;
use listeners::tproxy::TProxyListener;

mod context;

// #[tokio::main]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    use tokio::runtime;

    let rt = runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    rt.block_on(async {
        let (tx, mut rx) = channel(100);

        let listener = TProxyListener::create("127.0.0.1:8080").await?;
        listener.listen(tx.clone()).await?;

        let listener = HttpListener::create("127.0.0.1:8081").await?;
        listener.listen(tx.clone()).await?;

        let connector = DirectConnector::create("").await?;
        loop {
            let ctx = rx.recv().await.unwrap();
            connector.connect(ctx).await?;
        }
    })
}
