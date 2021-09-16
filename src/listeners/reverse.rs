use async_trait::async_trait;
use easy_error::{Error, ResultExt};
use futures::TryFutureExt;
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::mpsc::Sender;
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use crate::common::keepalive::set_keepalive;
use crate::context::ContextRefOps;
use crate::context::{make_buffered_stream, ContextRef, TargetAddress};
use crate::GlobalState;

use super::Listener;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ReverseProxyListener {
    name: String,
    bind: SocketAddr,
    target: TargetAddress,
}

pub fn from_value(value: &Value) -> Result<Box<dyn Listener>, Error> {
    let ret: ReverseProxyListener =
        serde_yaml::from_value(value.clone()).context("parse config")?;
    Ok(Box::new(ret))
}

#[async_trait]
impl Listener for ReverseProxyListener {
    async fn listen(
        self: Arc<Self>,
        state: Arc<GlobalState>,
        queue: Sender<ContextRef>,
    ) -> Result<(JoinHandle<()>, Arc<Notify>), Error> {
        info!("{} listening on {}", self.name, self.bind);
        let listener = TcpListener::bind(&self.bind).await.context("bind")?;
        let shutdown = Arc::new(Notify::new());
        let task = tokio::spawn(
            self.clone()
                .accept(listener, state, queue, shutdown.clone())
                .unwrap_or_else(move |e| {
                    warn!("{}: accept error: {} \ncause: {:?}", self.name, e, e.cause)
                }),
        );
        Ok((task, shutdown))
    }

    fn name(&self) -> &str {
        &self.name
    }
}

impl ReverseProxyListener {
    async fn accept(
        self: Arc<Self>,
        listener: TcpListener,
        state: Arc<GlobalState>,
        queue: Sender<ContextRef>,
        shutdown: Arc<Notify>,
    ) -> Result<(), Error> {
        loop {
            tokio::select! {
            _ = shutdown.notified() => break,
            res = listener.accept() =>
                match res {
                    Ok((socket, source)) => {
                        set_keepalive(&socket)?;
                        debug!("{}: connected from {:?}", self.name, source);
                        let ctx = state
                            .contexts
                            .create_context(self.name.to_owned(), source)
                            .await;
                        ctx.write()
                            .await
                            .set_target(self.target.clone())
                            .set_client_stream(make_buffered_stream(socket));
                        ctx.enqueue(&queue).await?;
                    },
                    Err(e) => {
                        error!("{} accept error: {:?}", self.name, e);
                        break;
                    }
                },
            }
        }
        Ok(())
    }
}
