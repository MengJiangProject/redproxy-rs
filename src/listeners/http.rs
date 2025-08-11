use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::Sender;
use tracing::{error, info, warn};

use crate::common::h11c::h11c_handshake;
use crate::common::set_keepalive;
use crate::common::tls::TlsServerConfig;
use crate::config::Timeouts;
use crate::context::ContextManager;
use crate::context::{ContextRef, make_buffered_stream};
use crate::listeners::Listener;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct HttpListener {
    name: String,
    bind: SocketAddr,
    tls: Option<TlsServerConfig>,
}

pub fn from_value(value: &serde_yaml_ng::Value) -> Result<Box<dyn Listener>> {
    let ret: HttpListener =
        serde_yaml_ng::from_value(value.clone()).with_context(|| "parse config")?;
    Ok(Box::new(ret))
}

#[async_trait]
impl Listener for HttpListener {
    fn name(&self) -> &str {
        &self.name
    }
    async fn init(&mut self) -> Result<()> {
        if let Some(Err(e)) = self.tls.as_mut().map(TlsServerConfig::init) {
            return Err(e);
        }
        Ok(())
    }
    async fn listen(
        self: Arc<Self>,
        contexts: Arc<ContextManager>,
        timeouts: Timeouts,
        queue: Sender<ContextRef>,
    ) -> Result<()> {
        info!("{} listening on {}", self.name, self.bind);
        let listener = TcpListener::bind(&self.bind)
            .await
            .with_context(|| "bind")?;
        let this = self.clone();
        tokio::spawn(this.accept(listener, contexts, timeouts, queue));
        Ok(())
    }
}
impl HttpListener {
    async fn accept(
        self: Arc<Self>,
        listener: TcpListener,
        contexts: Arc<ContextManager>,
        _timeouts: Timeouts,
        queue: Sender<ContextRef>,
    ) {
        loop {
            match listener.accept().await.with_context(|| "accept") {
                Ok((socket, source)) => {
                    // we spawn a new thread here to avoid handshake to block accept thread
                    let this = self.clone();
                    let queue = queue.clone();
                    let contexts = contexts.clone();
                    let source = crate::common::try_map_v4_addr(source);
                    tokio::spawn(async move {
                        let res = match this.create_context(contexts, source, socket).await {
                            Ok(ctx) => {
                                h11c_handshake(ctx, queue, |_, _| async { bail!("not supported") })
                                    .await
                            }
                            Err(e) => Err(e),
                        };
                        if let Err(e) = res {
                            warn!(
                                "{}: handshake failed: {}\ncause: {:?}",
                                this.name,
                                e,
                                e.source()
                            );
                        }
                    });
                }
                Err(e) => {
                    error!(
                        "{} accept error: {} \ncause: {:?}",
                        self.name,
                        e,
                        e.source()
                    );
                    return;
                }
            }
        }
    }
    async fn create_context(
        &self,
        contexts: Arc<ContextManager>,
        source: SocketAddr,
        socket: TcpStream,
    ) -> Result<ContextRef> {
        set_keepalive(&socket)?;
        let tls_acceptor = self
            .tls
            .as_ref()
            .map(|options| options.acceptor())
            .transpose()
            .with_context(|| "TLS acceptor initialization failed")?;
        let stream = if let Some(acceptor) = tls_acceptor {
            acceptor
                .accept(socket)
                .await
                .with_context(|| "tls accept error")
                .map(make_buffered_stream)?
        } else {
            make_buffered_stream(socket)
        };
        let ctx = contexts.create_context(self.name.to_owned(), source).await;
        ctx.write().await.set_client_stream(stream);
        Ok(ctx)
    }
}
