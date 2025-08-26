use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc::Sender;
use tracing::{error, info, warn};

use crate::common::auth::AuthData;
use crate::common::http_proxy::http_forward_proxy_handshake;
use crate::common::socket_ops::{TcpListener, RealSocketOps, SocketOps};
use crate::common::tls::TlsServerConfig;
use crate::config::Timeouts;
use crate::context::ContextManager;
use crate::context::{ContextRef, make_buffered_stream};
use crate::listeners::Listener;
use std::ops::{Deref, DerefMut};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct HttpListenerConfig {
    name: String,
    bind: SocketAddr,
    tls: Option<TlsServerConfig>,
    #[serde(default)]
    auth: AuthData,
}

#[derive(Debug, Clone, Serialize)]
pub struct HttpListener<S = RealSocketOps>
where
    S: SocketOps,
{
    #[serde(flatten)]
    config: HttpListenerConfig,
    #[serde(skip)]
    socket_ops: Arc<S>,
}

impl<S: SocketOps> Deref for HttpListener<S> {
    type Target = HttpListenerConfig;
    fn deref(&self) -> &Self::Target {
        &self.config
    }
}

impl<S: SocketOps> DerefMut for HttpListener<S> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.config
    }
}

impl<S: SocketOps> HttpListener<S> {
    pub fn new(config: HttpListenerConfig, socket_ops: Arc<S>) -> Self {
        Self { config, socket_ops }
    }
}

pub fn from_value(value: &serde_yaml_ng::Value) -> Result<Box<dyn Listener>> {
    let config: HttpListenerConfig =
        serde_yaml_ng::from_value(value.clone()).with_context(|| "parse http listener config")?;
    let ret = HttpListener::new(config, Arc::new(RealSocketOps));
    Ok(Box::new(ret))
}

#[async_trait]
impl<S: SocketOps + Send + Sync + 'static> Listener for HttpListener<S> {
    fn name(&self) -> &str {
        &self.name
    }
    async fn init(&mut self) -> Result<()> {
        if let Some(Err(e)) = self.tls.as_mut().map(TlsServerConfig::init) {
            return Err(e);
        }
        self.auth.init().await?;
        Ok(())
    }
    async fn listen(
        self: Arc<Self>,
        contexts: Arc<ContextManager>,
        _timeouts: Timeouts,
        queue: Sender<ContextRef>,
    ) -> Result<()> {
        info!("{} listening on {}", self.name, self.bind);
        let listener = self.socket_ops.tcp_listen(self.bind).await?;

        let this = self.clone();
        tokio::spawn(this.accept(listener, contexts, queue));
        Ok(())
    }
}

impl<S: SocketOps + Send + Sync + 'static> HttpListener<S> {
    async fn accept(
        self: Arc<Self>,
        listener: Box<dyn TcpListener>,
        contexts: Arc<ContextManager>,
        queue: Sender<ContextRef>,
    ) {
        loop {
            match listener.accept().await.with_context(|| "accept") {
                Ok((stream, source)) => {
                    // we spawn a new thread here to avoid handshake to block accept thread
                    let this = self.clone();
                    let queue = queue.clone();
                    let contexts = contexts.clone();
                    let source = crate::common::try_map_v4_addr(source);
                    tokio::spawn(async move {
                        let stream = if let Some(tls_config) = &this.tls {
                            match this
                                .socket_ops
                                .tls_handshake_server(stream, tls_config)
                                .await
                            {
                                Ok((stream, _alpn)) => stream,
                                Err(e) => {
                                    warn!("tls handshake failed: {}", e);
                                    return;
                                }
                            }
                        } else {
                            stream
                        };

                        let ctx = contexts.create_context(this.name.to_owned(), source).await;
                        this.socket_ops
                            .set_keepalive(stream.as_ref(), true)
                            .await
                            .unwrap_or_else(|e| warn!("set_keepalive failed: {}", e));

                        // Set the listener's bind address as local address for loop detection
                        ctx.write()
                            .await
                            .set_client_stream(make_buffered_stream(stream))
                            .set_local_addr(this.bind);

                        let auth_data = if this.auth.required {
                            Some(this.auth.clone())
                        } else {
                            None
                        };
                        let res = http_forward_proxy_handshake(
                            ctx,
                            queue,
                            |_, _| async { bail!("not supported") },
                            auth_data,
                        )
                        .await;
                        if let Err(e) = res {
                            warn!("{}: handshake failed: {}", this.name, e,);
                        }
                    });
                }
                Err(e) => {
                    error!("{} accept error: {}", self.name, e,);
                    return;
                }
            }
        }
    }
}
