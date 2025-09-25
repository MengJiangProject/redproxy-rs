use anyhow::{Context as AnyhowContext, Error, Result};
use async_trait::async_trait;
use chashmap_async::CHashMap;
use serde::{Deserialize, Serialize};
use serde_yaml_ng::Value;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{Sender, channel};
use tracing::{debug, error, info, warn};

use super::Listener;
use crate::common::frames::Frame;
use crate::common::socket_ops::{RealSocketOps, SocketOps, TcpListener};
use crate::common::udp::{self, setup_udp_session};
use crate::config::Timeouts;
use crate::context::ContextManager;
use crate::context::{
    Context, ContextCallback, ContextRef, ContextRefOps, Feature, TargetAddress,
    make_buffered_stream,
};
use std::ops::{Deref, DerefMut};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ReverseProxyListenerConfig {
    name: String,
    bind: SocketAddr,
    target: TargetAddress,
    #[serde(default = "default_protocol")]
    protocol: Protocol,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReverseProxyListener<S = RealSocketOps>
where
    S: SocketOps,
{
    #[serde(flatten)]
    config: ReverseProxyListenerConfig,
    #[serde(skip)]
    sessions: Arc<CHashMap<SocketAddr, udp::Sender>>,
    #[serde(skip)]
    socket_ops: Arc<S>,
}

impl<S: SocketOps> Deref for ReverseProxyListener<S> {
    type Target = ReverseProxyListenerConfig;
    fn deref(&self) -> &Self::Target {
        &self.config
    }
}

impl<S: SocketOps> DerefMut for ReverseProxyListener<S> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.config
    }
}

impl<S: SocketOps> ReverseProxyListener<S> {
    pub fn new(config: ReverseProxyListenerConfig, socket_ops: Arc<S>) -> Self {
        Self {
            config,
            sessions: Arc::new(CHashMap::new()),
            socket_ops,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
#[serde(rename_all = "camelCase")]
pub enum Protocol {
    Tcp,
    Udp,
}

fn default_protocol() -> Protocol {
    Protocol::Tcp
}

pub fn from_value(value: &Value) -> Result<Box<dyn Listener>> {
    let config: ReverseProxyListenerConfig = serde_yaml_ng::from_value(value.clone())
        .with_context(|| "parse reverse proxy listener config")?;
    let ret = ReverseProxyListener::new(config, Arc::new(RealSocketOps));
    Ok(Box::new(ret))
}

#[async_trait]
impl<S: SocketOps + Send + Sync + 'static> Listener for ReverseProxyListener<S> {
    async fn listen(
        self: Arc<Self>,
        contexts: Arc<ContextManager>,
        timeouts: Timeouts,
        queue: Sender<ContextRef>,
    ) -> Result<()> {
        info!("{} listening on {}", self.name, self.bind);
        match self.protocol {
            Protocol::Tcp => {
                let listener = self.socket_ops.tcp_listen(self.bind).await?;
                tokio::spawn(async move {
                    loop {
                        self.tcp_accept(listener.as_ref(), &contexts, &timeouts, &queue)
                            .await
                            .unwrap_or_else(|e| {
                                error!(
                                    "{}: accept error: {} \ncause: {:?}",
                                    self.name,
                                    e,
                                    e.source()
                                )
                            });
                    }
                });
            }
            Protocol::Udp => {
                let (socket, _) = self.socket_ops.udp_bind(self.bind).await?;
                let listener = Arc::new(socket);
                tokio::spawn(async move {
                    loop {
                        self.udp_accept(&listener, &contexts, &timeouts, &queue)
                            .await
                            .unwrap_or_else(|e| {
                                error!(
                                    "{}: accept error: {} \ncause: {:?}",
                                    self.name,
                                    e,
                                    e.source()
                                )
                            });
                    }
                });
            }
        }
        Ok(())
    }

    fn name(&self) -> &str {
        &self.name
    }

    async fn shutdown(&self) -> Result<()> {
        info!("{}: shutting down UDP sessions", self.name);
        self.sessions.clear().await;
        Ok(())
    }
}

impl<S: SocketOps + Send + Sync + 'static> ReverseProxyListener<S> {
    async fn tcp_accept(
        self: &Arc<Self>,
        listener: &dyn TcpListener,
        contexts: &Arc<ContextManager>,
        _timeouts: &Timeouts,
        queue: &Sender<ContextRef>,
    ) -> Result<()> {
        let (socket, source) = listener.accept().await.with_context(|| "accept")?;
        let source = crate::common::try_map_v4_addr(source);
        self.socket_ops
            .set_keepalive(socket.as_ref(), true)
            .await
            .unwrap_or_else(|e| warn!("set_keepalive failed: {}", e));
        debug!("{}: connected from {:?}", self.name, source);
        let ctx = contexts.create_context(self.name.to_owned(), source).await;
        ctx.write()
            .await
            .set_target(self.target.clone())
            .set_client_stream(make_buffered_stream(socket));
        ctx.enqueue(queue).await?;
        Ok(())
    }

    async fn udp_accept(
        self: &Arc<Self>,
        listener: &Arc<UdpSocket>,
        contexts: &Arc<ContextManager>,
        timeouts: &Timeouts,
        queue: &Sender<ContextRef>,
    ) -> Result<()> {
        let mut buf = Frame::new();
        let (size, source) = buf.recv_from(listener).await.with_context(|| "accept")?;
        buf.addr = Some(self.target.clone());
        let source = crate::common::try_map_v4_addr(source);
        debug!("{}: recv from {:?} length: {}", self.name, source, size);

        if let Some(tx) = self.sessions.get(&source).await {
            tx.send(buf).await.with_context(|| "send")?;
        } else {
            let (tx, rx) = channel(100);
            let io = setup_udp_session(self.target.clone(), self.bind, source, rx, false)
                .with_context(|| "setup session")?;
            self.sessions.insert(source, tx).await;
            let ctx = contexts.create_context(self.name.to_owned(), source).await;
            ctx.write()
                .await
                .set_target(self.target.clone())
                .set_feature(Feature::UdpForward)
                .set_idle_timeout(timeouts.udp)
                .set_callback(ReverseCallback::new(source, self.sessions.clone()))
                .set_client_frames(io);
            ctx.enqueue(queue).await?;
        }
        Ok(())
    }
}

struct ReverseCallback {
    client: SocketAddr,
    sessions: Arc<CHashMap<SocketAddr, udp::Sender>>,
}

impl ReverseCallback {
    fn new(client: SocketAddr, sessions: Arc<CHashMap<SocketAddr, udp::Sender>>) -> Self {
        Self { client, sessions }
    }
}

#[async_trait]
impl ContextCallback for ReverseCallback {
    async fn on_error(&self, _ctx: &mut Context, _error: Error) {
        self.sessions.remove(&self.client).await;
    }
    async fn on_finish(&self, _ctx: &mut Context) {
        self.sessions.remove(&self.client).await;
    }
}
