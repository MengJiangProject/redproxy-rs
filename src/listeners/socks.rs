use anyhow::{Context as AnyhowContext, Error, Result, anyhow};
use async_trait::async_trait;
use futures::TryFutureExt;
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tokio::sync::mpsc::Sender;
use tracing::{debug, error, info, warn};

use crate::{
    common::{
        auth::AuthData,
        into_unspecified,
        socket_ops::{AppTcpListener, RealSocketOps, SocketOps, Stream},
        socks::{
            PasswordAuth, SOCKS_CMD_BIND, SOCKS_CMD_CONNECT, SOCKS_CMD_UDP_ASSOCIATE,
            SOCKS_REPLY_GENERAL_FAILURE, SOCKS_REPLY_OK, SocksRequest, SocksResponse,
            frames::setup_udp_session,
        },
        tls::TlsServerConfig,
    },
    config::Timeouts,
    context::{
        Context, ContextCallback, ContextManager, ContextRef, ContextRefOps, Feature,
        make_buffered_stream,
    },
    listeners::Listener,
};
use std::ops::{Deref, DerefMut};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SocksListenerConfig {
    name: String,
    bind: SocketAddr,
    tls: Option<TlsServerConfig>,
    #[serde(default)]
    auth: AuthData,
    #[serde(default = "default_allow_udp")]
    allow_udp: bool,
    #[serde(default)]
    enforce_udp_client: bool,
    #[serde(default)]
    override_udp_address: Option<IpAddr>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SocksListener<S = RealSocketOps>
where
    S: SocketOps,
{
    #[serde(flatten)]
    config: SocksListenerConfig,
    #[serde(skip)]
    socket_ops: Arc<S>,
}

impl<S: SocketOps> Deref for SocksListener<S> {
    type Target = SocksListenerConfig;
    fn deref(&self) -> &Self::Target {
        &self.config
    }
}

impl<S: SocketOps> DerefMut for SocksListener<S> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.config
    }
}

impl<S: SocketOps> SocksListener<S> {
    pub fn new(config: SocksListenerConfig, socket_ops: Arc<S>) -> Self {
        Self { config, socket_ops }
    }
}

fn default_allow_udp() -> bool {
    true
}

pub fn from_value(value: &serde_yaml_ng::Value) -> Result<Box<dyn Listener>> {
    let config: SocksListenerConfig =
        serde_yaml_ng::from_value(value.clone()).with_context(|| "parse socks listener config")?;
    let ret = SocksListener::new(config, Arc::new(RealSocketOps));
    Ok(Box::new(ret))
}

#[async_trait]
impl<S: SocketOps + Send + Sync + 'static> Listener for SocksListener<S> {
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
        timeouts: Timeouts,
        queue: Sender<ContextRef>,
    ) -> Result<()> {
        info!("{} listening on {}", self.name, self.bind);
        let listener = self.socket_ops.tcp_listen(self.bind).await?;
        let this = self.clone();
        tokio::spawn(this.accept(listener, contexts, timeouts, queue));
        Ok(())
    }

    fn name(&self) -> &str {
        &self.name
    }
}

impl<S: SocketOps + Send + Sync + 'static> SocksListener<S> {
    async fn accept(
        self: Arc<Self>,
        listener: Box<dyn AppTcpListener>,
        contexts: Arc<ContextManager>,
        timeouts: Timeouts,
        queue: Sender<ContextRef>,
    ) {
        loop {
            match listener.accept().await.with_context(|| "accept") {
                Ok((socket, source)) => {
                    let source = crate::common::try_map_v4_addr(source);
                    let this = self.clone();
                    let queue = queue.clone();
                    let contexts = contexts.clone();
                    let timeouts = timeouts.clone();
                    debug!("{}: connected from {:?}", self.name, source);
                    // we spawn a new thread here to avoid handshake to block accept thread
                    tokio::spawn(
                        this.clone()
                            .handshake(socket, source, contexts, timeouts, queue)
                            .unwrap_or_else(move |e| {
                                warn!(
                                    "{}: handshake error: {}: cause: {:?}",
                                    this.name,
                                    e,
                                    e.source()
                                );
                            }),
                    );
                }
                Err(e) => {
                    error!(
                        "{}, Accept error: {}: cause: {:?}",
                        self.name,
                        e,
                        e.source()
                    );
                    return;
                }
            }
        }
    }

    async fn handshake(
        self: Arc<Self>,
        socket: Box<dyn Stream>,
        source: SocketAddr,
        contexts: Arc<ContextManager>,
        timeouts: Timeouts,
        queue: Sender<ContextRef>,
    ) -> Result<()> {
        let local_addr =
            if let Some(tcp_stream) = socket.as_any().downcast_ref::<tokio::net::TcpStream>() {
                tcp_stream.local_addr().with_context(|| "local_addr")?
            } else {
                // For mock streams, we don't have a local address.
                "0.0.0.0:0".parse().unwrap()
            };

        self.socket_ops
            .set_keepalive(socket.as_ref(), true)
            .await
            .unwrap_or_else(|e| warn!("set_keepalive failed: {}", e));

        let mut socket = if let Some(tls_config) = &self.tls {
            let stream = self
                .socket_ops
                .tls_handshake_server(socket, tls_config)
                .await?;
            make_buffered_stream(stream)
        } else {
            make_buffered_stream(socket)
        };

        let ctx = contexts.create_context(self.name.to_owned(), source).await;

        let auth_server = PasswordAuth {
            required: self.auth.required,
        };
        let request = SocksRequest::read_from(&mut socket, auth_server).await?;
        debug!("request {:?}", request);

        ctx.write()
            .await
            .set_extra(
                "user",
                request.auth.as_ref().map(|a| a.0.as_str()).unwrap_or(""),
            )
            .set_callback(Callback {
                version: request.version,
                listen_addr: None,
            })
            .set_client_stream(socket);

        if !self.auth.check(&request.auth).await {
            ctx.on_error(anyhow!("not authencated")).await;
            debug!("client not authencated: {:?}", request.auth);
            return Ok(());
        }
        match request.cmd {
            SOCKS_CMD_CONNECT => {
                ctx.write().await.set_target(request.target);
                ctx.enqueue(&queue).await?;
            }
            SOCKS_CMD_BIND => {
                ctx.on_error(anyhow!("not supported")).await;
                debug!("not supported cmd: {:?}", request.cmd);
            }
            SOCKS_CMD_UDP_ASSOCIATE => {
                if !self.allow_udp {
                    ctx.on_error(anyhow!("not supported")).await;
                    debug!("udp not allowed");
                    return Ok(());
                }
                let local = into_unspecified(source);
                let remote = if self.enforce_udp_client {
                    request
                        .target
                        .as_socket_addr()
                        .filter(|x| !x.ip().is_unspecified())
                } else {
                    None
                };
                let target = into_unspecified(local).into();
                let (mut listen_addr, frames) = setup_udp_session(local, remote)
                    .await
                    .with_context(|| "setup_udp_session")?;

                if let Some(override_addr) = self.override_udp_address {
                    listen_addr = SocketAddr::new(override_addr, listen_addr.port());
                } else if listen_addr.ip().is_unspecified() {
                    listen_addr = SocketAddr::new(local_addr.ip(), listen_addr.port());
                }

                ctx.write()
                    .await
                    .set_target(target)
                    .set_feature(Feature::UdpForward)
                    .set_client_frames(frames)
                    .set_callback(Callback {
                        version: request.version,
                        listen_addr: Some(listen_addr),
                    })
                    .set_idle_timeout(timeouts.udp);
                ctx.enqueue(&queue).await?;
            }
            _ => {
                ctx.on_error(anyhow!("unknown cmd")).await;
                debug!("unknown cmd: {:?}", request.cmd);
            }
        }
        Ok(())
    }
}

struct Callback {
    version: u8,
    listen_addr: Option<SocketAddr>,
}

#[async_trait]
impl ContextCallback for Callback {
    async fn on_connect(&self, ctx: &mut Context) {
        let version = self.version;
        let cmd = SOCKS_REPLY_OK;
        let target = self.listen_addr.map_or_else(|| ctx.target(), |x| x.into());
        let socket = ctx.borrow_client_stream();
        let resp = SocksResponse {
            version,
            cmd,
            target,
        };
        if let Some(e) = resp.write_to(socket.unwrap()).await.err() {
            warn!("failed to send response: {}", e)
        }
    }
    async fn on_error(&self, ctx: &mut Context, _error: Error) {
        let version = self.version;
        let cmd = SOCKS_REPLY_GENERAL_FAILURE;
        let target = "0.0.0.0:0".parse().unwrap();
        let socket = ctx.borrow_client_stream();
        if socket.is_none() {
            return;
        }
        let resp = SocksResponse {
            version,
            cmd,
            target,
        };
        if let Some(e) = resp.write_to(socket.unwrap()).await.err() {
            warn!("failed to send response: {}", e)
        }
    }
}
