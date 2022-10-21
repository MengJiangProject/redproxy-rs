use async_trait::async_trait;
use easy_error::{err_msg, Error, ResultExt};
use futures::TryFutureExt;
use log::{debug, error, info, trace, warn};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::Arc};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::mpsc::Sender,
};

use crate::{
    common::{
        auth::AuthData,
        into_unspecified, set_keepalive,
        socks::{
            frames::setup_udp_session, PasswordAuth, SocksRequest, SocksResponse, SOCKS_CMD_BIND,
            SOCKS_CMD_CONNECT, SOCKS_CMD_UDP_ASSOCIATE, SOCKS_REPLY_GENERAL_FAILURE,
            SOCKS_REPLY_OK,
        },
        tls::TlsServerConfig,
    },
    context::{make_buffered_stream, Context, ContextCallback, ContextRef, ContextRefOps, Feature},
    listeners::Listener,
    GlobalState,
};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SocksListener {
    name: String,
    bind: SocketAddr,
    tls: Option<TlsServerConfig>,
    #[serde(default)]
    auth: AuthData,
    #[serde(default)]
    enforce_udp_client: bool,
}

pub fn from_value(value: &serde_yaml::Value) -> Result<Box<dyn Listener>, Error> {
    let ret: SocksListener = serde_yaml::from_value(value.clone()).context("parse config")?;
    Ok(Box::new(ret))
}

#[async_trait]
impl Listener for SocksListener {
    async fn init(&mut self) -> Result<(), Error> {
        if let Some(Err(e)) = self.tls.as_mut().map(TlsServerConfig::init) {
            return Err(e);
        }
        self.auth.init().await?;
        Ok(())
    }
    async fn listen(
        self: Arc<Self>,
        state: Arc<GlobalState>,
        queue: Sender<ContextRef>,
    ) -> Result<(), Error> {
        info!("{} listening on {}", self.name, self.bind);
        let listener = TcpListener::bind(&self.bind).await.context("bind")?;
        let this = self.clone();
        tokio::spawn(this.accept(listener, state, queue));
        Ok(())
    }

    fn name(&self) -> &str {
        &self.name
    }
}

impl SocksListener {
    async fn accept(
        self: Arc<Self>,
        listener: TcpListener,
        state: Arc<GlobalState>,
        queue: Sender<ContextRef>,
    ) {
        loop {
            match listener.accept().await.context("accept") {
                Ok((socket, source)) => {
                    let source = crate::common::try_map_v4_addr(source);
                    let this = self.clone();
                    let queue = queue.clone();
                    let state = state.clone();
                    debug!("{}: connected from {:?}", self.name, source);
                    // we spawn a new thread here to avoid handshake to block accept thread
                    tokio::spawn(
                        this.clone()
                            .handshake(socket, source, state, queue)
                            .unwrap_or_else(move |e| {
                                warn!(
                                    "{}: handshake error: {}: cause: {:?}",
                                    this.name, e, e.cause
                                );
                            }),
                    );
                }
                Err(e) => {
                    error!("{}, Accept error: {}: cause: {:?}", self.name, e, e.cause);
                    return;
                }
            }
        }
    }

    async fn handshake(
        self: Arc<Self>,
        socket: TcpStream,
        source: SocketAddr,
        state: Arc<GlobalState>,
        queue: Sender<ContextRef>,
    ) -> Result<(), Error> {
        set_keepalive(&socket)?;
        let tls_acceptor = self.tls.as_ref().map(|options| options.acceptor());
        let mut socket = if let Some(acceptor) = tls_acceptor {
            make_buffered_stream(acceptor.accept(socket).await.context("tls accept error")?)
        } else {
            make_buffered_stream(socket)
        };
        let ctx = state
            .contexts
            .create_context(self.name.to_owned(), source)
            .await;

        let auth_server = PasswordAuth {
            required: self.auth.required,
        };
        let request = SocksRequest::read_from(&mut socket, auth_server).await?;
        trace!("request {:?}", request);

        ctx.write()
            .await
            .set_extra(
                "user",
                request.auth.as_ref().map(|a| a.0.as_str()).unwrap_or(""),
            )
            .set_callback(Callback {
                cmd: request.cmd,
                version: request.version,
                local_addr: None,
            })
            .set_client_stream(socket);

        if !self.auth.check(&request.auth).await {
            ctx.on_error(err_msg("not authencated")).await;
            debug!("client not authencated: {:?}", request.auth);
            return Ok(());
        }
        match request.cmd {
            SOCKS_CMD_CONNECT => {
                ctx.write().await.set_target(request.target);
                ctx.enqueue(&queue).await?;
            }
            SOCKS_CMD_BIND => {
                ctx.on_error(err_msg("not supported")).await;
                debug!("not supported cmd: {:?}", request.cmd);
            }
            SOCKS_CMD_UDP_ASSOCIATE => {
                let local = into_unspecified(source);
                let remote = if self.enforce_udp_client {
                    request.target.as_socket_addr()
                } else {
                    None
                };
                let (local_addr, frames) = setup_udp_session(local, remote)
                    .await
                    .context("setup_udp_session")?;
                ctx.write()
                    .await
                    .set_feature(Feature::UdpForward)
                    .set_client_frames(frames)
                    .set_callback(Callback {
                        cmd: request.cmd,
                        version: request.version,
                        local_addr: Some(local_addr),
                    })
                    .set_idle_timeout(state.timeouts.udp);
                ctx.enqueue(&queue).await?;
            }
            _ => {
                ctx.on_error(err_msg("unknown cmd")).await;
                debug!("unknown cmd: {:?}", request.cmd);
            }
        }
        Ok(())
    }
}

struct Callback {
    cmd: u8,
    version: u8,
    local_addr: Option<SocketAddr>,
}

#[async_trait]
impl ContextCallback for Callback {
    async fn on_connect(&self, ctx: &mut Context) {
        let version = self.version;
        let cmd = SOCKS_REPLY_OK;
        let target = if self.cmd == SOCKS_CMD_UDP_ASSOCIATE {
            self.local_addr.unwrap().into()
        } else {
            ctx.target()
        };
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
        let target = ctx.target();
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
