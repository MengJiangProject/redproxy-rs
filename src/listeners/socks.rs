use async_trait::async_trait;
use easy_error::{err_msg, Error, ResultExt};
use futures::TryFutureExt;
use log::{debug, error, info, trace, warn};
use serde::{Deserialize, Serialize};
use std::{future::Future, net::SocketAddr, ops::DerefMut, pin::Pin, sync::Arc};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::mpsc::Sender,
};

use crate::{
    common::{
        auth::AuthData,
        keepalive::set_keepalive,
        socks::{PasswordAuth, SocksRequest, SocksResponse},
        tls::TlsServerConfig,
    },
    context::{make_buffered_stream, ContextCallback, ContextRef, ContextRefOps},
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
            .set_target(request.target)
            .set_extra(
                "user",
                request.auth.as_ref().map(|a| a.0.as_str()).unwrap_or(""),
            )
            .set_callback(Callback {
                version: request.version,
            })
            .set_client_stream(socket);
        if self.auth.check(&request.auth).await {
            ctx.enqueue(&queue).await?;
        } else {
            ctx.on_error(err_msg("not authencated")).await;
            debug!("client not authencated: {:?}", request.auth);
        }
        Ok(())
    }
}
struct Callback {
    version: u8,
}

impl ContextCallback for Callback {
    fn on_connect(&self, ctx: ContextRef) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let version = self.version;
        let cmd = 0;
        Box::pin(async move {
            let ctx = ctx.read().await;
            let target = ctx.target();
            let mut socket = ctx.get_client_stream().await;
            let s = socket.deref_mut();
            let resp = SocksResponse {
                version,
                cmd,
                target,
            };
            if let Some(e) = resp.write_to(s).await.err() {
                warn!("failed to send response: {}", e)
            }
        })
    }
    fn on_error(&self, ctx: ContextRef, _error: Error) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let version = self.version;
        let cmd = 1;
        Box::pin(async move {
            let ctx = ctx.read().await;
            let target = ctx.target();
            let mut socket = ctx.get_client_stream().await;
            let s = socket.deref_mut();
            let resp = SocksResponse {
                version,
                cmd,
                target,
            };
            if let Some(e) = resp.write_to(s).await.err() {
                warn!("failed to send response: {}", e)
            }
        })
    }
}
