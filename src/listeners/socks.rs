use std::future::Future;
use std::net::SocketAddr;
use std::ops::DerefMut;
use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use easy_error::{err_msg, Error, ResultExt};
use log::{debug, info, trace, warn};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::Sender;

use crate::common::socks::{PasswordAuth, SocksRequest, SocksResponse};
use crate::common::tls::TlsServerConfig;
use crate::context::{make_buffered_stream, Context, ContextCallback, ContextRef, ContextRefOps};
use crate::listeners::Listener;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SocksListener {
    name: String,
    bind: String,
    tls: Option<TlsServerConfig>,
    auth: Option<SocksAuthData>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SocksAuthData {
    required: bool,
    users: Vec<UserEntry>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserEntry {
    username: String,
    password: String,
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
        Ok(())
    }
    async fn listen(self: Arc<Self>, queue: Sender<ContextRef>) -> Result<(), Error> {
        info!("{} listening on {}", self.name, self.bind);
        let listener = TcpListener::bind(&self.bind).await.context("bind")?;
        let this = self.clone();
        tokio::spawn(this.accept(listener, queue));
        Ok(())
    }

    fn name(&self) -> &str {
        &self.name
    }
}

impl SocksListener {
    async fn accept(self: Arc<Self>, listener: TcpListener, queue: Sender<ContextRef>) {
        loop {
            let this = self.clone();
            let queue = queue.clone();
            match listener.accept().await.context("accept") {
                Ok((socket, source)) => {
                    // we spawn a new thread here to avoid handshake to block accept thread
                    tokio::spawn(async move {
                        if let Err(e) = this.handshake(socket, source, queue).await {
                            warn!("{}: {:?}", e, e.cause);
                        }
                    });
                }
                Err(e) => {
                    warn!("{}: {:?}", e, e.cause);
                    return;
                }
            }
        }
    }

    async fn handshake(
        self: Arc<Self>,
        socket: TcpStream,
        source: SocketAddr,
        queue: Sender<ContextRef>,
    ) -> Result<(), Error> {
        let tls_acceptor = self.tls.as_ref().map(|options| options.acceptor());
        let mut socket = if let Some(acceptor) = tls_acceptor {
            make_buffered_stream(acceptor.accept(socket).await.context("tls accept error")?)
        } else {
            make_buffered_stream(socket)
        };
        debug!("{}: connected from {:?}", self.name, source);
        let ctx = Context::new(self.name.to_owned(), source);
        let auth_required = self
            .auth
            .as_ref()
            .map(|options| options.required)
            .unwrap_or(false);

        let auth_server = PasswordAuth {
            required: auth_required,
        };
        let request = SocksRequest::read_from(&mut socket, auth_server).await?;
        trace!("request {:?}", request);

        ctx.write()
            .await
            .set_target(request.target)
            .set_callback(Callback {
                version: request.version,
            })
            .set_client_stream(socket);
        if auth_required && !self.lookup_user(&request.auth) {
            ctx.on_error(err_msg("not authencated")).await;
            debug!("client not authencated: {:?}", request.auth);
        } else {
            ctx.enqueue(&queue).await?;
        }
        Ok(())
    }

    fn lookup_user(&self, user: &Option<(String, String)>) -> bool {
        if let Some((user, pass)) = user {
            let db = &self.auth.as_ref().unwrap().users;
            db.iter()
                .any(|e| &e.username == user && &e.password == pass)
        } else {
            false
        }
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
