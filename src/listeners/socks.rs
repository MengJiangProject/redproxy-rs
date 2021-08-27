use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use easy_error::{err_msg, Error, ResultExt};
use log::{debug, info, trace, warn};
use tokio::io::BufStream;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::Sender;

use crate::common::socks::{PasswordAuth, SocksRequest, SocksResponse};
use crate::common::tls::TlsServerConfig;
use crate::context::{Context, ContextCallback, IOStream};
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
    async fn listen(&self, queue: Sender<Context>) -> Result<(), Error> {
        info!("{} listening on {}", self.name, self.bind);
        let listener = TcpListener::bind(&self.bind).await.context("bind")?;
        let this = Arc::new(self.clone());
        tokio::spawn(this.accept(listener, queue));
        Ok(())
    }

    fn name(&self) -> &str {
        &self.name
    }
}

impl SocksListener {
    async fn accept(self: Arc<Self>, listener: TcpListener, queue: Sender<Context>) {
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
        queue: Sender<Context>,
    ) -> Result<(), Error> {
        let tls_acceptor = self.tls.as_ref().map(|options| options.acceptor());
        let socket: Box<dyn IOStream> = if let Some(acceptor) = tls_acceptor {
            Box::new(acceptor.accept(socket).await.context("tls accept error")?)
        } else {
            Box::new(socket)
        };
        debug!("connected from {:?}", source);
        let mut socket = BufStream::new(socket);
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
        let target = request.target;
        let callback = Callback::new(request.version);
        let mut ctx = Context {
            socket,
            target,
            source,
            listener: self.name().into(),
            callback: Some(callback.clone()),
        };

        if !auth_required || self.lookup_user(request.auth) {
            queue.send(ctx).await.context("enqueue")?;
        } else {
            callback
                .on_error(&mut ctx, err_msg("not authencated"))
                .await;
            trace!("not authencated");
        }
        Ok(())
    }

    fn lookup_user(&self, user: Option<(String, String)>) -> bool {
        if let Some((user, pass)) = user {
            let db = &self.auth.as_ref().unwrap().users;
            db.iter().any(|e| e.username == user && e.password == pass)
        } else {
            false
        }
    }
}
struct Callback {
    version: u8,
}
impl Callback {
    fn new(version: u8) -> Arc<Self> {
        Arc::new(Callback { version })
    }
}
impl ContextCallback for Callback {
    fn on_connect<'a>(
        &self,
        ctx: &'a mut Context,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        let version = self.version;
        let target = ctx.target.clone();
        let cmd = 0;
        Box::pin(async move {
            let s = &mut ctx.socket;
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
    fn on_error<'a>(
        &self,
        ctx: &'a mut Context,
        _error: Error,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        let version = self.version;
        let target = ctx.target.clone();
        let cmd = 1;
        Box::pin(async move {
            let s = &mut ctx.socket;
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
