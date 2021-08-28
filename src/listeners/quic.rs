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
}

pub fn from_value(value: &serde_yaml::Value) -> Result<Box<dyn Listener>, Error> {
    let ret: SocksListener = serde_yaml::from_value(value.clone()).context("parse config")?;
    Ok(Box::new(ret))
}

#[async_trait]
impl Listener for SocksListener {
    async fn init(&mut self) -> Result<(), Error> {
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
        Ok(())
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
