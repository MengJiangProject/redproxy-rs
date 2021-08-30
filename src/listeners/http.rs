use async_trait::async_trait;
use easy_error::{Error, ResultExt};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::mpsc::Sender;

use crate::common::h11c::h11c_handshake;
use crate::common::tls::TlsServerConfig;
use crate::context::{make_buffered_stream, ContextRef};
use crate::listeners::Listener;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HttpListener {
    name: String,
    bind: String,
    tls: Option<TlsServerConfig>,
}

pub fn from_value(value: &serde_yaml::Value) -> Result<Box<dyn Listener>, Error> {
    let ret: HttpListener = serde_yaml::from_value(value.clone()).context("parse config")?;
    Ok(Box::new(ret))
}

#[async_trait]
impl Listener for HttpListener {
    fn name(&self) -> &str {
        &self.name
    }
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
}
impl HttpListener {
    async fn accept(self: Arc<Self>, listener: TcpListener, queue: Sender<ContextRef>) {
        loop {
            let queue = queue.clone();
            match listener.accept().await.context("accept") {
                Ok((socket, source)) => {
                    // we spawn a new thread here to avoid handshake to block accept thread
                    let this = self.clone();
                    tokio::spawn(async move {
                        let name = this.name.to_owned();
                        if let Err(e) = {
                            let tls_acceptor = this.tls.as_ref().map(|options| options.acceptor());
                            let stream = if let Some(acceptor) = tls_acceptor {
                                acceptor
                                    .accept(socket)
                                    .await
                                    .context("tls accept error")
                                    .map(make_buffered_stream)
                            } else {
                                Ok(make_buffered_stream(socket))
                            };
                            match stream {
                                Ok(stream) => h11c_handshake(name, stream, source, queue).await,
                                Err(e) => Err(e),
                            }
                        } {
                            warn!(
                                "{}: handshake failed: {}\ncause: {:?}",
                                this.name, e, e.cause
                            );
                        }
                    });
                }
                Err(e) => {
                    warn!("{} accept error: {} \ncause: {:?}", self.name, e, e.cause);
                    return;
                }
            }
        }
    }
}
