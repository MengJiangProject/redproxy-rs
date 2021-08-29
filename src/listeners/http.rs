use async_trait::async_trait;
use easy_error::{Error, ResultExt};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::mpsc::Sender;

use crate::common::h11c::h11c_handshake;
use crate::common::tls::TlsServerConfig;
use crate::context::{make_buffered_stream, Context};
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
    async fn listen(self: Arc<Self>, queue: Sender<Context>) -> Result<(), Error> {
        info!("{} listening on {}", self.name, self.bind);
        let listener = TcpListener::bind(&self.bind).await.context("bind")?;
        let this = self.clone();
        tokio::spawn(this.accept(listener, queue));
        Ok(())
    }
}
impl HttpListener {
    async fn accept(self: Arc<Self>, listener: TcpListener, queue: Sender<Context>) {
        loop {
            let name = self.name.to_owned();
            let queue = queue.clone();
            match listener.accept().await.context("accept") {
                Ok((socket, source)) => {
                    // we spawn a new thread here to avoid handshake to block accept thread
                    tokio::spawn(async move {
                        let stream = make_buffered_stream(socket);
                        if let Err(e) = h11c_handshake(name, stream, source, queue).await {
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
}
