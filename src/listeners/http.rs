use async_trait::async_trait;
use easy_error::{Error, ResultExt, bail};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::Sender;
use tracing::{error, info, warn};

use crate::GlobalState;
use crate::common::h11c::h11c_handshake;
use crate::common::set_keepalive;
use crate::common::tls::TlsServerConfig;
use crate::context::{ContextRef, make_buffered_stream};
use crate::listeners::Listener;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct HttpListener {
    name: String,
    bind: SocketAddr,
    tls: Option<TlsServerConfig>,
}

pub fn from_value(value: &serde_yaml_ng::Value) -> Result<Box<dyn Listener>, Error> {
    let ret: HttpListener = serde_yaml_ng::from_value(value.clone()).context("parse config")?;
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
}
impl HttpListener {
    async fn accept(
        self: Arc<Self>,
        listener: TcpListener,
        state: Arc<GlobalState>,
        queue: Sender<ContextRef>,
    ) {
        loop {
            match listener.accept().await.context("accept") {
                Ok((socket, source)) => {
                    // we spawn a new thread here to avoid handshake to block accept thread
                    let this = self.clone();
                    let queue = queue.clone();
                    let state = state.clone();
                    let source = crate::common::try_map_v4_addr(source);
                    tokio::spawn(async move {
                        let res = match this.create_context(state, source, socket).await {
                            Ok(ctx) => {
                                h11c_handshake(ctx, queue, |_, _| async { bail!("not supported") })
                                    .await
                            }
                            Err(e) => Err(e),
                        };
                        if let Err(e) = res {
                            warn!(
                                "{}: handshake failed: {}\ncause: {:?}",
                                this.name, e, e.cause
                            );
                        }
                    });
                }
                Err(e) => {
                    error!("{} accept error: {} \ncause: {:?}", self.name, e, e.cause);
                    return;
                }
            }
        }
    }
    async fn create_context(
        &self,
        state: Arc<GlobalState>,
        source: SocketAddr,
        socket: TcpStream,
    ) -> Result<ContextRef, Error> {
        set_keepalive(&socket)?;
        let tls_acceptor = self.tls.as_ref().map(|options| options.acceptor());
        let stream = if let Some(acceptor) = tls_acceptor {
            acceptor
                .accept(socket)
                .await
                .context("tls accept error")
                .map(make_buffered_stream)?
        } else {
            make_buffered_stream(socket)
        };
        let ctx = state
            .contexts
            .create_context(self.name.to_owned(), source)
            .await;
        ctx.write().await.set_client_stream(stream);
        Ok(ctx)
    }
}
