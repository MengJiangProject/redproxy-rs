use async_trait::async_trait;
use easy_error::{bail, Error, ResultExt};
use futures_util::{StreamExt, TryFutureExt};
use log::{debug, info, warn};
use quinn::{Endpoint, Incoming, IncomingBiStreams, NewConnection};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc::Sender;
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use crate::common::h11c::h11c_handshake;
use crate::common::quic::{create_quic_server, QuicStream};
use crate::common::tls::TlsServerConfig;
use crate::context::{make_buffered_stream, ContextRef};
use crate::listeners::Listener;
use crate::GlobalState;

#[derive(Serialize, Deserialize, Debug)]
pub struct QuicListener {
    name: String,
    bind: SocketAddr,
    tls: TlsServerConfig,
}

pub fn from_value(value: &serde_yaml::Value) -> Result<Box<dyn Listener>, Error> {
    let ret: QuicListener = serde_yaml::from_value(value.clone()).context("parse config")?;
    Ok(Box::new(ret))
}

#[async_trait]
impl Listener for QuicListener {
    fn name(&self) -> &str {
        &self.name
    }
    async fn init(&mut self) -> Result<(), Error> {
        self.tls.init()?;
        Ok(())
    }
    async fn listen(
        self: Arc<Self>,
        state: Arc<GlobalState>,
        queue: Sender<ContextRef>,
    ) -> Result<(JoinHandle<()>, Arc<Notify>), Error> {
        info!("{} listening on {}", self.name, self.bind);
        let epb = create_quic_server(&self.tls)?;
        let (endpoint, incoming) = epb.bind(&self.bind).context("bind")?;
        let shutdown = Arc::new(Notify::new());
        let task = tokio::spawn(
            self.accept(endpoint, incoming, state, queue, shutdown.clone())
                .unwrap_or_else(|e| panic!("{}: {:?}", e, e.cause)),
        );
        Ok((task, shutdown))
    }
}
impl QuicListener {
    async fn accept(
        self: Arc<Self>,
        endpoint: Endpoint,
        mut incoming: Incoming,
        state: Arc<GlobalState>,
        queue: Sender<ContextRef>,
        shutdown: Arc<Notify>,
    ) -> Result<(), Error> {
        loop {
            tokio::select! {
                _ = shutdown.notified() => {
                    endpoint.close(0u8.into(),b"shutdown");
                    return Ok(())
                },
                res = incoming.next() => match res {
                    Some(conn) => {
                        let source = conn.remote_address();
                        debug!("{}: QUIC connected from {:?}", self.name, source);
                        match conn.await.context("connection") {
                            Ok(NewConnection { bi_streams, .. }) => {
                                let this = self.clone();
                                let state = state.clone();
                                let queue = queue.clone();
                                tokio::spawn(this.client_thead(bi_streams, source, state, queue));
                            }
                            Err(e) => {
                                warn!("{}, Accept error: {}: cause: {:?}", self.name, e, e.cause);
                            }
                        }
                    }
                    None => bail!("end of incoming stream")
                },
            }
        }
    }
    async fn client_thead(
        self: Arc<Self>,
        mut bi_streams: IncomingBiStreams,
        source: SocketAddr,
        state: Arc<GlobalState>,
        queue: Sender<ContextRef>,
    ) {
        while let Some(stream) = bi_streams.next().await {
            let stream = match stream {
                Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                    info!("{}: QUIC connection closed", self.name);
                    break;
                }
                Err(e) => {
                    warn!("{}: QUIC connection error: {}", self.name, e);
                    break;
                }
                Ok(s) => s,
            };
            debug!("{}: BiStream connected from {:?}", self.name, source);
            let stream: QuicStream = stream.into();
            let stream = make_buffered_stream(stream);
            let ctx = state
                .contexts
                .create_context(self.name.to_owned(), source)
                .await;
            ctx.write().await.set_client_stream(stream);
            let this = self.clone();
            tokio::spawn(h11c_handshake(ctx, queue.clone()).unwrap_or_else(move |e| {
                warn!("{}: h11c handshake error: {}: {:?}", this.name, e, e.cause)
            }));
        }
    }
}
