use async_trait::async_trait;
use easy_error::{Error, ResultExt};
use futures_util::{StreamExt, TryFutureExt};
use log::{debug, info, warn};
use quinn::{Endpoint, Incoming, NewConnection};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc::Sender;

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
    ) -> Result<(), Error> {
        info!("{} listening on {}", self.name, self.bind);
        let epb = create_quic_server(&self.tls)?;
        let (endpoint, incoming) = epb.bind(&self.bind).context("bind")?;
        tokio::spawn(
            self.accept(endpoint, incoming, state, queue)
                .unwrap_or_else(|e| warn!("{}: {:?}", e, e.cause)),
        );
        Ok(())
    }
}
impl QuicListener {
    async fn accept(
        self: Arc<Self>,
        _endpoint: Endpoint,
        mut incoming: Incoming,
        state: Arc<GlobalState>,
        queue: Sender<ContextRef>,
    ) -> Result<(), Error> {
        while let Some(conn) = incoming.next().await {
            let queue = queue.clone();
            let source = conn.remote_address();
            debug!("{}: QUIC connected from {:?}", self.name, source);
            let NewConnection { mut bi_streams, .. } = conn.await.context("connection")?;
            let this = self.clone();
            let state = state.clone();
            tokio::spawn(async move {
                while let Some(stream) = bi_streams.next().await {
                    let stream = match stream {
                        Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                            info!("{}: QUIC connection closed", this.name);
                            break;
                        }
                        Err(e) => {
                            warn!("{}: QUIC connection error: {}", this.name, e);
                            break;
                        }
                        Ok(s) => s,
                    };
                    debug!("{}: BiStream connected from {:?}", this.name, source);
                    let stream: QuicStream = stream.into();
                    let stream = make_buffered_stream(stream);
                    let ctx = state.contexts.create_context(this.name.to_owned(), source);
                    ctx.write().await.set_client_stream(stream);
                    let this = this.clone();
                    tokio::spawn(h11c_handshake(ctx, queue.clone()).unwrap_or_else(move |e| {
                        warn!("{}: h11c handshake error: {}: {:?}", this.name, e, e.cause)
                    }));
                }
            });
        }
        Ok(())
    }
}
