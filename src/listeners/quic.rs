use async_trait::async_trait;
use easy_error::{Error, ResultExt};
use futures_util::{StreamExt, TryFutureExt};
use log::{debug, info, warn};
use quinn::{Endpoint, Incoming, NewConnection};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::mpsc::Sender;

use crate::common::h11c::h11c_handshake;
use crate::common::quic::{create_quic_server, QuicStream};
use crate::common::tls::TlsServerConfig;
use crate::context::{make_buffered_stream, Context};
use crate::listeners::Listener;

#[derive(Serialize, Deserialize, Debug)]
pub struct QuicListener {
    name: String,
    bind: String,
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
    async fn listen(self: Arc<Self>, queue: Sender<Arc<Context>>) -> Result<(), Error> {
        info!("{} listening on {}", self.name, self.bind);
        let epb = create_quic_server(&self.tls)?;
        let bind_addr = self.bind.parse().context("parse bind")?;
        let (endpoint, incoming) = epb.bind(&bind_addr).context("bind")?;
        tokio::spawn(
            self.accept(endpoint, incoming, queue)
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
        queue: Sender<Arc<Context>>,
    ) -> Result<(), Error> {
        while let Some(conn) = incoming.next().await {
            let name = self.name().to_owned();
            let queue = queue.clone();
            let source = conn.remote_address();
            debug!("{}: connected from {:?}", name, source);
            let NewConnection { mut bi_streams, .. } = conn.await.context("connection")?;
            tokio::spawn(async move {
                while let Some(stream) = bi_streams.next().await {
                    let name = name.clone();
                    let stream = match stream {
                        Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                            info!("{}: connection closed", name);
                            break;
                        }
                        Err(e) => {
                            warn!("{}: connection error: {}", name, e);
                            break;
                        }
                        Ok(s) => s,
                    };
                    let stream: QuicStream = stream.into();
                    let stream = make_buffered_stream(stream);
                    tokio::spawn(
                        h11c_handshake(name.clone(), stream, source, queue.clone()).unwrap_or_else(
                            move |e| warn!("{}: handshake error: {}: {:?}", name, e, e.cause),
                        ),
                    );
                }
            });
        }
        Ok(())
    }
}
