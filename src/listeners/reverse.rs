use async_trait::async_trait;
use chashmap_async::CHashMap;
use easy_error::{Error, ResultExt};
use serde::{Deserialize, Serialize};
use serde_yaml_ng::Value;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc::{Sender, channel};
use tracing::{debug, error, info};

use super::Listener;
use crate::GlobalState;
use crate::common::frames::Frame;
use crate::common::set_keepalive;
use crate::common::udp::{self, setup_udp_session, udp_socket};
use crate::context::{Context, ContextRef, Feature, TargetAddress, make_buffered_stream};
use crate::context::{ContextCallback, ContextRefOps};

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReverseProxyListener {
    name: String,
    bind: SocketAddr,
    target: TargetAddress,
    #[serde(default = "default_protocol")]
    protocol: Protocol,
    #[serde(skip)]
    sessions: Arc<CHashMap<SocketAddr, udp::Sender>>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
#[serde(rename_all = "camelCase")]
pub enum Protocol {
    Tcp,
    Udp,
}

fn default_protocol() -> Protocol {
    Protocol::Tcp
}

pub fn from_value(value: &Value) -> Result<Box<dyn Listener>, Error> {
    let ret: ReverseProxyListener =
        serde_yaml_ng::from_value(value.clone()).context("parse config")?;
    Ok(Box::new(ret))
}

#[async_trait]
impl Listener for ReverseProxyListener {
    async fn listen(
        self: Arc<Self>,
        state: Arc<GlobalState>,
        queue: Sender<ContextRef>,
    ) -> Result<(), Error> {
        info!("{} listening on {}", self.name, self.bind);
        match self.protocol {
            Protocol::Tcp => {
                let listener = TcpListener::bind(&self.bind).await.context("bind")?;
                tokio::spawn(async move {
                    loop {
                        self.tcp_accept(&listener, &state, &queue)
                            .await
                            .unwrap_or_else(|e| {
                                error!("{}: accept error: {} \ncause: {:?}", self.name, e, e.cause)
                            });
                    }
                });
            }
            Protocol::Udp => {
                let socket = udp_socket(self.bind, None, false).context("bind")?;
                let listener = Arc::new(socket);
                tokio::spawn(async move {
                    loop {
                        self.udp_accept(&listener, &state, &queue)
                            .await
                            .unwrap_or_else(|e| {
                                error!("{}: accept error: {} \ncause: {:?}", self.name, e, e.cause)
                            });
                    }
                });
            }
        }
        Ok(())
    }

    fn name(&self) -> &str {
        &self.name
    }
}

impl ReverseProxyListener {
    async fn tcp_accept(
        self: &Arc<Self>,
        listener: &TcpListener,
        state: &Arc<GlobalState>,
        queue: &Sender<ContextRef>,
    ) -> Result<(), Error> {
        let (socket, source) = listener.accept().await.context("accept")?;
        let source = crate::common::try_map_v4_addr(source);
        set_keepalive(&socket)?;
        debug!("{}: connected from {:?}", self.name, source);
        let ctx = state
            .contexts
            .create_context(self.name.to_owned(), source)
            .await;
        ctx.write()
            .await
            .set_target(self.target.clone())
            .set_client_stream(make_buffered_stream(socket));
        ctx.enqueue(queue).await?;
        Ok(())
    }

    async fn udp_accept(
        self: &Arc<Self>,
        listener: &Arc<UdpSocket>,
        state: &Arc<GlobalState>,
        queue: &Sender<ContextRef>,
    ) -> Result<(), Error> {
        let mut buf = Frame::new();
        let (size, source) = buf.recv_from(listener).await.context("accept")?;
        buf.addr = Some(self.target.clone());
        let source = crate::common::try_map_v4_addr(source);
        debug!("{}: recv from {:?} length: {}", self.name, source, size);

        if let Some(tx) = self.sessions.get(&source).await {
            tx.send(buf).await.context("send")?;
        } else {
            let (tx, rx) = channel(100);
            let io = setup_udp_session(self.target.clone(), self.bind, source, rx, false)
                .context("setup session")?;
            self.sessions.insert(source, tx).await;
            let ctx = state
                .contexts
                .create_context(self.name.to_owned(), source)
                .await;
            ctx.write()
                .await
                .set_target(self.target.clone())
                .set_feature(Feature::UdpForward)
                .set_idle_timeout(state.timeouts.udp)
                .set_callback(ReverseCallback::new(source, self.sessions.clone()))
                .set_client_frames(io);
            ctx.enqueue(queue).await?;
        }
        Ok(())
    }
}

struct ReverseCallback {
    client: SocketAddr,
    sessions: Arc<CHashMap<SocketAddr, udp::Sender>>,
}

impl ReverseCallback {
    fn new(client: SocketAddr, sessions: Arc<CHashMap<SocketAddr, udp::Sender>>) -> Self {
        Self { client, sessions }
    }
}

#[async_trait]
impl ContextCallback for ReverseCallback {
    async fn on_error(&self, _ctx: &mut Context, _error: Error) {
        self.sessions.remove(&self.client).await;
    }
    async fn on_finish(&self, _ctx: &mut Context) {
        self.sessions.remove(&self.client).await;
    }
}
