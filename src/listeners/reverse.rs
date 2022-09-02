use async_trait::async_trait;
use bytes::BytesMut;
use easy_error::{Error, ResultExt};
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{duplex, split, AsyncReadExt, AsyncWriteExt, DuplexStream, WriteHalf};
use tokio::spawn;

use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc::Sender;
use tokio::sync::Mutex;

use crate::common::keepalive::set_keepalive;
use crate::common::udp_buffer::UdpBuffer;
use crate::connectors::Feature;
use crate::context::{make_buffered_stream, ContextRef, TargetAddress};
use crate::context::{ContextCallback, ContextRefOps};
use crate::GlobalState;

use super::Listener;

#[derive(Serialize, Deserialize, Debug)]
pub struct ReverseProxyListener {
    name: String,
    bind: SocketAddr,
    target: TargetAddress,
    #[serde(default = "default_protocol")]
    protocol: Protocol,
    #[serde(skip)]
    udp_sessions: Mutex<HashMap<SocketAddr, Session>>,
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
        serde_yaml::from_value(value.clone()).context("parse config")?;
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
                let listener = Arc::new(UdpSocket::bind(&self.bind).await.context("bind")?);
                tokio::spawn(async move {
                    loop {
                        self.udp_recv(&listener, &state, &queue)
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

    async fn udp_recv(
        self: &Arc<Self>,
        listener: &Arc<UdpSocket>,
        state: &Arc<GlobalState>,
        queue: &Sender<ContextRef>,
    ) -> Result<(), Error> {
        let mut buf = UdpBuffer::new();
        let rbuf = buf.body_mut();
        let (size, source) = listener.recv_from(rbuf).await.context("accept")?;
        let buf = buf.finialize(size);
        let source = crate::common::try_map_v4_addr(source);
        debug!("{}: recv from {:?} length: {}", self.name, source, size);
        let mut sessions = self.udp_sessions.lock().await;
        if !sessions.contains_key(&source) {
            let mut new_session = Session::new(listener.clone(), source);
            let ctx = state
                .contexts
                .create_context(self.name.to_owned(), source)
                .await;
            ctx.write()
                .await
                .set_target(self.target.clone())
                .set_feature(Feature::UdpForward)
                .set_idle_timeout(state.timeouts.udp)
                .set_client_stream(make_buffered_stream(new_session.pair()))
                .set_callback(SessionCallback::new(self.clone(), source));
            ctx.enqueue(&queue).await?;
            sessions.insert(source, new_session);
            debug!("session {} added", source);
        }

        let session = sessions.get_mut(&source).unwrap();
        session.push_packet(&buf).await.context("push packet")?;
        Ok(())
    }

    async fn session_end(self: &Arc<Self>, target: SocketAddr) {
        let mut sessions = self.udp_sessions.lock().await;
        if let Some(session) = sessions.get_mut(&target) {
            if let Err(e) = session.shutdown().await {
                warn!("shutdown: unexpected error: {:?}", e);
            }
        }
        sessions.remove(&target);
    }
}

#[derive(Debug)]
struct Session {
    socket: Arc<UdpSocket>,
    target: SocketAddr,
    sink: Option<WriteHalf<DuplexStream>>,
}

impl Session {
    fn new(socket: Arc<UdpSocket>, target: SocketAddr) -> Self {
        Self {
            socket,
            target,
            sink: None,
        }
    }
    fn pair(&mut self) -> DuplexStream {
        let (mine, yours) = duplex(65536 * 10);
        let (read, write) = split(mine);
        self.sink = Some(write);
        let target = self.target;
        let socket = self.socket.clone();
        spawn(async move {
            let mut read = read;
            let mut buf = BytesMut::with_capacity(65536 * 10);
            loop {
                let mut pktbuf = buf.split();
                unsafe {
                    pktbuf.set_len(pktbuf.capacity());
                }
                match read.read_buf(&mut pktbuf).await {
                    Err(e) => {
                        warn!("unexpected error while read udp packet: {:?}", e);
                        break;
                    }
                    Ok(n) => {
                        if n == 0 {
                            break;
                        }
                        pktbuf.truncate(n)
                    }
                }
                buf.unsplit(pktbuf);
                let mut offset = 0;
                while let Some(pkt) = UdpBuffer::try_from_buffer(&buf[offset..]) {
                    if let Err(e) = socket.send_to(&pkt, target).await {
                        warn!("unexpected error while sending udp packet: {:?}", e);
                    }
                    offset += pkt.len() + 8;
                }
                if offset > 0 && offset < buf.len() {
                    let range = offset..buf.len();
                    buf.copy_within(range.clone(), 0);
                    buf.truncate(range.len())
                }
            }
        });
        yours
    }
    async fn push_packet(&mut self, packet: &[u8]) -> std::io::Result<()> {
        self.sink.as_mut().unwrap().write_all(packet).await?;
        Ok(())
    }
    async fn shutdown(&mut self) -> std::io::Result<()> {
        self.sink.as_mut().unwrap().shutdown().await
    }
}

struct SessionCallback {
    listener: Arc<ReverseProxyListener>,
    target: SocketAddr,
}

impl SessionCallback {
    fn new(listener: Arc<ReverseProxyListener>, target: SocketAddr) -> Self {
        Self { listener, target }
    }
}

#[async_trait]
impl ContextCallback for SessionCallback {
    async fn on_error(&self, _ctx: ContextRef, _error: Error) {
        self.listener.session_end(self.target).await
    }
    async fn on_finish(&self, _ctx: ContextRef) {
        self.listener.session_end(self.target).await
    }
}
