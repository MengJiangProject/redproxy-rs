use async_trait::async_trait;
use easy_error::{Error, ResultExt};
use log::{debug, error, info};
use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::io::{ErrorKind, Result as IoResult};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::Mutex;

use crate::common::frames::{Frame, FrameReader, FrameWriter, Frames};
use crate::common::keepalive::set_keepalive;
use crate::context::{make_buffered_stream, Context, ContextRef, Feature, TargetAddress};
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
        let mut buf = Frame::new();
        let (size, source) = buf.recv_from(listener).await.context("accept")?;
        buf.addr = Some(self.target.clone());
        let source = crate::common::try_map_v4_addr(source);
        debug!("{}: recv from {:?} length: {}", self.name, source, size);
        let mut sessions = self.udp_sessions.lock().await;
        if let Entry::Vacant(e) = sessions.entry(source) {
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
                .set_client_frames(new_session.frames())
                .set_callback(SessionCallback::new(self.clone(), source));
            ctx.enqueue(queue).await?;
            e.insert(new_session);
            debug!("session {} added", source);
        }

        let session = sessions.get_mut(&source).unwrap();
        session.push_packet(buf).await.context("push packet")?;
        Ok(())
    }

    async fn session_end(self: &Arc<Self>, target: SocketAddr) {
        let mut sessions = self.udp_sessions.lock().await;
        if let Some(session) = sessions.get_mut(&target) {
            session.shutdown().await
        }
        sessions.remove(&target);
    }
}

struct Session {
    socket: Arc<UdpSocket>,
    target: SocketAddr,
    tx: Option<Sender<Frame>>,
    rx: Option<Receiver<Frame>>,
}

impl Session {
    fn new(socket: Arc<UdpSocket>, target: SocketAddr) -> Self {
        let (tx, rx) = channel(10);
        Self {
            socket,
            target,
            tx: Some(tx),
            rx: Some(rx),
        }
    }

    async fn push_packet(&mut self, frame: Frame) -> IoResult<()> {
        if self.tx.is_none() {
            return Err(std::io::Error::from(ErrorKind::BrokenPipe));
        }
        self.tx
            .as_mut()
            .unwrap()
            .send(frame)
            .await
            .map_err(|_| std::io::Error::from(ErrorKind::BrokenPipe))
    }

    async fn shutdown(&mut self) {
        self.tx.take();
    }

    fn frames(&mut self) -> Frames {
        let rx = self.rx.take().unwrap();
        let socket = self.socket.clone();
        let target = self.target;
        let r = SessionFrameReader { rx };
        let w = SessionFrameWriter { socket, target };
        (Box::new(r), Box::new(w))
    }
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("target", &self.target)
            .finish()
    }
}

struct SessionFrameReader {
    rx: Receiver<Frame>,
}

#[async_trait]
impl FrameReader for SessionFrameReader {
    async fn read(&mut self) -> IoResult<Option<Frame>> {
        Ok(self.rx.recv().await)
    }
}

struct SessionFrameWriter {
    socket: Arc<UdpSocket>,
    target: SocketAddr,
}

#[async_trait]
impl FrameWriter for SessionFrameWriter {
    async fn write(&mut self, frame: &Frame) -> IoResult<()> {
        self.socket.send_to(frame.body(), self.target).await?;
        Ok(())
    }
    async fn shutdown(&mut self) -> IoResult<()> {
        Ok(())
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
    async fn on_error(&self, _ctx: &mut Context, _error: Error) {
        self.listener.session_end(self.target).await
    }
    async fn on_finish(&self, _ctx: &mut Context) {
        self.listener.session_end(self.target).await
    }
}
