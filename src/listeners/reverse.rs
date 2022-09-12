use async_trait::async_trait;
use easy_error::{Error, ResultExt};
use log::{debug, error, info};
use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc::Sender;

use super::Listener;
use crate::common::frames::Frame;
use crate::common::keepalive::set_keepalive;
use crate::common::udp::setup_udp_session;
use crate::context::ContextRefOps;
use crate::context::{make_buffered_stream, ContextRef, Feature, TargetAddress};
use crate::GlobalState;

#[derive(Serialize, Deserialize, Debug)]
pub struct ReverseProxyListener {
    name: String,
    bind: SocketAddr,
    target: TargetAddress,
    #[serde(default = "default_protocol")]
    protocol: Protocol,
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
                let socket = UdpSocket::bind(&self.bind).await.context("bind")?;
                set_reuse_addr(&socket, true)?;
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

        let ctx = state
            .contexts
            .create_context(self.name.to_owned(), source)
            .await;
        let frames = setup_udp_session(self.target.clone(), self.bind, source, buf, false)
            .context("setup session")?;
        ctx.write()
            .await
            .set_target(self.target.clone())
            .set_feature(Feature::UdpForward)
            .set_idle_timeout(state.timeouts.udp)
            .set_client_frames(frames);
        ctx.enqueue(queue).await?;
        Ok(())
    }
}

#[cfg(unix)]
fn set_reuse_addr(socket: &UdpSocket, reuse: bool) -> Result<(), Error> {
    use nix::sys::socket::setsockopt;
    use nix::sys::socket::sockopt::ReuseAddr;
    use std::os::unix::prelude::AsRawFd;
    setsockopt(socket.as_raw_fd(), ReuseAddr, &reuse).context("set_reuse_addr")
}

#[cfg(windows)]
fn set_reuse_addr(sk: &UdpSocket, reuse: bool) -> Result<(), Error> {
    use crate::common::windows;
    use std::os::windows::prelude::*;
    windows::set_reuse_addr(sk.as_raw_socket() as _, reuse).context("set_reuse_addr")
}
