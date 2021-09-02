use std::{os::unix::prelude::AsRawFd, sync::Arc};

use async_trait::async_trait;
use easy_error::{Error, ResultExt};
use log::{debug, info, trace, warn};
use nix::sys::socket::getsockopt;
use nix::sys::socket::sockopt::OriginalDst;
use serde_yaml::Value;
use std::net::Ipv4Addr;
use tokio::net::TcpListener;
use tokio::sync::mpsc::Sender;

use crate::context::ContextRefOps;
use crate::context::{make_buffered_stream, ContextRef, TargetAddress};
use crate::GlobalState;
use serde::{Deserialize, Serialize};

use super::Listener;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TProxyListener {
    name: String,
    bind: String,
}

pub fn from_value(value: &Value) -> Result<Box<dyn Listener>, Error> {
    let ret: TProxyListener = serde_yaml::from_value(value.clone()).context("parse config")?;
    Ok(Box::new(ret))
}

#[async_trait]
impl Listener for TProxyListener {
    async fn init(&mut self) -> Result<(), Error> {
        Ok(())
    }
    async fn listen(
        self: Arc<Self>,
        state: Arc<GlobalState>,
        queue: Sender<ContextRef>,
    ) -> Result<(), Error> {
        info!("{} listening on {}", self.name, self.bind);
        let listener = TcpListener::bind(&self.bind).await.context("bind")?;
        tokio::spawn(async move {
            loop {
                self.clone()
                    .accept(&listener, &state, &queue)
                    .await
                    .map_err(|e| warn!("{}: accept error: {} \ncause: {:?}", self.name, e, e.cause))
                    .unwrap_or(());
            }
        });
        Ok(())
    }

    fn name(&self) -> &str {
        &self.name
    }
}

impl TProxyListener {
    async fn accept(
        self: Arc<Self>,
        listener: &TcpListener,
        state: &Arc<GlobalState>,
        queue: &Sender<ContextRef>,
    ) -> Result<(), Error> {
        let (socket, source) = listener.accept().await.context("accept")?;
        debug!("connected from {:?}", source);
        let dst = getsockopt(socket.as_raw_fd(), OriginalDst).context("getsockopt")?;
        let addr = Ipv4Addr::from(ntohl(dst.sin_addr.s_addr));
        let port = ntohs(dst.sin_port);
        trace!("{}: dst={}:{}", self.name, addr, port);
        let ctx = state.contexts.create_context(self.name.to_owned(), source);
        ctx.write()
            .await
            .set_target(TargetAddress::from((addr, port)))
            .set_client_stream(make_buffered_stream(socket));
        ctx.enqueue(queue).await?;
        Ok(())
    }
}

fn ntohl(x: u32) -> u32 {
    u32::from_be(x)
}

fn ntohs(x: u16) -> u16 {
    u16::from_be(x)
}
