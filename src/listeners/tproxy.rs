use std::os::unix::prelude::AsRawFd;

use async_trait::async_trait;
use easy_error::{Error, ResultExt};
use log::{info, trace, warn};
use nix::sys::socket::getsockopt;
use nix::sys::socket::sockopt::OriginalDst;
use serde_yaml::Value;
use std::net::Ipv4Addr;
use tokio::io::BufStream;
use tokio::net::TcpListener;
use tokio::sync::mpsc::Sender;

use crate::context::{Context, TargetAddress};
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
    async fn listen(&self, queue: Sender<Context>) -> Result<(), Error> {
        info!("listening on {}", self.bind);
        let listener = TcpListener::bind(&self.bind).await.context("bind")?;
        let self = self.clone();
        tokio::spawn(async move {
            loop {
                if let Err(e) = async {
                    let (socket, source) = listener.accept().await.context("accept")?;
                    trace!("connected from {:?}", source);
                    let dst = getsockopt(socket.as_raw_fd(), OriginalDst).context("getsockopt")?;
                    let addr = Ipv4Addr::from(ntohl(dst.sin_addr.s_addr));
                    let port = ntohs(dst.sin_port);
                    trace!("dst={:}:{:?}", addr, port);
                    let socket = BufStream::new(socket);
                    let target = TargetAddress::from((addr, port));
                    queue
                        .send(Context {
                            socket,
                            target,
                            source,
                            listener: self.name().into(),
                        })
                        .await
                        .context("enqueue")?;
                    Ok::<(), Error>(())
                }
                .await
                {
                    warn!("{}: {:?}", e, e.cause);
                }
            }
        });
        Ok(())
    }

    fn name(&self) -> &str {
        &self.name
    }
}

fn ntohl(x: u32) -> u32 {
    u32::from_be(x)
}

fn ntohs(x: u16) -> u16 {
    u16::from_be(x)
}
