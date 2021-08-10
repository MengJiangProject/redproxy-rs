use std::os::unix::prelude::AsRawFd;

use async_trait::async_trait;
use easy_error::{Error, ResultExt};
use log::{info, trace, warn};
use nix::sys::socket::getsockopt;
use nix::sys::socket::sockopt::OriginalDst;
use std::net::Ipv4Addr;
use tokio::io::BufStream;
use tokio::net::TcpListener;
use tokio::sync::mpsc::Sender;

use crate::context::{Context, TargetAddress};

pub struct TProxyListener {
    listen_addr: String,
}

#[async_trait]
impl super::Listener for TProxyListener {
    async fn create(block: &str) -> Result<Box<Self>, Box<dyn std::error::Error>> {
        Ok(Box::new(TProxyListener {
            listen_addr: block.to_owned(),
        }))
    }
    async fn listen(&self, queue: Sender<Context>) -> Result<(), Box<dyn std::error::Error>> {
        info!("listening on {}", self.listen_addr);
        let listener = TcpListener::bind(&self.listen_addr).await?;
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
}

fn ntohl(x: u32) -> u32 {
    u32::from_be(x)
}

fn ntohs(x: u16) -> u16 {
    u16::from_be(x)
}
