use async_trait::async_trait;
use easy_error::{err_msg, Error, ResultExt};
use log::{info, trace, warn};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufStream};
use tokio::net::TcpListener;
use tokio::sync::mpsc::Sender;

use crate::context::{Context, TargetAddress};

pub struct HttpListener {
    listen_addr: String,
}

#[async_trait]
impl super::Listener for HttpListener {
    async fn create(block: &str) -> Result<Box<Self>, Error> {
        Ok(Box::new(HttpListener {
            listen_addr: block.to_owned(),
        }))
    }
    async fn listen(&self, queue: Sender<Context>) -> Result<(), Error> {
        info!("listening on {}", self.listen_addr);
        let listener = TcpListener::bind(&self.listen_addr).await.context("bind")?;
        tokio::spawn(async move {
            loop {
                if let Err(e) = accept(&listener, &queue).await {
                    warn!("{}: {:?}", e, e.cause);
                }
            }
        });
        Ok(())
    }
}

async fn accept(listener: &TcpListener, queue: &Sender<Context>) -> Result<(), Error> {
    let (socket, source) = listener.accept().await.context("accept")?;
    trace!("connected from {:?}", source);
    let mut buf = String::with_capacity(256);
    let mut socket = BufStream::new(socket);
    read_line(&mut socket, &mut buf).await?;
    let target = parse_request(&buf)?;
    trace!("dst={:?}", target);
    while buf != "\r\n" && buf != "\n" {
        trace!("buf={:?}", buf);
        buf.clear();
        read_line(&mut socket, &mut buf).await?;
    }
    socket
        .write_all("HTTP/1.1 200 Connection established\r\n\r\n".as_bytes())
        .await
        .context("write_all")?;
    socket.flush().await.context("flush")?;
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

async fn read_line(
    s: &mut (dyn AsyncBufRead + Send + Unpin),
    buf: &mut String,
) -> Result<(), Error> {
    let sz = s.read_line(buf).await.context("readline")?;
    match sz {
        0 => Err(err_msg("EOF")),
        _ => Ok(()),
    }
}

fn parse_request(s: &str) -> Result<TargetAddress, Error> {
    let a: Vec<&str> = s.split_ascii_whitespace().collect();
    if a[0].eq_ignore_ascii_case("CONNECT") && a[2].eq_ignore_ascii_case("HTTP/1.1") {
        a[1].parse().context("parse address")
    } else {
        Err(err_msg("bad request"))
    }
}
