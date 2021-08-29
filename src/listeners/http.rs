use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use easy_error::{bail, err_msg, Error, ResultExt};
use log::{debug, info, warn};
use tokio::io::{AsyncWriteExt, BufStream};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::Sender;

use crate::common::http::{HttpRequest, HttpResponse};
use crate::common::tls::TlsServerConfig;
use crate::context::{Context, ContextCallback, IOStream};
use crate::listeners::Listener;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HttpListener {
    name: String,
    bind: String,
    tls: Option<TlsServerConfig>,
}

pub fn from_value(value: &serde_yaml::Value) -> Result<Box<dyn Listener>, Error> {
    let ret: HttpListener = serde_yaml::from_value(value.clone()).context("parse config")?;
    Ok(Box::new(ret))
}

#[async_trait]
impl Listener for HttpListener {
    fn name(&self) -> &str {
        &self.name
    }
    async fn init(&mut self) -> Result<(), Error> {
        if let Some(Err(e)) = self.tls.as_mut().map(TlsServerConfig::init) {
            return Err(e);
        }
        Ok(())
    }
    async fn listen(&self, queue: Sender<Context>) -> Result<(), Error> {
        info!("{} listening on {}", self.name, self.bind);
        let listener = TcpListener::bind(&self.bind).await.context("bind")?;
        let this = Arc::new(self.clone());
        tokio::spawn(this.accept(listener, queue));
        Ok(())
    }
}
impl HttpListener {
    async fn accept(self: Arc<Self>, listener: TcpListener, queue: Sender<Context>) {
        loop {
            let this = self.clone();
            let queue = queue.clone();
            match listener.accept().await.context("accept") {
                Ok((socket, source)) => {
                    // we spawn a new thread here to avoid handshake to block accept thread
                    tokio::spawn(async move {
                        if let Err(e) = this.handshake(socket, source, queue).await {
                            warn!("{}: {:?}", e, e.cause);
                        }
                    });
                }
                Err(e) => {
                    warn!("{}: {:?}", e, e.cause);
                    return;
                }
            }
        }
    }

    async fn handshake(
        self: Arc<Self>,
        socket: TcpStream,
        source: SocketAddr,
        queue: Sender<Context>,
    ) -> Result<(), Error> {
        let tls_acceptor = self.tls.as_ref().map(|options| options.acceptor());
        let socket: Box<dyn IOStream> = if let Some(acceptor) = tls_acceptor {
            Box::new(acceptor.accept(socket).await.context("tls accept error")?)
        } else {
            Box::new(socket)
        };
        debug!("connected from {:?}", source);
        let mut socket = BufStream::new(socket);
        let request = HttpRequest::read_from(&mut socket).await?;
        if !request.method.eq_ignore_ascii_case("CONNECT") {
            bail!("Invalid request method: {}", request.method)
        }
        let target = request.resource.parse().map_err(|_e| {
            err_msg(format!(
                "failed to parse target address: {}",
                request.resource
            ))
        })?;

        queue
            .send(Context {
                socket,
                target,
                source,
                listener: self.name().into(),
                callback: Some(Arc::new(Callback)),
            })
            .await
            .context("enqueue")?;
        Ok(())
    }
}
struct Callback;
impl ContextCallback for Callback {
    fn on_connect<'a>(
        &self,
        ctx: &'a mut Context,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            let s = &mut ctx.socket;
            if let Some(e) = HttpResponse::new(200, "Connection established")
                .write_to(s)
                .await
                .and(s.flush().await.context("flush"))
                .err()
            {
                warn!("failed to send response: {}", e)
            }
        })
    }
    fn on_error<'a>(
        &self,
        ctx: &'a mut Context,
        error: Error,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            let s = &mut ctx.socket;
            if let Some(e) = HttpResponse::new(503, "Service unavailable")
                .with_header("Error", error)
                .write_to(s)
                .await
                .and(s.flush().await.context("flush"))
                .err()
            {
                warn!("failed to send response: {}", e)
            }
        })
    }
}
