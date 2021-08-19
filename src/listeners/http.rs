use async_trait::async_trait;
use easy_error::{bail, err_msg, Error, ResultExt};
use log::{info, trace, warn};
use tokio::io::{AsyncWriteExt, BufStream};
use tokio::net::TcpListener;
use tokio::sync::mpsc::Sender;

use crate::common::http::HttpRequest;
use crate::common::tls::{acceptor, TlsOptions};
use crate::context::Context;
use crate::listeners::Listener;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HttpListener {
    name: String,
    bind: String,
    tls: Option<TlsOptions>,
}

pub fn from_value(value: &serde_yaml::Value) -> Result<Box<dyn Listener>, Error> {
    let ret: HttpListener = serde_yaml::from_value(value.clone()).context("parse config")?;
    Ok(Box::new(ret))
}

#[async_trait]
impl Listener for HttpListener {
    async fn init(&mut self) -> Result<(), Error> {
        Ok(())
    }
    async fn listen(&self, queue: Sender<Context>) -> Result<(), Error> {
        info!("listening on {}", self.bind);
        let listener = TcpListener::bind(&self.bind).await.context("bind")?;
        let tls_acceptor = self.tls.as_ref().map(|options| acceptor(options));
        if let Some(Err(e)) = tls_acceptor {
            return Err(e);
        }
        // let tls_acceptor = tls_acceptor??;
        let self = self.clone();
        tokio::spawn(async move {
            loop {
                if let Err(e) = self.accept(&listener, &queue).await {
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

impl HttpListener {
    async fn accept(&self, listener: &TcpListener, queue: &Sender<Context>) -> Result<(), Error> {
        let (socket, source) = listener.accept().await.context("accept")?;
        trace!("connected from {:?}", source);
        let mut socket = BufStream::new(socket);
        let request = HttpRequest::new(&mut socket).await?;
        if !request.method.eq_ignore_ascii_case("CONNECT") {
            bail!("Invalid request method: {}", request.method)
        }
        let target = request.resource.parse().map_err(|_e| {
            err_msg(format!(
                "failed to parse target address: {}",
                request.resource
            ))
        })?;
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
                listener: self.name().into(),
            })
            .await
            .context("enqueue")?;
        Ok::<(), Error>(())
    }
}
