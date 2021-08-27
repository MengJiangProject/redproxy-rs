use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use easy_error::{Error, ResultExt};
use log::{debug, info, warn};
use tokio::io::BufStream;
use tokio::net::TcpListener;
use tokio::sync::mpsc::Sender;

use crate::common::socks::{NoAuth, SocksRequest, SocksResponse};
use crate::common::tls::TlsServerConfig;
use crate::context::{Context, ContextCallback, IOStream};
use crate::listeners::Listener;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SocksListener {
    name: String,
    bind: String,
    tls: Option<TlsServerConfig>,
}

pub fn from_value(value: &serde_yaml::Value) -> Result<Box<dyn Listener>, Error> {
    let ret: SocksListener = serde_yaml::from_value(value.clone()).context("parse config")?;
    Ok(Box::new(ret))
}

#[async_trait]
impl Listener for SocksListener {
    async fn init(&mut self) -> Result<(), Error> {
        if let Some(Err(e)) = self.tls.as_mut().map(TlsServerConfig::init) {
            return Err(e);
        }
        Ok(())
    }
    async fn listen(&self, queue: Sender<Context>) -> Result<(), Error> {
        info!("{} listening on {}", self.name, self.bind);
        let listener = TcpListener::bind(&self.bind).await.context("bind")?;
        let self = self.clone();
        tokio::spawn(async move {
            loop {
                let accept = async {
                    let tls_acceptor = self.tls.as_ref().map(|options| options.acceptor());
                    let (socket, source) = listener.accept().await.context("accept")?;
                    let socket: Box<dyn IOStream> = if let Some(acceptor) = tls_acceptor {
                        Box::new(acceptor.accept(socket).await.context("tls accept error")?)
                    } else {
                        Box::new(socket)
                    };
                    debug!("connected from {:?}", source);
                    let mut socket = BufStream::new(socket);
                    let request = SocksRequest::read_from(&mut socket, NoAuth).await?;
                    let target = request.target;
                    struct Callback {
                        version: u8,
                    }
                    impl ContextCallback for Callback {
                        fn on_connect<'a>(
                            &self,
                            ctx: &'a mut Context,
                        ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
                            let version = self.version;
                            let target = ctx.target.clone();
                            let cmd = 0;
                            Box::pin(async move {
                                let s = &mut ctx.socket;
                                let resp = SocksResponse {
                                    version,
                                    cmd,
                                    target,
                                };
                                if let Some(e) = resp.write_to(s).await.err() {
                                    warn!("failed to send response: {}", e)
                                }
                            })
                        }
                        fn on_error<'a>(
                            &self,
                            ctx: &'a mut Context,
                            _error: Error,
                        ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
                            let version = self.version;
                            let target = ctx.target.clone();
                            let cmd = 1;
                            Box::pin(async move {
                                let s = &mut ctx.socket;
                                let resp = SocksResponse {
                                    version,
                                    cmd,
                                    target,
                                };
                                if let Some(e) = resp.write_to(s).await.err() {
                                    warn!("failed to send response: {}", e)
                                }
                            })
                        }
                    }

                    queue
                        .send(Context {
                            socket,
                            target,
                            source,
                            listener: self.name().into(),
                            callback: Some(Arc::new(Callback {
                                version: request.version,
                            })),
                        })
                        .await
                        .context("enqueue")?;
                    Ok::<(), Error>(())
                };
                if let Err(e) = accept.await {
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
