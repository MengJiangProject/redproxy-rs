use async_trait::async_trait;
use easy_error::{bail, Error, ResultExt};
use log::{trace, warn};
use tokio::{
    io::{AsyncWriteExt, BufStream},
    net::TcpStream,
};
use tokio_rustls::webpki::DNSNameRef;

use crate::common::{copy::copy_bidi, http::HttpRequest, tls::TlsClientConfig};
use crate::context::Context;
use crate::{common::http::HttpResponse, context::IOStream};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HttpConnector {
    name: String,
    server: String,
    port: u16,
    tls: Option<TlsClientConfig>,
}

pub fn from_value(value: &serde_yaml::Value) -> Result<Box<dyn super::Connector>, Error> {
    let ret: HttpConnector = serde_yaml::from_value(value.clone()).context("parse config")?;
    Ok(Box::new(ret))
}

#[async_trait]
impl super::Connector for HttpConnector {
    fn name(&self) -> &str {
        self.name.as_str()
    }

    async fn init(&mut self) -> Result<(), Error> {
        if let Some(Err(e)) = self.tls.as_mut().map(TlsClientConfig::init) {
            return Err(e);
        }
        Ok(())
    }

    async fn connect(&self, ctx: Context) -> Result<(), Error> {
        let server_addr = (self.server.to_owned(), self.port);
        let mut client = ctx.socket;
        let target = ctx.target;
        let tls_insecure = self.tls.as_ref().map(|x| x.insecure).unwrap_or(false);
        let tls_connector = self.tls.as_ref().map(|options| options.connector());
        tokio::spawn(async move {
            if let Err(err) = async {
                trace!("connecting to server {:?}", server_addr);
                let server = TcpStream::connect(server_addr.clone())
                    .await
                    .context("connect")?;
                let server: Box<dyn IOStream> = if let Some(connector) = tls_connector {
                    let domain = DNSNameRef::try_from_ascii(server_addr.0.as_bytes())
                        .context(&server_addr.0);
                    let domain = if domain.is_err() && tls_insecure {
                        DNSNameRef::try_from_ascii_str("example.com").unwrap()
                    } else {
                        domain?
                    };
                    Box::new(
                        connector
                            .connect(domain, server)
                            .await
                            .context("tls connector error")?,
                    )
                } else {
                    Box::new(server)
                };

                let mut server = BufStream::new(server);
                HttpRequest::new("CONNECT", &target)
                    .with_header("Host", &target)
                    .write_to(&mut server)
                    .await?;
                server.flush().await.context("flush")?;
                let resp = HttpResponse::read_from(&mut server).await?;
                if resp.code != 200 {
                    bail!("server failure {:?}", resp);
                }
                // let mut client = client.into_inner();
                copy_bidi(&mut client, &mut server)
                    .await
                    .context("copy_bidirectional")
            }
            .await
            {
                warn!("connection failed {:?} {:?}", target, err);
            }
        });
        Ok(())
    }
}
