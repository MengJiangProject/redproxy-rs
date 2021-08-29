use std::sync::Arc;

use async_trait::async_trait;
use easy_error::{bail, Error, ResultExt};
use log::trace;
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio_rustls::webpki::DNSNameRef;

use crate::{
    common::{
        http::{HttpRequest, HttpResponse},
        tls::TlsClientConfig,
    },
    context::{make_buffered_stream, Context, IOBufStream},
};

use super::ConnectorRef;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HttpConnector {
    name: String,
    server: String,
    port: u16,
    tls: Option<TlsClientConfig>,
}

pub fn from_value(value: &serde_yaml::Value) -> Result<ConnectorRef, Error> {
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

    async fn connect(self: Arc<Self>, ctx: &Context) -> Result<IOBufStream, Error> {
        let tls_insecure = self.tls.as_ref().map(|x| x.insecure).unwrap_or(false);
        let tls_connector = self.tls.as_ref().map(|options| options.connector());
        trace!(
            "{} connecting to server {}:{}",
            self.name,
            self.server,
            self.port
        );
        let server = TcpStream::connect((self.server.as_str(), self.port))
            .await
            .with_context(|| format!("failed to connect to upstream server: {}", self.server))?;
        let mut server = if let Some(connector) = tls_connector {
            let domain = DNSNameRef::try_from_ascii(self.server.as_bytes())
                .or_else(|e| {
                    if tls_insecure {
                        DNSNameRef::try_from_ascii_str("example.com")
                    } else {
                        Err(e)
                    }
                })
                .with_context(|| format!("invalid upstream address: {}", self.server))?;
            make_buffered_stream(
                connector
                    .connect(domain, server)
                    .await
                    .context("tls connector error")?,
            )
        } else {
            make_buffered_stream(server)
        };

        HttpRequest::new("CONNECT", &ctx.target)
            .with_header("Host", &ctx.target)
            .write_to(&mut server)
            .await?;
        let resp = HttpResponse::read_from(&mut server).await?;
        if resp.code != 200 {
            bail!("upstream server failure: {:?}", resp);
        }
        Ok(server)
    }
}
