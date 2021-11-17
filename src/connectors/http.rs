use std::{convert::TryFrom, sync::Arc};

use async_trait::async_trait;
use easy_error::{bail, err_msg, Error, ResultExt};
use log::trace;
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio_rustls::rustls::ServerName;

use crate::{
    common::{
        http::{HttpRequest, HttpResponse},
        keepalive::set_keepalive,
        tls::TlsClientConfig,
    },
    context::{make_buffered_stream, ContextRef},
    GlobalState,
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

    async fn connect(
        self: Arc<Self>,
        _state: Arc<GlobalState>,
        ctx: ContextRef,
    ) -> Result<(), Error> {
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
        let local = server.local_addr().context("local_addr")?;
        let remote = server.peer_addr().context("peer_addr")?;
        set_keepalive(&server)?;

        let mut server = if let Some(connector) = tls_connector {
            let domain = ServerName::try_from(self.server.as_str())
                .or_else(|e| {
                    if tls_insecure {
                        ServerName::try_from("example.com")
                    } else {
                        Err(e)
                    }
                })
                .map_err(|_e| err_msg(format!("invalid upstream address: {}", self.server)))?;
            make_buffered_stream(
                connector
                    .connect(domain, server)
                    .await
                    .context("tls connector error")?,
            )
        } else {
            make_buffered_stream(server)
        };

        let target = ctx.read().await.target();
        HttpRequest::new("CONNECT", &target)
            .with_header("Host", &target)
            .write_to(&mut server)
            .await?;
        let resp = HttpResponse::read_from(&mut server).await?;
        if resp.code != 200 {
            bail!("upstream server failure: {:?}", resp);
        }
        ctx.write()
            .await
            .set_server_stream(server)
            .set_local_addr(local)
            .set_server_addr(remote);
        Ok(())
    }
}
