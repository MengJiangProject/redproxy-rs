use std::{convert::TryFrom, sync::Arc};

use async_trait::async_trait;
use easy_error::{err_msg, Error, ResultExt};
use rustls::pki_types::ServerName;
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tracing::trace;

use crate::{
    common::{http_proxy::http_proxy_connect, set_keepalive, tls::TlsClientConfig},
    context::{make_buffered_stream, ContextRef, Feature},
    GlobalState,
};

use super::ConnectorRef;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct HttpConnector {
    name: String,
    server: String,
    port: u16,
    tls: Option<TlsClientConfig>,
    always_use_connect: Option<bool>,
}

pub fn from_value(value: &serde_yaml_ng::Value) -> Result<ConnectorRef, Error> {
    let ret: HttpConnector = serde_yaml_ng::from_value(value.clone()).context("parse config")?;
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

    fn features(&self) -> &[Feature] {
        &[Feature::TcpForward, Feature::UdpForward, Feature::UdpBind]
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

        let server_connection = if let Some(connector) = tls_connector {
            let server_name = self.server.clone();
            let domain = ServerName::try_from(server_name)
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

        let always_connect_enabled = self.always_use_connect.unwrap_or(false);
        let is_incoming_http_request = ctx.read().await.http_request().is_some();

        if always_connect_enabled && is_incoming_http_request {
            ctx.write()
                .await
                .set_extra("h_conn_force_connect_then_send", "true");
        }

        http_proxy_connect(server_connection, ctx, local, remote, "inline", |_| async {
            panic!("not supported")
        })
        .await?;
        Ok(())
    }
}
