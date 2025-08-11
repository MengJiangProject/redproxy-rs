use std::{convert::TryFrom, sync::Arc};

use anyhow::{Context, Result};
use async_trait::async_trait;
use rustls::pki_types::ServerName;
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tracing::{error, trace};

use crate::{
    common::{h11c::h11c_connect, set_keepalive, tls::TlsClientConfig},
    context::{ContextRef, Feature, make_buffered_stream},
};

use super::ConnectorRef;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct HttpConnector {
    name: String,
    server: String,
    port: u16,
    tls: Option<TlsClientConfig>,
}

pub fn from_value(value: &serde_yaml_ng::Value) -> Result<ConnectorRef> {
    let ret: HttpConnector = serde_yaml_ng::from_value(value.clone()).context("parse config")?;
    Ok(Box::new(ret))
}

#[async_trait]
impl super::Connector for HttpConnector {
    fn name(&self) -> &str {
        self.name.as_str()
    }

    async fn init(&mut self) -> Result<()> {
        if let Some(Err(e)) = self.tls.as_mut().map(TlsClientConfig::init) {
            return Err(e);
        }
        Ok(())
    }

    fn features(&self) -> &[Feature] {
        &[Feature::TcpForward, Feature::UdpForward, Feature::UdpBind]
    }

    async fn connect(self: Arc<Self>, ctx: ContextRef) -> Result<()> {
        let tls_insecure = self.tls.as_ref().map(|x| x.insecure).unwrap_or(false);
        let tls_connector = self
            .tls
            .as_ref()
            .map(|options| options.connector())
            .transpose()
            .context("TLS connector initialization failed")?;
        trace!(
            "{} connecting to server {}:{}",
            self.name, self.server, self.port
        );
        let server = TcpStream::connect((self.server.as_str(), self.port))
            .await
            .with_context(|| format!("failed to connect to upstream server: {}", self.server))?;
        let local = server.local_addr().context("local_addr")?;
        let remote = server.peer_addr().context("peer_addr")?;
        set_keepalive(&server)?;

        let server = if let Some(connector) = tls_connector {
            let server_name = self.server.clone();
            let domain = ServerName::try_from(server_name)
                .or_else(|e| {
                    if tls_insecure {
                        ServerName::try_from("example.com")
                    } else {
                        Err(e)
                    }
                })
                .map_err(|_e| anyhow::anyhow!("invalid upstream address: {}", self.server))?;
            make_buffered_stream(
                connector
                    .connect(domain, server)
                    .await
                    .context("tls connector error")?,
            )
        } else {
            make_buffered_stream(server)
        };

        h11c_connect(server, ctx, local, remote, "inline", |_| async {
            // This should never be called when channel="inline"
            error!("HTTP connector frame callback called unexpectedly - this indicates a bug");
            // Return a dummy FrameIO that will fail immediately
            use crate::common::frames::frames_from_stream;
            let dummy_stream = tokio::io::duplex(1).0;
            frames_from_stream(0, dummy_stream)
        })
        .await?;
        Ok(())
    }
}
