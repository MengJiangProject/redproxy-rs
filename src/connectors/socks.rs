use std::{convert::TryFrom, net::SocketAddr, sync::Arc};

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use rustls::pki_types::ServerName;
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tracing::trace;

use crate::{
    GlobalState,
    common::{
        into_unspecified, set_keepalive,
        socks::{
            PasswordAuth, SOCKS_CMD_CONNECT, SOCKS_CMD_UDP_ASSOCIATE, SOCKS_REPLY_OK, SocksRequest,
            SocksResponse, frames::setup_udp_session,
        },
        tls::TlsClientConfig,
    },
    context::{ContextRef, Feature, make_buffered_stream},
};

use super::ConnectorRef;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SocksConnector {
    name: String,
    server: String,
    port: u16,
    #[serde(default = "default_socks_version")]
    version: u8,
    auth: Option<SocksAuthData>,
    tls: Option<TlsClientConfig>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SocksAuthData {
    username: String,
    password: String,
}

fn default_socks_version() -> u8 {
    5
}

pub fn from_value(value: &serde_yaml_ng::Value) -> Result<ConnectorRef> {
    let ret: SocksConnector = serde_yaml_ng::from_value(value.clone()).context("parse config")?;
    Ok(Box::new(ret))
}

#[async_trait]
impl super::Connector for SocksConnector {
    fn name(&self) -> &str {
        self.name.as_str()
    }

    fn features(&self) -> &[Feature] {
        &[Feature::TcpForward, Feature::UdpForward, Feature::UdpBind]
    }

    async fn init(&mut self) -> Result<()> {
        if let Some(Err(e)) = self.tls.as_mut().map(TlsClientConfig::init) {
            return Err(e);
        }
        if self.version != 4 && self.version != 5 {
            bail!("illegal socks version {}", self.version);
        }
        Ok(())
    }

    async fn connect(self: Arc<Self>, _state: Arc<GlobalState>, ctx: ContextRef) -> Result<()> {
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

        let mut server = if let Some(connector) = tls_connector {
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
        let feature = ctx.read().await.feature();
        let cmd = match feature {
            Feature::UdpBind | Feature::UdpForward => SOCKS_CMD_UDP_ASSOCIATE,
            Feature::TcpForward => SOCKS_CMD_CONNECT,
            _ => bail!("unknown supported feature: {:?}", feature),
        };
        let auth = self
            .auth
            .to_owned()
            .map(|auth| (auth.username, auth.password));
        let req = SocksRequest {
            version: self.version,
            cmd,
            target: ctx.read().await.target(),
            auth,
        };
        req.write_to(&mut server, PasswordAuth::optional()).await?;
        let resp = SocksResponse::read_from(&mut server).await?;
        if resp.cmd != SOCKS_REPLY_OK {
            bail!("upstream server failure: {:?}", resp.cmd);
        }
        ctx.write()
            .await
            .set_server_stream(server)
            .set_local_addr(local)
            .set_server_addr(remote);
        if feature == Feature::UdpBind || feature == Feature::UdpForward {
            let mut udp_remote = resp
                .target
                .as_socket_addr()
                .ok_or_else(|| anyhow::anyhow!("bad bind address"))?;
            if udp_remote.ip().is_unspecified() {
                udp_remote = SocketAddr::new(remote.ip(), udp_remote.port());
            }
            let udp_local = into_unspecified(remote);
            let (_, frames) = setup_udp_session(udp_local, Some(udp_remote))
                .await
                .context("setup_udp_session")?;
            ctx.write().await.set_server_frames(frames);
        }
        Ok(())
    }
}
