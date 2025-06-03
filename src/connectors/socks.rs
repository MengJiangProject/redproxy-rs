use std::{convert::TryFrom, net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use easy_error::{bail, err_msg, Error, ResultExt};
use rustls::pki_types::ServerName<'static>; // Ensure 'static lifetime
use serde::{Deserialize, Serialize};
// No longer using tokio::net::TcpStream directly for connect
use tracing::trace;

use crate::{
    common::{
        into_unspecified,
        // set_keepalive, // Handled by TcpDialer
        socks::{
            frames::setup_udp_session, PasswordAuth, SocksRequest, SocksResponse,
            SOCKS_CMD_CONNECT, SOCKS_CMD_UDP_ASSOCIATE, SOCKS_REPLY_OK,
        },
        tls::TlsClientConfig,
        dialers::{TcpDialer, TokioTcpDialer, TcpConnectionInfo, TlsStreamConnector, TokioTlsConnectorWrapper}, // Import from common
        IoStream, // Import from common
    },
    context::{make_buffered_stream, ContextRef, Feature},
    GlobalState,
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
    auth_data: Option<SocksAuthData>,
    tls_config: Option<Arc<TlsClientConfig>>,

    #[serde(skip)]
    tcp_dialer: Arc<dyn TcpDialer>,
    #[serde(skip)]
    tls_connector: Option<Arc<dyn TlsStreamConnector>>,
}

impl SocksConnector {
    #[cfg(test)]
    pub fn new_with_mocks(
        name: String,
        server: String,
        port: u16,
        version: u8,
        auth_data: Option<SocksAuthData>,
        tls_config: Option<Arc<TlsClientConfig>>,
        tcp_dialer: Arc<dyn TcpDialer>,
        tls_connector: Option<Arc<dyn TlsStreamConnector>>,
    ) -> Self {
        Self {
            name,
            server,
            port,
            version,
            auth_data,
            tls_config,
            tcp_dialer,
            tls_connector,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SocksAuthData {
    username: String,
    password: String,
}

fn default_socks_version() -> u8 {
    5
}

pub fn from_value(value: &serde_yaml_ng::Value) -> Result<ConnectorRef, Error> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct TempSocksConnectorConfig { // For deserialization
        name: String,
        server: String,
        port: u16,
        #[serde(default = "default_socks_version")]
        version: u8,
        auth: Option<SocksAuthData>, // Original field name from YAML
        tls: Option<TlsClientConfig>,
    }

    let mut temp_config: TempSocksConnectorConfig = serde_yaml_ng::from_value(value.clone())
        .map_err(|e| Error::new(format!("Failed to parse SocksConnector config: {}", e)))?;

    if let Some(tls_cfg) = temp_config.tls.as_mut() {
        tls_cfg.init().context("Failed to initialize TlsClientConfig for SocksConnector")?;
    }

    let tls_arc_config = temp_config.tls.map(Arc::new);
    let tls_connector_instance = tls_arc_config.as_ref().map(|conf| Arc::new(TokioTlsConnectorWrapper::new(conf.clone())) as Arc<dyn TlsStreamConnector>);

    Ok(Box::new(SocksConnector {
        name: temp_config.name,
        server: temp_config.server,
        port: temp_config.port,
        version: temp_config.version,
        auth_data: temp_config.auth,
        tls_config: tls_arc_config,
        tcp_dialer: Arc::new(TokioTcpDialer),
        tls_connector: tls_connector_instance,
    }))
}

#[async_trait]
impl super::Connector for SocksConnector {
    fn name(&self) -> &str {
        self.name.as_str()
    }

    fn features(&self) -> &[Feature] {
        &[Feature::TcpForward, Feature::UdpForward, Feature::UdpBind]
    }

    async fn init(&mut self) -> Result<(), Error> {
        // TlsClientConfig::init is now called in from_value
        if self.version != 4 && self.version != 5 {
            bail!("illegal socks version {}", self.version);
        }
        Ok(())
    }

    async fn connect(
        self: Arc<Self>,
        _state: Arc<GlobalState>,
        ctx: ContextRef,
    ) -> Result<(), Error> {
        let server_addr_str = self.server.as_str();
        let server_port = self.port;
        let target_socket_addr: SocketAddr = format!("{}:{}", server_addr_str, server_port)
            .parse()
            .with_context(|| format!("Invalid server address format: {}:{}", server_addr_str, server_port))?;

        trace!(
            "{} connecting to SOCKS server {}",
            self.name,
            target_socket_addr
        );

        // Use TcpDialer. Keepalive is true.
        let tcp_conn_info = self.tcp_dialer.connect(target_socket_addr, None, true, None).await
            .with_context(|| format!("failed to connect to upstream SOCKS server: {}", target_socket_addr))?;

        let mut current_stream = tcp_conn_info.stream;

        if let Some(tls_connector_arc) = &self.tls_connector {
            let server_name_str = self.server.clone();
            let tls_insecure = self.tls_config.as_ref().map(|c| c.insecure).unwrap_or(false);
            let domain = ServerName::try_from(server_name_str.as_str())
                 .or_else(|_e| {
                    if tls_insecure {
                        ServerName::try_from("example.com").map_err(|_| err_msg("Failed to create default ServerName for insecure TLS"))
                    } else {
                        Err(err_msg(format!("Invalid server name for TLS: {}", server_name_str)))
                    }
                })?;
            current_stream = tls_connector_arc.connect_tls(domain, current_stream).await
                .context("SOCKS TLS handshake error")?;
        }

        let feature = ctx.read().await.feature();
        let cmd = match feature {
            Feature::UdpBind | Feature::UdpForward => SOCKS_CMD_UDP_ASSOCIATE,
            Feature::TcpForward => SOCKS_CMD_CONNECT,
            _ => bail!("SOCKS connector: unknown supported feature: {:?}", feature),
        };

        let auth_credentials = self
            .auth_data // Use the renamed field
            .as_ref() // Use as_ref to avoid consuming, then clone inner parts
            .map(|auth_item| (auth_item.username.clone(), auth_item.password.clone()));

        let req = SocksRequest {
            version: self.version,
            cmd,
            target: ctx.read().await.target(),
            auth: auth_credentials, // Use the cloned credentials
        };

        req.write_to(&mut current_stream, PasswordAuth::optional()).await?;
        let resp = SocksResponse::read_from(&mut current_stream).await?;

        if resp.cmd != SOCKS_REPLY_OK {
            bail!("SOCKS upstream server failure: cmd response {:?}", resp.cmd);
        }

        ctx.write()
            .await
            .set_server_stream(current_stream)
            .set_local_addr(tcp_conn_info.local_addr)
            .set_server_addr(tcp_conn_info.remote_addr); // This is the SOCKS server addr

        if feature == Feature::UdpBind || feature == Feature::UdpForward {
            let mut udp_bind_addr = resp
                .target
                .as_socket_addr()
                .ok_or_else(|| err_msg("bad bind address for SOCKS UDP associate"))?; // Clarified error

            // If SOCKS server returns 0.0.0.0, use the SOCKS server's actual IP
            // tcp_conn_info.remote_addr is the SOCKS server's address
            if udp_bind_addr.ip().is_unspecified() {
                udp_bind_addr.set_ip(tcp_conn_info.remote_addr.ip());
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
