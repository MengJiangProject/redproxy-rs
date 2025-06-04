use std::{convert::TryFrom, net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use easy_error::{bail, err_msg, Error, ResultExt};
use rustls::pki_types::ServerName;
use serde::{Deserialize, Serialize};
use tracing::trace;

use crate::{
    common::{
        into_unspecified,
        socks::{
            frames::setup_udp_session, PasswordAuth, SocksRequest, SocksResponse,
            SOCKS_CMD_CONNECT, SOCKS_CMD_UDP_ASSOCIATE, SOCKS_REPLY_OK, SOCKS_AUTH_NONE,
            SOCKS_ATYP_DOMAIN, SOCKS_ATYP_INET4, SOCKS_ATYP_INET6, SOCKS_AUTH_USRPWD, SOCKS_CMD_BIND
        },
        tls::TlsClientConfig,
        dialers::{TcpDialer, TokioTcpDialer, TlsStreamConnector, TokioTlsConnectorWrapper, TcpConnectionInfo},
    },
    context::{ContextRef, Feature, IOBufStream},
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

    #[serde(skip, default = "default_tcp_dialer_socks")]
    tcp_dialer: Arc<dyn TcpDialer>,
    #[serde(skip)]
    tls_connector: Option<Arc<dyn TlsStreamConnector>>,
}

fn default_tcp_dialer_socks() -> Arc<dyn TcpDialer> { Arc::new(TokioTcpDialer) }


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
    struct TempSocksConnectorConfig {
        name: String,
        server: String,
        port: u16,
        #[serde(default = "default_socks_version")]
        version: u8,
        auth: Option<SocksAuthData>,
        tls: Option<TlsClientConfig>,
    }

    let mut temp_config: TempSocksConnectorConfig = serde_yaml_ng::from_value(value.clone())
        .map_err(|e| err_msg(format!("Failed to parse SocksConnector config: {}", e)))?; // Simplified err_msg

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
        tcp_dialer: Arc::new(TokioTcpDialer), // Initialize here
        tls_connector: tls_connector_instance, // Initialize here
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

        let tcp_conn_info = self.tcp_dialer.connect(target_socket_addr, None, true, None).await
            .with_context(|| format!("failed to connect to upstream SOCKS server: {}", target_socket_addr))?;

        let mut current_stream: IOBufStream = tcp_conn_info.stream;

        if let Some(tls_connector_arc) = &self.tls_connector {
            let server_name_str = self.server.clone();
            let tls_insecure = self.tls_config.as_ref().map(|c| c.insecure).unwrap_or(false);
            let domain = ServerName::try_from(server_name_str.as_str())
                 .or_else(|e_domain| {
                    if tls_insecure {
                        ServerName::try_from("example.com").map_err(|e_default| err_msg(format!("Failed to create default ServerName for insecure TLS: {}, original error: {}", e_default, e_domain)))
                    } else {
                        Err(err_msg(format!("Invalid server name for TLS: {}, error: {}", server_name_str, e_domain)))
                    }
                })?;
            current_stream = tls_connector_arc.connect_tls(domain, current_stream).await
                .context("SOCKS TLS handshake error")?;
        }

        let feature = ctx.read().await.props().request_feature; // Use props()
        let cmd = match feature {
            Feature::UdpBind | Feature::UdpForward => SOCKS_CMD_UDP_ASSOCIATE,
            Feature::TcpForward => SOCKS_CMD_CONNECT,
            _ => bail!("SOCKS connector: unknown supported feature: {:?}", feature),
        };

        let auth_credentials = self
            .auth_data
            .as_ref()
            .map(|auth_item| (auth_item.username.clone(), auth_item.password.clone()));

        let req = SocksRequest {
            version: self.version,
            cmd,
            target: ctx.read().await.props().target.clone(), // Use props()
            auth: auth_credentials,
        };

        req.write_to(&mut current_stream, PasswordAuth::optional()).await?;
        let resp = SocksResponse::read_from(&mut current_stream).await?;

        if resp.cmd != SOCKS_REPLY_OK {
            bail!("SOCKS upstream server failure: cmd response {:?}", resp.cmd);
        }

        let mut ctx_write = ctx.write().await;
        ctx_write.set_server_stream(current_stream);
        ctx_write.set_local_addr(tcp_conn_info.local_addr);
        ctx_write.set_server_addr(tcp_conn_info.remote_addr);

        if feature == Feature::UdpBind || feature == Feature::UdpForward {
            let mut udp_bind_addr = resp
                .target
                .as_socket_addr()
                .ok_or_else(|| err_msg("bad bind address for SOCKS UDP associate"))?;

            if udp_bind_addr.ip().is_unspecified() {
                udp_bind_addr.set_ip(tcp_conn_info.remote_addr.ip());
            }
            let udp_session_local_addr = into_unspecified(tcp_conn_info.remote_addr);
            let (_, frames) = setup_udp_session::<tokio::net::UdpSocket>(udp_session_local_addr, Some(udp_bind_addr))
                .await
                .context("setup_udp_session for SOCKS connector")?;
            ctx_write.set_server_frames(frames); // Use existing ctx_write
        }
        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::mocks::connector_mocks::{MockTcpDialer, MockTlsStreamConnector, MockIoStream};
    use crate::config::context::Contexts as AppContexts;
    use crate::context::TargetAddress;
    use std::sync::atomic::AtomicU32;
    use bytes::{BytesMut, BufMut, Bytes};
    use std::net::Ipv4Addr;
    use crate::connectors::Connector; // Import Connector trait

    fn create_mock_global_state_for_socks_connector() -> Arc<GlobalState> {
        Arc::new(GlobalState {
            contexts: Arc::new(AppContexts::new(1024, Arc::new(AtomicU32::new(0)))),
            rules: Default::default(),
            connectors: Default::default(),
            metrics: Default::default(),
            io_params: Default::default(),
        })
    }

    #[tokio::test]
    async fn test_socks_connector_connect_tcp_no_tls_no_auth() {
        let server_name = "socks-proxy.example.com".to_string();
        let server_port = 1080u16;
        let proxy_addr_parsed: SocketAddr = format!("{}:{}", server_name, server_port).parse().unwrap();

        let mock_tcp_dialer = Arc::new(MockTcpDialer::new());
        let mock_tls_connector: Option<Arc<dyn TlsStreamConnector>> = None;

        let socks_connector = SocksConnector::new_with_mocks(
            "test_socks_no_tls_no_auth".to_string(),
            server_name.clone(),
            server_port,
            5,
            None,
            None,
            mock_tcp_dialer.clone(),
            mock_tls_connector,
        );
        let connector_arc: Arc<dyn Connector> = Arc::new(socks_connector); // Use Arc<dyn Connector>

        let mock_server_raw_stream = MockIoStream::new("rw_to_socks_server_raw");
        let mock_server_raw_stream_clone = mock_server_raw_stream.clone();

        let tcp_local_addr: SocketAddr = "192.168.1.100:34567".parse().unwrap();
        mock_tcp_dialer.add_response(Ok(TcpConnectionInfo {
            stream: crate::context::make_buffered_stream(Box::new(mock_server_raw_stream)),
            local_addr: tcp_local_addr,
            remote_addr: proxy_addr_parsed,
        }));

        let mut server_auth_response = BytesMut::new();
        server_auth_response.put_u8(5);
        server_auth_response.put_u8(SOCKS_AUTH_NONE);
        mock_server_raw_stream_clone.add_read_data(server_auth_response.freeze());

        let mut server_connect_response = BytesMut::new();
        server_connect_response.put_u8(5);
        server_connect_response.put_u8(SOCKS_REPLY_OK);
        server_connect_response.put_u8(0);
        server_connect_response.put_u8(SOCKS_ATYP_INET4);
        server_connect_response.put_slice(&[10,0,0,1]);
        server_connect_response.put_u16(1080);
        mock_server_raw_stream_clone.add_read_data(server_connect_response.freeze());

        let mock_state = create_mock_global_state_for_socks_connector();
        let ctx = mock_state.contexts.create_context("test_listener_socks".to_string(), "1.2.3.4:4444".parse().unwrap()).await;

        let final_dest_domain = "target.service.com";
        let final_dest_port = 80;
        ctx.write().await.set_target(TargetAddress::DomainPort(final_dest_domain.to_string(), final_dest_port));
        ctx.write().await.set_feature(Feature::TcpForward);

        let result = connector_arc.connect(mock_state.clone(), ctx.clone()).await;
        assert!(result.is_ok(), "SocksConnector connect failed: {:?}", result.err());

        let written_data = mock_server_raw_stream_clone.get_written_data();

        assert!(written_data.len() >= 3);
        assert_eq!(&written_data[0..3], &[5, 1, 0], "SOCKS auth request mismatch");

        let domain_bytes = final_dest_domain.as_bytes();
        assert!(written_data.len() >= 3 + 4 + 1 + domain_bytes.len() + 2);
        assert_eq!(&written_data[3..7], &[5, SOCKS_CMD_CONNECT, 0, SOCKS_ATYP_DOMAIN], "SOCKS CONNECT cmd header mismatch");
        assert_eq!(written_data[7], domain_bytes.len() as u8, "SOCKS domain length mismatch");
        assert_eq!(&written_data[8..8+domain_bytes.len()], domain_bytes, "SOCKS domain mismatch");
        let port_offset = 8 + domain_bytes.len();
        assert_eq!(u16::from_be_bytes([written_data[port_offset], written_data[port_offset+1]]), final_dest_port, "SOCKS port mismatch");

        let ctx_read = ctx.read().await;
        assert!(ctx_read.server_stream_is_some(), "Server stream not set in context");
        assert_eq!(ctx_read.props().local_addr, tcp_local_addr);
        assert_eq!(ctx_read.props().server_addr, proxy_addr_parsed);
    }
}
