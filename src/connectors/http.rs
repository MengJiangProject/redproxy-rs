use std::{convert::TryFrom, sync::Arc, net::SocketAddr};

use async_trait::async_trait;
use easy_error::{err_msg, Error, ResultExt};
use rustls::pki_types::ServerName;
use serde::{Deserialize, Serialize};
use tracing::trace;

use crate::{
    common::{
        h11c::h11c_connect,
        tls::TlsClientConfig,
        dialers::{TcpDialer, TokioTcpDialer, TcpConnectionInfo, TlsStreamConnector, TokioTlsConnectorWrapper},
    },
    context::{ContextRef, Feature, IOBufStream},
    GlobalState,
};

use super::ConnectorRef;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct HttpConnector {
    name: String,
    server: String,
    port: u16,
    tls_config: Option<Arc<TlsClientConfig>>,

    #[serde(skip, default = "default_tcp_dialer")] // Added default
    tcp_dialer: Arc<dyn TcpDialer>,
    #[serde(skip)] // tls_connector is Option, so it defaults to None if not set by from_value
    tls_connector: Option<Arc<dyn TlsStreamConnector>>,
}

// Default functions for skipped fields in Deserialize
fn default_tcp_dialer() -> Arc<dyn TcpDialer> { Arc::new(TokioTcpDialer) }

impl HttpConnector {
    #[cfg(test)]
    pub fn new_with_mocks(
        name: String,
        server: String,
        port: u16,
        tls_config: Option<Arc<TlsClientConfig>>,
        tcp_dialer: Arc<dyn TcpDialer>,
        tls_connector: Option<Arc<dyn TlsStreamConnector>>,
    ) -> Self {
        Self {
            name,
            server,
            port,
            tls_config,
            tcp_dialer,
            tls_connector,
        }
    }
}


pub fn from_value(value: &serde_yaml_ng::Value) -> Result<ConnectorRef, Error> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct TempHttpConnectorConfig { // Temporary struct for deserialization for fields present in YAML
        name: String,
        server: String,
        port: u16,
        tls: Option<TlsClientConfig>,
    }

    let mut temp_config: TempHttpConnectorConfig = serde_yaml_ng::from_value(value.clone())
        .map_err(|e| err_msg(format!("Failed to parse HttpConnector config: {}", e)))?; // Simplified err_msg

    if let Some(tls_cfg) = temp_config.tls.as_mut() {
        tls_cfg.init().context("Failed to initialize TlsClientConfig for HttpConnector")?;
    }

    let tls_arc_config = temp_config.tls.map(Arc::new);
    let tls_connector_instance = tls_arc_config.as_ref().map(|conf| Arc::new(TokioTlsConnectorWrapper::new(conf.clone())) as Arc<dyn TlsStreamConnector>);

    Ok(Box::new(HttpConnector {
        name: temp_config.name,
        server: temp_config.server,
        port: temp_config.port,
        tls_config: tls_arc_config,
        tcp_dialer: Arc::new(TokioTcpDialer), // Initialize here
        tls_connector: tls_connector_instance, // Initialize here
    }))
}

#[async_trait]
impl super::Connector for HttpConnector {
    fn name(&self) -> &str {
        self.name.as_str()
    }

    async fn init(&mut self) -> Result<(), Error> {
        // If TlsClientConfig was field on HttpConnector directly (not Arc), init would be here.
        // But it's Arc, and from_value initializes it before Arc-ing.
        // If tcp_dialer or tls_connector needed async init, it would go here.
        Ok(())
    }


    fn features(&self) -> &[Feature] {
        &[Feature::TcpForward, Feature::UdpForward, Feature::UdpBind] // Assuming HttpConnector can proxy these
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
            "{} connecting to server {}",
            self.name,
            target_socket_addr
        );

        let tcp_conn_info = self.tcp_dialer.connect(target_socket_addr, None, true, None).await
            .with_context(|| format!("failed to connect to upstream TCP server: {}", target_socket_addr))?;

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
                .context("TLS handshake error")?;
        }

        h11c_connect(current_stream, ctx, tcp_conn_info.local_addr, tcp_conn_info.remote_addr, "inline", |_| async {
            panic!("h11c frame_io_factory not supported for HttpConnector's usage of h11c_connect")
        })
        .await?;
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
    use crate::connectors::Connector; // Import Connector trait

    fn create_mock_global_state_for_http_connector() -> Arc<GlobalState> {
        Arc::new(GlobalState {
            contexts: Arc::new(AppContexts::new(1024, Arc::new(AtomicU32::new(0)))),
            rules: Default::default(),
            // These fields are based on the actual GlobalState struct definition.
            // If dns_resolver, etc., are not direct fields, this needs adjustment or they should be mocked differently.
            connectors: Default::default(),
            metrics: Default::default(),
            io_params: Default::default(),
        })
    }

    #[tokio::test]
    async fn test_http_connector_connect_no_tls() {
        let server_name = "proxy.example.com".to_string();
        let server_port = 8080u16;
        let target_addr: SocketAddr = format!("{}:{}", server_name, server_port).parse().unwrap();
        let mock_tcp_dialer = Arc::new(MockTcpDialer::new());

        let mock_tls_connector: Option<Arc<dyn TlsStreamConnector>> = None;

        let http_connector = HttpConnector::new_with_mocks(
            "test_http_no_tls".to_string(),
            server_name.clone(),
            server_port,
            None,
            mock_tcp_dialer.clone(),
            mock_tls_connector,
        );
        let connector_arc: Arc<dyn Connector> = Arc::new(http_connector); // Use Arc<dyn Connector>

        let mock_raw_downstream_stream = MockIoStream::new("downstream_mock_for_h11c");
        let mock_raw_downstream_stream_clone = mock_raw_downstream_stream.clone();

        mock_tcp_dialer.add_response(Ok(TcpConnectionInfo {
            stream: crate::context::make_buffered_stream(Box::new(mock_raw_downstream_stream)),
            local_addr: "192.168.1.100:12345".parse().unwrap(),
            remote_addr: target_addr,
        }));

        let mock_state = create_mock_global_state_for_http_connector();
        let ctx = mock_state.contexts.create_context("test_listener_http".to_string(), "1.2.3.4:2222".parse().unwrap()).await;

        let final_dest_domain = "final.destination.com";
        let final_dest_port = 80;
        ctx.write().await.set_target(TargetAddress::DomainPort(final_dest_domain.to_string(), final_dest_port));
        ctx.write().await.set_feature(Feature::TcpForward);

        let result = connector_arc.connect(mock_state.clone(), ctx.clone()).await;
        assert!(result.is_ok(), "HttpConnector connect (no TLS) failed: {:?}", result.err());

        let written_data = mock_raw_downstream_stream_clone.get_written_data();
        let written_str = String::from_utf8(written_data).unwrap_or_default();

        assert!(written_str.starts_with(&format!("CONNECT {}:{} HTTP/1.1\r\n", final_dest_domain, final_dest_port)), "HTTP CONNECT request line mismatch. Got: {}", written_str);
        assert!(written_str.contains(&format!("\r\nhost: {}:{}\r\n", final_dest_domain, final_dest_port)), "HTTP CONNECT host header mismatch. Got: {}", written_str);
    }

    #[tokio::test]
    async fn test_http_connector_connect_with_tls() {
        let server_name = "secureproxy.example.com".to_string();
        let server_port = 443u16;
        let proxy_addr_parsed: SocketAddr = format!("{}:{}", server_name, server_port).parse().unwrap();

        let mock_tcp_dialer = Arc::new(MockTcpDialer::new());
        let mock_tls_connector_inner = Arc::new(MockTlsStreamConnector::new());

        let tls_client_cfg = Arc::new(TlsClientConfig {
            insecure: true,
            sni: Some(server_name.clone()),
            ..Default::default()
        });

        let http_connector = HttpConnector::new_with_mocks(
            "test_http_with_tls".to_string(),
            server_name.clone(),
            server_port,
            Some(tls_client_cfg.clone()),
            mock_tcp_dialer.clone(),
            Some(mock_tls_connector_inner.clone()),
        );
        let connector_arc: Arc<dyn Connector> = Arc::new(http_connector); // Use Arc<dyn Connector>

        let mock_tcp_raw_stream = MockIoStream::new("tcp_to_proxy_raw");
        mock_tcp_dialer.add_response(Ok(TcpConnectionInfo {
            stream: crate::context::make_buffered_stream(Box::new(mock_tcp_raw_stream)),
            local_addr: "192.168.1.100:54321".parse().unwrap(),
            remote_addr: proxy_addr_parsed,
        }));

        let mock_tls_upgraded_raw_stream = MockIoStream::new("tls_upgraded_raw_stream");
        let mock_tls_upgraded_raw_stream_clone = mock_tls_upgraded_raw_stream.clone();
        mock_tls_connector_inner.add_response(Ok(crate::context::make_buffered_stream(Box::new(mock_tls_upgraded_raw_stream))));


        let mock_state = create_mock_global_state_for_http_connector();
        let ctx = mock_state.contexts.create_context("test_listener_http_tls".to_string(), "1.2.3.4:3333".parse().unwrap()).await;

        let final_dest_domain = "target.service.com";
        let final_dest_port = 443;
        ctx.write().await.set_target(TargetAddress::DomainPort(final_dest_domain.to_string(), final_dest_port));
        ctx.write().await.set_feature(Feature::TcpForward);

        let result = connector_arc.connect(mock_state.clone(), ctx.clone()).await;
        assert!(result.is_ok(), "HttpConnector connect (with TLS) failed: {:?}", result.err());

        let written_data_on_tls_stream = mock_tls_upgraded_raw_stream_clone.get_written_data();
        let written_str_tls = String::from_utf8(written_data_on_tls_stream).unwrap_or_default();

        assert!(written_str_tls.starts_with(&format!("CONNECT {}:{} HTTP/1.1\r\n", final_dest_domain, final_dest_port)), "HTTP CONNECT request line mismatch on TLS stream. Got: {}", written_str_tls);
        assert!(written_str_tls.contains(&format!("\r\nhost: {}:{}\r\n", final_dest_domain, final_dest_port)), "HTTP CONNECT host header mismatch on TLS stream. Got: {}", written_str_tls);
    }
}
