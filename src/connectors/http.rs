use std::{convert::TryFrom, sync::Arc, net::SocketAddr};

use async_trait::async_trait;
use easy_error::{err_msg, Error, ResultExt};
use rustls::pki_types::ServerName<'static>; // Make lifetime explicit for trait
use serde::{Deserialize, Serialize};
// No longer using tokio::net::TcpStream directly for connect
use tracing::trace;

use crate::{
    common::{
        h11c::h11c_connect,
        // set_keepalive, // This is handled by TcpDialer now
        tls::TlsClientConfig,
        dialers::{TcpDialer, TokioTcpDialer, TcpConnectionInfo}, // Import from common
        IoStream, // Import from common
    },
    context::{make_buffered_stream, ContextRef, Feature},
    GlobalState,
};

use super::ConnectorRef;

// --- Testability Trait for TLS Connection ---
#[async_trait]
pub trait TlsStreamConnector: Send + Sync + 'static {
    // Takes a pre-established stream (Box<dyn IoStream>) and upgrades it
    async fn connect_tls(&self, domain: ServerName<'static>, stream: Box<dyn IoStream>) -> Result<Box<dyn IoStream>, Error>;
}

// --- Wrapper for real tokio_rustls::TlsConnector ---
pub struct TokioTlsConnectorWrapper {
    // This will wrap Arc<rustls::ClientConfig> or tokio_rustls::TlsConnector
    // TlsClientConfig from common::tls already holds Arc<rustls::ClientConfig>
    // TlsClientConfig::connector() returns a tokio_rustls::TlsConnector
    // So we can store the TlsClientConfig and get connector from it, or store the connector itself.
    // Storing TlsClientConfig is easier as it's already Arc'd and configured.
    tls_config: Arc<TlsClientConfig>, // Or more directly Arc<tokio_rustls::TlsConnector> if config allows
}

impl TokioTlsConnectorWrapper {
    pub fn new(tls_config: Arc<TlsClientConfig>) -> Self {
        Self { tls_config }
    }
}

#[async_trait]
impl TlsStreamConnector for TokioTlsConnectorWrapper {
    async fn connect_tls(&self, domain: ServerName<'static>, stream: Box<dyn IoStream>) -> Result<Box<dyn IoStream>, Error> {
        let tls_connector = self.tls_config.connector(); // Gets a tokio_rustls::TlsConnector
        let rustls_stream = tls_connector.connect(domain, stream).await // tokio_rustls::TlsConnector takes S: AsyncRead + AsyncWrite + Unpin
            .context("TokioTlsConnectorWrapper: TLS connect error")?;
        Ok(make_buffered_stream(rustls_stream)) // Re-buffer after TLS
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct HttpConnector {
    name: String,
    server: String, // This is the server address (domain or IP)
    port: u16,
    tls_config: Option<Arc<TlsClientConfig>>, // Store Arc for sharing; renamed from tls

    #[serde(skip)]
    tcp_dialer: Arc<dyn TcpDialer>,
    #[serde(skip)]
    tls_connector: Option<Arc<dyn TlsStreamConnector>>, // Option because TLS is optional
}

impl HttpConnector {
    // Custom constructor for tests or programmatic creation
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
    struct TempHttpConnectorConfig {
        name: String,
        server: String,
        port: u16,
        tls: Option<TlsClientConfig>,
    }

    let mut temp_config: TempHttpConnectorConfig = serde_yaml_ng::from_value(value.clone())
        .map_err(|e| Error::new(format!("Failed to parse HttpConnector config: {}",e)))?;

    // Call init on TlsClientConfig if it exists, before Arc-ing it.
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
        tcp_dialer: Arc::new(TokioTcpDialer),
        tls_connector: tls_connector_instance,
    }))
}

#[async_trait]
impl super::Connector for HttpConnector {
    fn name(&self) -> &str {
        self.name.as_str()
    }

    async fn init(&mut self) -> Result<(), Error> {
        // TlsClientConfig init is now handled in from_value before Arc construction.
        // So, this init method for HttpConnector might not need to do anything for TLS anymore.
        // If HttpConnector itself had other fields needing mutable init, they would go here.
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

        // Use TcpDialer. Keepalive is true, local_bind and fwmark are None for typical HTTP proxy.
        let tcp_conn_info = self.tcp_dialer.connect(target_socket_addr, None, true, None).await
            .with_context(|| format!("failed to connect to upstream TCP server: {}", target_socket_addr))?;

        let mut current_stream = tcp_conn_info.stream;

        if let Some(tls_connector_arc) = &self.tls_connector {
            // TLS is enabled
            let server_name_str = self.server.clone(); // server field is domain or IP
            let tls_insecure = self.tls_config.as_ref().map(|c| c.insecure).unwrap_or(false);

            let domain = ServerName::try_from(server_name_str.as_str())
                .or_else(|_e| { // Ignore the error from try_from if insecure, try a default
                    if tls_insecure {
                        ServerName::try_from("example.com").map_err(|_| err_msg("Failed to create default ServerName for insecure TLS"))
                    } else {
                        Err(err_msg(format!("Invalid server name for TLS: {}", server_name_str)))
                    }
                })?;

            current_stream = tls_connector_arc.connect_tls(domain, current_stream).await
                .context("TLS handshake error")?;
        }

        // h11c_connect now takes the (potentially TLS wrapped) stream
        h11c_connect(current_stream, ctx, tcp_conn_info.local_addr, tcp_conn_info.remote_addr, "inline", |_| async {
            // This frame_io_factory is for when h11c itself needs to establish a new data channel (e.g. for WebSockets over HTTP/2)
            // For basic HTTP proxying (CONNECT or direct), this might not be used if the main stream is the data channel.
            // The panic indicates it's not expected to be called for this connector's typical use.
            panic!("h11c frame_io_factory not supported for HttpConnector's usage of h11c_connect")
        })
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::dialers::{TcpDialer, TlsStreamConnector}; // For struct fields
    use crate::common::mocks::connector_mocks::{MockTcpDialer, MockTlsStreamConnector, MockIoStream};
    use crate::config::Contexts as AppContexts;
    use crate::context::TargetAddress;
    use std::sync::atomic::AtomicU32;
    use std::net::Ipv4Addr;


    fn create_mock_global_state_for_http_connector() -> Arc<GlobalState> {
        // Similar to the one in direct.rs tests
        Arc::new(GlobalState {
            contexts: Arc::new(AppContexts::new(1024, Arc::new(AtomicU32::new(0)))),
            rules: Default::default(),
            dns_resolver: Arc::new(crate::dns::create_resolver(None, false).unwrap()),
            geoip_db: Default::default(),
            transports: Default::default(),
            listeners: Default::default(),
            udp_capacity: 0,
            timeouts: Default::default(),
            hostname: "test_http_connector_host".to_string(),
            #[cfg(feature = "dashboard")] web_ui_port: None,
            #[cfg(feature = "dashboard")] web_ui_path: None,
            #[cfg(feature = "api")] api_port: None,
            #[cfg(feature = "api")] external_controller: None,
        })
    }

    #[tokio::test]
    async fn test_http_connector_connect_no_tls() {
        let server_name = "proxy.example.com".to_string();
        let server_port = 8080u16;
        let target_addr: SocketAddr = format!("{}:{}", server_name, server_port).parse().unwrap();
        let mock_tcp_dialer = Arc::new(MockTcpDialer::new());

        // For no-TLS, tls_connector can be None
        let mock_tls_connector: Option<Arc<dyn TlsStreamConnector>> = None;

        let http_connector = HttpConnector::new_with_mocks(
            "test_http_no_tls".to_string(),
            server_name.clone(),
            server_port,
            None, // No TlsClientConfig
            mock_tcp_dialer.clone(),
            mock_tls_connector,
        );
        let connector_arc = Arc::new(http_connector);

        let mock_downstream_stream = MockIoStream::new("downstream_mock_for_h11c");
        let mock_downstream_stream_clone = mock_downstream_stream.clone(); // If MockIoStream is Clone

        let tcp_local_addr: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        mock_tcp_dialer.add_response(Ok(TcpConnectionInfo {
            stream: Box::new(mock_downstream_stream), // This stream is given to h11c_connect
            local_addr: tcp_local_addr,
            remote_addr: target_addr,
        }));

        let mock_state = create_mock_global_state_for_http_connector();
        let ctx = mock_state.contexts.create_context("test_listener_http".to_string(), "1.2.3.4:2222".parse().unwrap()).await;

        // Target for the actual connection being proxied (e.g., what user wants to connect to)
        let final_dest_domain = "final.destination.com";
        let final_dest_port = 80;
        ctx.write().await.set_target(TargetAddress::DomainPort(final_dest_domain.to_string(), final_dest_port));
        ctx.write().await.set_feature(Feature::TcpForward); // Standard TCP forwarding via HTTP proxy

        let result = connector_arc.connect(mock_state.clone(), ctx.clone()).await;
        assert!(result.is_ok(), "HttpConnector connect (no TLS) failed: {:?}", result.err());

        // Check what was written to the mock_downstream_stream by h11c_connect
        // It should be an HTTP CONNECT request
        let written_data = mock_downstream_stream_clone.get_written_data();
        let written_str = String::from_utf8(written_data).unwrap_or_default();

        assert!(written_str.starts_with(&format!("CONNECT {}:{} HTTP/1.1\r\n", final_dest_domain, final_dest_port)), "HTTP CONNECT request line mismatch. Got: {}", written_str);
        assert!(written_str.contains(&format!("\r\nhost: {}:{}\r\n", final_dest_domain, final_dest_port)), "HTTP CONNECT host header mismatch. Got: {}", written_str);

        // h11c_connect also sets up the context stream after successful CONNECT.
        // The stream set on ctx would be the same mock_downstream_stream in this case (after h11c consumes the headers).
        // This test focuses on the connector's role: establishing connection to proxy & initiating h11c_connect.
    }

    #[tokio::test]
    async fn test_http_connector_connect_with_tls() {
        let server_name = "secureproxy.example.com".to_string();
        let server_port = 443u16;
        let proxy_addr_parsed: SocketAddr = format!("{}:{}", server_name, server_port).parse().unwrap();

        let mock_tcp_dialer = Arc::new(MockTcpDialer::new());
        let mock_tls_connector_inner = Arc::new(MockTlsStreamConnector::new()); // Arc for the mock itself

        // Prepare TlsClientConfig for the connector
        // For testing, often insecure = true is fine if we're not testing rustls itself.
        let tls_client_cfg = Arc::new(TlsClientConfig {
            cafile: None,
            capath: None,
            cert: None,
            key: None,
            insecure: true, // Simplifies test setup
            sni: server_name.clone(), // SNI should match server_name
            ..Default::default() // Ensure other fields like alpn are default or explicitly set
        });
        // Note: TlsClientConfig::init() would normally be called; from_value handles this.
        // Here, we assume it's either not critical for mock interaction or handled if TlsClientConfig::connector() needs it.

        let http_connector = HttpConnector::new_with_mocks(
            "test_http_with_tls".to_string(),
            server_name.clone(),
            server_port,
            Some(tls_client_cfg.clone()), // Pass the Arc'd TlsClientConfig
            mock_tcp_dialer.clone(),
            Some(mock_tls_connector_inner.clone()), // Pass the Arc'd mock TlsStreamConnector
        );
        let connector_arc = Arc::new(http_connector);

        // Mocking TCP connection
        let mock_tcp_stream = MockIoStream::new("tcp_to_proxy");
        let mock_tcp_stream_clone_for_tls = mock_tcp_stream.clone(); // Clone for TLS connector to receive
        let tcp_local_addr: SocketAddr = "192.168.1.100:54321".parse().unwrap();
        mock_tcp_dialer.add_response(Ok(TcpConnectionInfo {
            stream: Box::new(mock_tcp_stream),
            local_addr: tcp_local_addr,
            remote_addr: proxy_addr_parsed,
        }));

        // Mocking TLS connection (what TlsStreamConnector returns)
        let mock_tls_upgraded_stream = MockIoStream::new("tls_upgraded_stream");
        let mock_tls_upgraded_stream_clone_for_h11c = mock_tls_upgraded_stream.clone();

        // Configure MockTlsStreamConnector to expect the plain stream and return the "TLS" stream
        mock_tls_connector_inner.add_response(Ok(Box::new(mock_tls_upgraded_stream)));


        let mock_state = create_mock_global_state_for_http_connector();
        let ctx = mock_state.contexts.create_context("test_listener_http_tls".to_string(), "1.2.3.4:3333".parse().unwrap()).await;

        let final_dest_domain = "target.service.com";
        let final_dest_port = 443; // Often TLS for final dest too
        ctx.write().await.set_target(TargetAddress::DomainPort(final_dest_domain.to_string(), final_dest_port));
        ctx.write().await.set_feature(Feature::TcpForward);

        let result = connector_arc.connect(mock_state.clone(), ctx.clone()).await;
        assert!(result.is_ok(), "HttpConnector connect (with TLS) failed: {:?}", result.err());

        // Verify what h11c_connect wrote. It should write to the stream returned by TlsStreamConnector.
        let written_data_on_tls_stream = mock_tls_upgraded_stream_clone_for_h11c.get_written_data();
        let written_str_tls = String::from_utf8(written_data_on_tls_stream).unwrap_or_default();

        assert!(written_str_tls.starts_with(&format!("CONNECT {}:{} HTTP/1.1\r\n", final_dest_domain, final_dest_port)), "HTTP CONNECT request line mismatch on TLS stream. Got: {}", written_str_tls);
        assert!(written_str_tls.contains(&format!("\r\nhost: {}:{}\r\n", final_dest_domain, final_dest_port)), "HTTP CONNECT host header mismatch on TLS stream. Got: {}", written_str_tls);

        // Optionally, verify that TlsStreamConnector was called with the correct domain and plain stream.
        // This requires MockTlsStreamConnector to store its inputs.
        // For now, the correct data on the final stream implies it was likely chained correctly.
    }
}
