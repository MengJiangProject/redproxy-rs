use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tracing::{error, trace};

use crate::{
    common::{
        http_proxy::{http_forward_proxy_connect, HttpProxyContextExt},
        socket_ops::{RealSocketOps, SocketOps},
        tls::TlsClientConfig,
    },
    context::{ContextRef, Feature, make_buffered_stream},
};

use super::ConnectorRef;

fn default_rfc9298_uri_template() -> String {
    "/.well-known/masque/udp/{host}/{port}/".to_string()
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UdpProtocolConfig {
    #[serde(default = "default_udp_protocol_name", rename = "udpProtocol")]
    protocol: String,
    #[serde(default = "default_rfc9298_uri_template", rename = "rfc9298UriTemplate")]
    rfc9298_uri_template: String,
}

fn default_udp_protocol_name() -> String {
    "custom".to_string()
}

impl Default for UdpProtocolConfig {
    fn default() -> Self {
        UdpProtocolConfig {
            protocol: default_udp_protocol_name(),
            rfc9298_uri_template: default_rfc9298_uri_template(),
        }
    }
}

impl UdpProtocolConfig {
    pub fn protocol_name(&self) -> &str {
        &self.protocol
    }

    pub fn rfc9298_uri_template(&self) -> Option<&str> {
        if self.protocol == "rfc9298" {
            Some(&self.rfc9298_uri_template)
        } else {
            None
        }
    }

    /// Validate that the protocol configuration is valid
    pub fn validate(&self) -> Result<(), String> {
        match self.protocol.as_str() {
            "custom" | "rfc9298" => Ok(()),
            other => Err(format!("Invalid UDP protocol: '{}'. Must be 'custom' or 'rfc9298'", other)),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct HttpAuthData {
    username: String,
    password: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct HttpConnectorConfig {
    name: String,
    server: String,
    port: u16,
    tls: Option<TlsClientConfig>,
    #[serde(default)]
    force_connect: bool,
    auth: Option<HttpAuthData>,
    #[serde(flatten, default)]
    udp_protocol_config: UdpProtocolConfig,
}

#[derive(Debug, Clone, Serialize)]
pub struct HttpConnector<S = RealSocketOps>
where
    S: SocketOps,
{
    #[serde(flatten)]
    config: HttpConnectorConfig,
    #[serde(skip)]
    socket_ops: Arc<S>,
}

impl<S: SocketOps> Deref for HttpConnector<S> {
    type Target = HttpConnectorConfig;
    fn deref(&self) -> &Self::Target {
        &self.config
    }
}

impl<S: SocketOps> DerefMut for HttpConnector<S> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.config
    }
}

// Production constructor (zero-cost)
impl HttpConnector<RealSocketOps> {
    pub fn new(config: HttpConnectorConfig) -> Self {
        Self {
            config,
            socket_ops: Arc::new(RealSocketOps),
        }
    }
}

// Generic constructor for testing
#[cfg(test)]
impl<S: SocketOps> HttpConnector<S> {
    pub fn with_socket_ops(config: HttpConnectorConfig, socket_ops: Arc<S>) -> Self {
        Self { config, socket_ops }
    }
}

pub fn from_value(value: &serde_yaml_ng::Value) -> Result<ConnectorRef> {
    let config: HttpConnectorConfig =
        serde_yaml_ng::from_value(value.clone()).context("parse config")?;
    let ret = HttpConnector::new(config);
    Ok(Box::new(ret))
}

#[async_trait]
impl<S: SocketOps + Send + Sync + 'static> super::Connector for HttpConnector<S> {
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
        trace!(
            "{} connecting to server {}:{}",
            self.name, self.server, self.port
        );

        let addrs = self.socket_ops.resolve(&self.server).await?;
        let server_addr = addrs
            .first()
            .ok_or_else(|| anyhow::anyhow!("no address found for {}", self.server))?;
        let server_addr = std::net::SocketAddr::new(*server_addr, self.port);

        let (mut server_stream, local, remote) = self
            .socket_ops
            .tcp_connect(server_addr, None)
            .await
            .context("TCP connection failed")?;

        if let Some(tls_config) = &self.tls {
            server_stream = self
                .socket_ops
                .tls_handshake_client(server_stream, &self.server, tls_config)
                .await
                .context("TLS handshake failed")?;
        }

        self.socket_ops
            .set_keepalive(server_stream.as_ref(), true)
            .await?;
        let server = make_buffered_stream(server_stream);

        // Set proxy configuration in context
        {
            let mut ctx_write = ctx.write().await;
            ctx_write
                .set_local_addr(local)
                .set_server_addr(remote)
                .set_proxy_frame_channel("inline")
                .set_proxy_force_connect(self.force_connect)
                .set_proxy_udp_protocol(self.udp_protocol_config.protocol_name());
            
            if let Some(template) = self.udp_protocol_config.rfc9298_uri_template() {
                ctx_write.set_proxy_rfc9298_uri_template(template);
            }
            
            // Set auth in context if available
            if let Some(auth_data) = &self.auth {
                ctx_write
                    .set_extra("proxy_auth_username", &auth_data.username)
                    .set_extra("proxy_auth_password", &auth_data.password);
            }
        }
        http_forward_proxy_connect(
            server,
            ctx,
            |_| async {
                // This should never be called when channel="inline"
                error!("HTTP connector frame callback called unexpectedly - this indicates a bug");
                // Return a dummy FrameIO that will fail immediately
                use crate::common::frames::frames_from_stream;
                let dummy_stream = tokio::io::duplex(1).0;
                frames_from_stream(0, dummy_stream)
            },
        )
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        common::socket_ops::{
            SocketOps,
            test_utils::{MockSocketOps, StreamScript},
        },
        connectors::Connector,
        context::{ContextManager, Feature, TargetAddress},
    };
    use std::net::SocketAddr;
    use tokio_test::io::Mock;

    // HTTP CONNECT protocol stream builder for HttpConnector tests
    fn http_connect_stream(target_host: &str, target_port: u16) -> Mock {
        StreamScript::new()
            .write(
                format!(
                    "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
                    target_host, target_port, target_host, target_port
                )
                .as_bytes(),
            )
            .read(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .build()
    }

    fn create_test_connector<S: SocketOps>(
        server: String,
        port: u16,
        tls: Option<TlsClientConfig>,
        force_connect: bool,
        socket_ops: Arc<S>,
    ) -> HttpConnector<S> {
        HttpConnector::with_socket_ops(
            HttpConnectorConfig {
                name: "test_http".to_string(),
                server,
                port,
                tls,
                force_connect,
                auth: None,
                udp_protocol_config: UdpProtocolConfig::default(),
            },
            socket_ops,
        )
    }

    async fn create_test_context(target: TargetAddress, feature: Feature) -> ContextRef {
        let manager = Arc::new(ContextManager::default());
        let source = "127.0.0.1:1234".parse::<SocketAddr>().unwrap();
        let ctx = manager.create_context("test".to_string(), source).await;

        ctx.write().await.set_target(target).set_feature(feature);
        ctx
    }

    #[tokio::test]
    async fn test_http_connector_basic_interface() {
        let mock_ops = Arc::new(MockSocketOps::new_with_builder(|| {
            http_connect_stream("httpbin.org", 80)
        }));
        let connector =
            create_test_connector("192.0.2.12".to_string(), 8080, None, false, mock_ops);

        // Test basic interface
        assert_eq!(connector.name(), "test_http");
        assert_eq!(
            connector.features(),
            &[Feature::TcpForward, Feature::UdpForward, Feature::UdpBind]
        );

        // Test init
        let mut connector_copy = connector.clone();
        let result = connector_copy.init().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_http_connector_connection_success() {
        let mock_ops = Arc::new(MockSocketOps::new_with_builder(|| {
            http_connect_stream("httpbin.org", 80)
        }));
        let connector = Arc::new(create_test_connector(
            "192.0.2.10".to_string(), // Use IP address instead of domain
            8080,
            None,
            false,
            mock_ops,
        ));

        let target = TargetAddress::DomainPort("httpbin.org".to_string(), 80);
        let ctx = create_test_context(target, Feature::TcpForward).await;

        // This should succeed with mock socket ops
        let result = connector.connect(ctx.clone()).await;
        assert!(result.is_ok());

        // Verify context was updated correctly with mock addresses
        let context_read = ctx.read().await;
        assert_eq!(context_read.local_addr().to_string(), "127.0.0.1:12345");
        assert_eq!(context_read.server_addr().to_string(), "192.0.2.1:80");
    }

    #[tokio::test]
    async fn test_http_connector_connection_failure() {
        let mock_ops = Arc::new(
            MockSocketOps::new_with_builder(|| http_connect_stream("example.com", 80))
                .with_tcp_error("Connection refused".to_string()),
        );
        let connector = Arc::new(create_test_connector(
            "192.0.2.11".to_string(), // Use IP address instead of domain
            8080,
            None,
            false,
            mock_ops,
        ));

        let target = TargetAddress::DomainPort("example.com".to_string(), 80);
        let ctx = create_test_context(target, Feature::TcpForward).await;

        // This should fail with mock error
        let result = connector.connect(ctx).await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("TCP connection failed")
        );
    }

    #[tokio::test]
    async fn test_http_connector_features() {
        let mock_ops = Arc::new(MockSocketOps::new_with_builder(|| {
            http_connect_stream("httpbin.org", 80)
        }));
        let connector =
            create_test_connector("192.0.2.13".to_string(), 8080, None, false, mock_ops);

        // Test supported features
        let features = connector.features();
        assert!(features.contains(&Feature::TcpForward));
        assert!(features.contains(&Feature::UdpForward));
        assert!(features.contains(&Feature::UdpBind));
    }

    #[tokio::test]
    async fn test_http_connector_force_connect() {
        // Test force_connect = true forces CONNECT tunneling even for HTTP forward proxy requests
        let mock_ops = Arc::new(MockSocketOps::new_with_builder(|| {
            http_connect_stream("httpbin.org", 80)
        }));
        let connector = Arc::new(create_test_connector(
            "192.0.2.14".to_string(),
            8080,
            None,
            true, // force_connect = true
            mock_ops,
        ));

        // Create context with HTTP request (which normally would use forward proxy)
        let target = TargetAddress::DomainPort("httpbin.org".to_string(), 80);
        let ctx = create_test_context(target, Feature::TcpForward).await;

        // Add an HTTP request to the context (simulating HTTP forward proxy scenario)
        {
            let mut ctx_lock = ctx.write().await;
            let http_request = crate::common::http::HttpRequest::new("GET", "/")
                .with_header("Host", "httpbin.org");
            ctx_lock.set_http_request(http_request);
        }

        // Connect should still use CONNECT tunneling because force_connect = true
        let result = connector.connect(ctx.clone()).await;
        assert!(
            result.is_ok(),
            "Connection should succeed with force_connect"
        );
    }

    #[test]
    fn test_udp_protocol_config_validation() {
        // Test valid protocols
        let custom_config = UdpProtocolConfig {
            protocol: "custom".to_string(),
            rfc9298_uri_template: default_rfc9298_uri_template(),
        };
        assert!(custom_config.validate().is_ok());

        let rfc9298_config = UdpProtocolConfig {
            protocol: "rfc9298".to_string(),
            rfc9298_uri_template: "/custom/{host}/{port}".to_string(),
        };
        assert!(rfc9298_config.validate().is_ok());

        // Test invalid protocol
        let invalid_config = UdpProtocolConfig {
            protocol: "invalid".to_string(),
            rfc9298_uri_template: default_rfc9298_uri_template(),
        };
        assert!(invalid_config.validate().is_err());

        // Test template access
        assert_eq!(custom_config.protocol_name(), "custom");
        assert_eq!(custom_config.rfc9298_uri_template(), None);
        
        assert_eq!(rfc9298_config.protocol_name(), "rfc9298");
        assert_eq!(rfc9298_config.rfc9298_uri_template(), Some("/custom/{host}/{port}"));
    }

    #[tokio::test]
    async fn test_http_connector_with_auth() {
        // Test that HTTP connector includes Proxy-Authorization header when auth is configured
        let mock_ops = Arc::new(MockSocketOps::new_with_builder(|| {
            StreamScript::new()
                .write(
                    "CONNECT httpbin.org:80 HTTP/1.1\r\nHost: httpbin.org:80\r\nProxy-Authorization: Basic dGVzdHVzZXI6dGVzdHBhc3M=\r\n\r\n"
                        .as_bytes(),
                )
                .read(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .build()
        }));
        
        let auth = HttpAuthData {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        };
        
        let connector = Arc::new(HttpConnector::with_socket_ops(
            HttpConnectorConfig {
                name: "test_http_auth".to_string(),
                server: "192.0.2.16".to_string(),
                port: 8080,
                tls: None,
                force_connect: false,
                auth: Some(auth),
            },
            mock_ops,
        ));

        let target = TargetAddress::DomainPort("httpbin.org".to_string(), 80);
        let ctx = create_test_context(target, Feature::TcpForward).await;

        // This should succeed and include the Proxy-Authorization header
        let result = connector.connect(ctx.clone()).await;
        assert!(result.is_ok(), "Connection with auth should succeed");

        // Verify context was updated correctly
        let context_read = ctx.read().await;
        assert_eq!(context_read.local_addr().to_string(), "127.0.0.1:12345");
        assert_eq!(context_read.server_addr().to_string(), "192.0.2.1:80");
    }

    #[tokio::test]
    async fn test_http_connector_no_force_connect() {
        // Test force_connect = false (default) allows HTTP forward proxy for HTTP requests
        let mock_ops = Arc::new(MockSocketOps::new_with_builder(|| {
            // No CONNECT expected, just plain TCP connection
            StreamScript::new().build()
        }));
        let connector = Arc::new(create_test_connector(
            "192.0.2.15".to_string(),
            8080,
            None,
            false, // force_connect = false (default)
            mock_ops,
        ));

        // Create context with HTTP request
        let target = TargetAddress::DomainPort("httpbin.org".to_string(), 80);
        let ctx = create_test_context(target, Feature::TcpForward).await;

        // Add an HTTP request to the context
        {
            let mut ctx_lock = ctx.write().await;
            let http_request = crate::common::http::HttpRequest::new("GET", "/")
                .with_header("Host", "httpbin.org");
            ctx_lock.set_http_request(http_request);
        }

        // Connect should use HTTP forward proxy (no CONNECT tunneling)
        let result = connector.connect(ctx.clone()).await;
        assert!(
            result.is_ok(),
            "Connection should succeed without force_connect"
        );
    }
}
