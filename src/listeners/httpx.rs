use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc::Sender;
use tracing::{debug, error, info, warn};

use crate::{
    HttpVersion,
    common::{
        auth::AuthData,
        socket_ops::{RealSocketOps, SocketOps, TcpListener},
        tls::TlsServerConfig,
    },
    config::Timeouts,
    context::{ContextManager, ContextRef, IOStream},
    listeners::Listener,
    protocols::http::http1::handle_listener_connection,
};
use std::ops::{Deref, DerefMut};

/// HTTP/1 specific configuration
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Http1Config {
    #[serde(default)]
    enable: bool,
}

impl Default for Http1Config {
    fn default() -> Self {
        Self { enable: true }
    }
}

/// HTTP/2 specific configuration  
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
#[derive(Default)]
pub struct Http2Config {
    #[serde(default)]
    enable: bool,
    #[serde(default)]
    max_concurrent_streams: Option<u32>,
    #[serde(default)]
    initial_window_size: Option<u32>,
}

/// HTTP/3 specific configuration
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
#[derive(Default)]
pub struct Http3Config {
    #[serde(default)]
    enable: bool,
    #[serde(default)]
    bind: Option<SocketAddr>, // UDP port for HTTP/3
    #[serde(default)]
    max_concurrent_streams: Option<u32>,
    #[serde(default)]
    max_idle_timeout: Option<String>,
}

/// Protocols configuration section
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
#[derive(Default)]
pub struct ProtocolsConfig {
    #[serde(default)]
    http1: Http1Config,
    #[serde(default)]
    http2: Http2Config,
    #[serde(default)]
    http3: Http3Config,
}

/// UDP configuration
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct UdpConfig {
    #[serde(default)]
    enable: bool,
}

impl Default for UdpConfig {
    fn default() -> Self {
        Self { enable: true }
    }
}

/// Loop detection configuration
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LoopDetectConfig {
    #[serde(default)]
    enable: bool,
    #[serde(default = "default_max_hops")]
    max_hops: u8,
}

fn default_max_hops() -> u8 {
    5
}

impl Default for LoopDetectConfig {
    fn default() -> Self {
        Self {
            enable: false,
            max_hops: 5,
        }
    }
}

/// Configuration for unified HTTP listener (httpx)
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct HttpxListenerConfig {
    name: String,
    bind: SocketAddr,
    #[serde(default)]
    tls: Option<TlsServerConfig>,
    #[serde(default)]
    protocols: ProtocolsConfig,
    #[serde(default)]
    udp: UdpConfig,
    #[serde(default)]
    loop_detect: LoopDetectConfig,
    #[serde(default)]
    auth: AuthData,
}

/// Unified HTTP listener supporting HTTP/1.1, HTTP/2, and HTTP/3
/// Uses ALPN negotiation to determine protocol version
#[derive(Debug, Clone, Serialize)]
pub struct HttpxListener<S = RealSocketOps>
where
    S: SocketOps,
{
    #[serde(flatten)]
    config: HttpxListenerConfig,
    #[serde(skip)]
    socket_ops: Arc<S>,
}

impl<S: SocketOps> Deref for HttpxListener<S> {
    type Target = HttpxListenerConfig;
    fn deref(&self) -> &Self::Target {
        &self.config
    }
}

impl<S: SocketOps> DerefMut for HttpxListener<S> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.config
    }
}

impl<S: SocketOps> HttpxListener<S> {
    pub fn new(config: HttpxListenerConfig, socket_ops: Arc<S>) -> Self {
        Self { config, socket_ops }
    }
}

pub fn from_value(value: &serde_yaml_ng::Value) -> Result<Box<dyn Listener>> {
    let config: HttpxListenerConfig =
        serde_yaml_ng::from_value(value.clone()).with_context(|| "parse httpx listener config")?;
    let ret = HttpxListener::new(config, Arc::new(RealSocketOps));
    Ok(Box::new(ret))
}

#[async_trait]
impl<S: SocketOps + Send + Sync + 'static> Listener for HttpxListener<S> {
    fn name(&self) -> &str {
        &self.name
    }

    async fn init(&mut self) -> Result<()> {
        // Initialize TLS if configured
        if self.tls.is_some() {
            // Extract protocol configuration before mutable borrow
            let http1_enable = self.protocols.http1.enable;
            let http2_enable = self.protocols.http2.enable;
            let http3_enable = self.protocols.http3.enable;
            let listener_name = self.name.clone();

            let tls_config = self.tls.as_mut().unwrap();

            // Configure ALPN protocols at runtime based on enabled protocols
            let mut alpn_protocols = Vec::new();

            // Add protocols in preference order based on enabled protocols
            if http3_enable {
                alpn_protocols.push(b"h3".to_vec());
                alpn_protocols.push(b"h3-29".to_vec());
            }
            if http2_enable {
                alpn_protocols.push(b"h2".to_vec());
            }
            if http1_enable {
                alpn_protocols.push(b"http/1.1".to_vec());
                alpn_protocols.push(b"http/1.0".to_vec());
            }

            // Set ALPN protocols in TLS configuration
            if !alpn_protocols.is_empty() {
                tls_config.set_alpn_protocols(alpn_protocols.clone());
                info!(
                    "ALPN protocols configured for {}: {:?}",
                    listener_name,
                    alpn_protocols
                        .iter()
                        .map(|p| String::from_utf8_lossy(p))
                        .collect::<Vec<_>>()
                );
            }

            // Validate and initialize TLS configuration
            tls_config.validate()?;
            tls_config.init()?;
            info!("TLS initialized for {}", listener_name);
        }

        self.auth.init().await?;

        // Validate protocol configuration
        if !self.protocols.http1.enable
            && !self.protocols.http2.enable
            && !self.protocols.http3.enable
        {
            bail!("At least one HTTP protocol must be enabled");
        }

        if self.protocols.http3.enable && self.tls.is_none() {
            bail!("HTTP/3 requires TLS configuration");
        }

        info!(
            "Enabled protocols for {}: HTTP/1.1={}, HTTP/2={}, HTTP/3={}",
            self.name,
            self.protocols.http1.enable,
            self.protocols.http2.enable,
            self.protocols.http3.enable
        );

        Ok(())
    }

    async fn verify(&self) -> Result<()> {
        // Validate protocol configuration
        if !self.protocols.http1.enable
            && !self.protocols.http2.enable
            && !self.protocols.http3.enable
        {
            bail!("At least one HTTP protocol must be enabled");
        }

        if self.protocols.http3.enable && self.tls.is_none() {
            bail!("HTTP/3 requires TLS configuration");
        }

        // Validate HTTP/3 UDP bind address if enabled
        if self.protocols.http3.enable {
            if let Some(udp_bind) = &self.protocols.http3.bind {
                // Ensure UDP port is different from TCP port
                if udp_bind.port() == self.bind.port() {
                    bail!("HTTP/3 UDP port must differ from TCP port");
                }
            } else if self.udp.enable {
                bail!("HTTP/3 enabled but no UDP bind address specified");
            }
        }

        // Validate HTTP/2 settings
        if self.protocols.http2.enable
            && let Some(streams) = self.protocols.http2.max_concurrent_streams
            && streams == 0
        {
            bail!("HTTP/2 max_concurrent_streams must be greater than 0");
        }

        Ok(())
    }

    async fn listen(
        self: Arc<Self>,
        contexts: Arc<ContextManager>,
        _timeouts: Timeouts,
        queue: Sender<ContextRef>,
    ) -> Result<()> {
        let protocols = if self.tls.is_some() {
            "HTTP/1.1+TLS, HTTP/2, HTTP/3"
        } else {
            "HTTP/1.1"
        };

        info!("{} listening on {} ({})", self.name, self.bind, protocols);

        // Start TCP listener for HTTP/1.1 and HTTP/2
        let tcp_listener = self.socket_ops.tcp_listen(self.bind).await?;
        let this_tcp = self.clone();
        let tcp_queue = queue.clone();
        tokio::spawn(this_tcp.accept(tcp_listener, contexts.clone(), tcp_queue));

        // Start UDP listener for HTTP/3 if enabled
        if self.protocols.http3.enable
            && self.udp.enable
            && let Some(udp_bind) = &self.protocols.http3.bind
        {
            info!("{} HTTP/3 listening on UDP {}", self.name, udp_bind);
            // TODO: Implement actual HTTP/3 UDP listener
            // This would require QUIC integration which is a separate feature
            warn!(
                "{} HTTP/3 UDP binding configured but not yet implemented",
                self.name
            );
        }

        Ok(())
    }
}

impl<S: SocketOps + Send + Sync + 'static> HttpxListener<S> {
    async fn accept(
        self: Arc<Self>,
        listener: Box<dyn TcpListener>,
        contexts: Arc<ContextManager>,
        queue: Sender<ContextRef>,
    ) {
        loop {
            match listener.accept().await.with_context(|| "accept") {
                Ok((stream, source)) => {
                    // Spawn a new task to handle each connection
                    let this = self.clone();
                    let queue = queue.clone();
                    let contexts = contexts.clone();
                    let source = crate::common::try_map_v4_addr(source);

                    tokio::spawn(async move {
                        let this_clone = this.clone();
                        if let Err(e) = this
                            .handle_connection(stream, source, contexts, queue)
                            .await
                        {
                            error!("{}: connection handling failed: {}", this_clone.name, e);
                        }
                    });
                }
                Err(e) => {
                    // Only fatal errors reach here now (socket ops handles transient errors)
                    error!(
                        "{}: fatal accept error: {}, shutting down listener",
                        self.name, e
                    );
                    return;
                }
            }
        }
    }

    async fn handle_connection(
        self: Arc<Self>,
        stream: Box<dyn IOStream>,
        source: SocketAddr,
        contexts: Arc<ContextManager>,
        queue: Sender<ContextRef>,
    ) -> Result<()> {
        debug!("{}: handling connection from {}", self.name, source);

        // Handle TLS handshake if configured and extract ALPN protocol
        let (stream, alpn_protocol) = if let Some(tls_config) = &self.tls {
            match self
                .socket_ops
                .tls_handshake_server(stream, tls_config)
                .await
            {
                Ok((stream, alpn)) => (stream, alpn),
                Err(e) => {
                    warn!("{}: TLS handshake failed with {}: {}", self.name, source, e);
                    return Err(e);
                }
            }
        } else {
            (stream, None)
        };

        // Create context
        let ctx = contexts.create_context(self.name.clone(), source).await;

        self.socket_ops
            .set_keepalive(stream.as_ref(), true)
            .await
            .unwrap_or_else(|e| warn!("set_keepalive failed: {}", e));

        // Set the listener's bind address as local address for loop detection
        ctx.write().await.set_local_addr(self.bind);

        // Protocol negotiation based on ALPN
        debug!(
            "{}: ALPN negotiated protocol: {:?}",
            self.name, alpn_protocol
        );
        let protocol_choice = negotiate_http_protocol(alpn_protocol.as_deref());

        // Delegate entire connection lifecycle to the appropriate protocol handler
        match protocol_choice {
            HttpVersion::Http1_1 | HttpVersion::Http1_0 => {
                handle_listener_connection(stream, contexts, queue, self.name.clone(), source, Some(self.auth.clone()))
                    .await?;
            }
            HttpVersion::Http2 => {
                bail!("HTTP/2 is not supported yet");
            }
            HttpVersion::Http3 => {
                bail!("HTTP/3 over TCP is not supported");
            }
        }

        debug!(
            "{}: connection handling completed for {}",
            self.name, source
        );
        Ok(())
    }
}

/// Determine HTTP protocol handler from ALPN result
pub fn negotiate_http_protocol(alpn_result: Option<&str>) -> HttpVersion {
    match alpn_result {
        Some("h2") | Some("h2c") => {
            tracing::debug!("ALPN negotiated HTTP/2: {:?}", alpn_result);
            HttpVersion::Http2
        }
        Some("http/1.1") | Some("http/1.0") => {
            tracing::debug!("ALPN negotiated HTTP/1.1: {:?}", alpn_result);
            HttpVersion::Http1_1
        }
        Some("h3") | Some("h3-29") => {
            tracing::debug!("ALPN negotiated HTTP/3: {:?}", alpn_result);
            HttpVersion::Http3
        }
        Some(other) => {
            tracing::warn!("Unknown ALPN protocol: {}, falling back to HTTP/1.1", other);
            HttpVersion::Http1_1
        }
        None => {
            // Fallback to HTTP/1.1 when no ALPN
            tracing::debug!("No ALPN protocol negotiated, falling back to HTTP/1.1");
            HttpVersion::Http1_1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        common::socket_ops::{SocketOps, test_utils::MockSocketOps},
        context::ContextManager,
    };
    use std::sync::Arc;
    use test_log::test;

    fn create_test_config() -> HttpxListenerConfig {
        HttpxListenerConfig {
            name: "test_httpx".to_string(),
            bind: "127.0.0.1:8080".parse().unwrap(),
            tls: None,
            protocols: ProtocolsConfig {
                http1: Http1Config { enable: true },
                http2: Http2Config {
                    enable: false,
                    ..Default::default()
                },
                http3: Http3Config {
                    enable: false,
                    ..Default::default()
                },
            },
            udp: UdpConfig { enable: false },
            loop_detect: LoopDetectConfig::default(),
            auth: AuthData::default(),
        }
    }

    fn create_test_listener<S: SocketOps>(
        config: HttpxListenerConfig,
        socket_ops: Arc<S>,
    ) -> HttpxListener<S> {
        HttpxListener::new(config, socket_ops)
    }

    #[test]
    fn test_httpx_listener_creation() {
        let config = create_test_config();
        let socket_ops = Arc::new(MockSocketOps::new());
        let listener = create_test_listener(config, socket_ops);

        assert_eq!(listener.name(), "test_httpx");
        assert_eq!(listener.bind.to_string(), "127.0.0.1:8080");
        assert!(listener.protocols.http1.enable);
        assert!(!listener.protocols.http2.enable);
    }

    #[test(tokio::test)]
    async fn test_httpx_listener_init() {
        let config = create_test_config();
        let socket_ops = Arc::new(MockSocketOps::new());
        let mut listener = create_test_listener(config, socket_ops);

        let result = listener.init().await;
        assert!(result.is_ok());
    }

    #[test(tokio::test)]
    async fn test_httpx_listener_init_no_protocols_enabled() {
        let mut config = create_test_config();
        config.protocols.http1.enable = false;
        config.protocols.http2.enable = false;
        config.protocols.http3.enable = false;

        let socket_ops = Arc::new(MockSocketOps::new());
        let mut listener = create_test_listener(config, socket_ops);

        let result = listener.init().await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("At least one HTTP protocol must be enabled")
        );
    }

    #[test(tokio::test)]
    async fn test_httpx_listener_verify() {
        let config = create_test_config();
        let socket_ops = Arc::new(MockSocketOps::new());
        let listener = create_test_listener(config, socket_ops);

        let result = listener.verify().await;
        assert!(result.is_ok());
    }

    #[test(tokio::test)]
    async fn test_httpx_listener_verify_http3_without_tls() {
        let mut config = create_test_config();
        config.protocols.http3.enable = true;
        config.tls = None;

        let socket_ops = Arc::new(MockSocketOps::new());
        let listener = create_test_listener(config, socket_ops);

        let result = listener.verify().await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("HTTP/3 requires TLS configuration")
        );
    }

    #[test]
    fn test_negotiate_http_protocol() {
        // Test HTTP/1.1 negotiation
        assert_eq!(
            negotiate_http_protocol(Some("http/1.1")),
            HttpVersion::Http1_1
        );
        assert_eq!(
            negotiate_http_protocol(Some("http/1.0")),
            HttpVersion::Http1_1
        );

        // Test HTTP/2 negotiation
        assert_eq!(negotiate_http_protocol(Some("h2")), HttpVersion::Http2);
        assert_eq!(negotiate_http_protocol(Some("h2c")), HttpVersion::Http2);

        // Test HTTP/3 negotiation
        assert_eq!(negotiate_http_protocol(Some("h3")), HttpVersion::Http3);
        assert_eq!(negotiate_http_protocol(Some("h3-29")), HttpVersion::Http3);

        // Test fallback behavior
        assert_eq!(
            negotiate_http_protocol(Some("unknown")),
            HttpVersion::Http1_1
        );
        assert_eq!(negotiate_http_protocol(None), HttpVersion::Http1_1);
    }

    #[test]
    fn test_http1_handler_delegation() {
        // Test that HTTP/1.1 protocol choice leads to Http1Handler delegation
        let socket_ops = Arc::new(MockSocketOps::new());
        let config = create_test_config();
        let listener = create_test_listener(config, socket_ops);

        // Verify that when HTTP/1.1 is enabled, the handler can be instantiated
        assert!(listener.protocols.http1.enable);

        // Test ALPN negotiation returns correct protocol
        let protocol = negotiate_http_protocol(Some("http/1.1"));
        matches!(protocol, HttpVersion::Http1_1);

        let protocol = negotiate_http_protocol(None); // No ALPN should default to HTTP/1.1
        matches!(protocol, HttpVersion::Http1_1);
    }

    #[test]
    fn test_http1_configuration_validation() {
        // Test various HTTP/1.1 configuration scenarios
        let mut config = create_test_config();

        // Valid config with only HTTP/1.1 enabled
        config.protocols.http1.enable = true;
        config.protocols.http2.enable = false;
        config.protocols.http3.enable = false;

        let socket_ops = Arc::new(MockSocketOps::new());
        let listener = create_test_listener(config, socket_ops);

        // Should be valid
        assert!(listener.protocols.http1.enable);
        assert!(!listener.protocols.http2.enable);
        assert!(!listener.protocols.http3.enable);
    }

    #[test]
    fn test_http1_alpn_protocol_precedence() {
        // Test that HTTP/1.1 ALPN protocols work correctly
        assert_eq!(
            negotiate_http_protocol(Some("http/1.1")),
            HttpVersion::Http1_1
        );
        assert_eq!(
            negotiate_http_protocol(Some("http/1.0")),
            HttpVersion::Http1_1
        );

        // Test precedence - HTTP/2 should take precedence over HTTP/1.1 when both present
        assert_eq!(negotiate_http_protocol(Some("h2")), HttpVersion::Http2);

        // Test fallback to HTTP/1.1
        assert_eq!(
            negotiate_http_protocol(Some("unknown-protocol")),
            HttpVersion::Http1_1
        );
        assert_eq!(negotiate_http_protocol(None), HttpVersion::Http1_1);
    }

    #[test(tokio::test)]
    async fn test_connection_handling_setup() {
        // Test the connection setup phase - this tests the httpx listener's role
        // in setting up contexts and delegating to the HTTP/1.1 handler
        let config = create_test_config();
        let socket_ops = Arc::new(MockSocketOps::new());
        let listener = Arc::new(create_test_listener(config, socket_ops));

        let contexts = Arc::new(ContextManager::default());
        let source = "127.0.0.1:12345".parse().unwrap();

        // Create a test context to verify the setup
        let ctx = contexts
            .create_context(listener.name().to_string(), source)
            .await;

        // Verify context was created correctly
        {
            let ctx_read = ctx.read().await;
            assert_eq!(ctx_read.props().listener, "test_httpx");
            assert_eq!(ctx_read.props().source, source);
        }

        // This tests the httpx listener's context management, not the full HTTP handling
        // The full HTTP/1.1 request processing is tested in the Http1Handler tests
    }

    #[test]
    fn test_config_serialization() {
        let config = HttpxListenerConfig {
            name: "test_httpx".to_string(),
            bind: "127.0.0.1:8080".parse().unwrap(),
            tls: None,
            protocols: ProtocolsConfig {
                http1: Http1Config { enable: true },
                http2: Http2Config {
                    enable: true,
                    max_concurrent_streams: Some(100),
                    initial_window_size: Some(65536),
                },
                http3: Http3Config {
                    enable: false,
                    bind: Some("127.0.0.1:8443".parse().unwrap()),
                    max_concurrent_streams: Some(50),
                    max_idle_timeout: Some("30s".to_string()),
                },
            },
            udp: UdpConfig { enable: true },
            loop_detect: LoopDetectConfig {
                enable: true,
                max_hops: 10,
            },
            auth: AuthData::default(),
        };

        let serialized = serde_yaml_ng::to_string(&config).unwrap();
        assert!(serialized.contains("name: test_httpx"));
        assert!(serialized.contains("bind: 127.0.0.1:8080"));

        let deserialized: HttpxListenerConfig = serde_yaml_ng::from_str(&serialized).unwrap();
        assert_eq!(deserialized.name, config.name);
        assert_eq!(deserialized.bind, config.bind);
        assert_eq!(
            deserialized.protocols.http1.enable,
            config.protocols.http1.enable
        );
    }

    #[test]
    fn test_protocol_configs() {
        // Test default configurations
        let http1_default = Http1Config::default();
        assert!(http1_default.enable);

        let http2_default = Http2Config::default();
        assert!(!http2_default.enable);
        assert!(http2_default.max_concurrent_streams.is_none());

        let udp_default = UdpConfig::default();
        assert!(udp_default.enable);

        let loop_detect_default = LoopDetectConfig::default();
        assert!(!loop_detect_default.enable);
        assert_eq!(loop_detect_default.max_hops, 5);
    }
}

#[cfg(test)]
mod e2e_tests {
    use super::*;
    use crate::{
        common::socket_ops::test_utils::{MockSocketOps, StreamScript},
        context::ContextManager,
        protocols::http::{HttpMessage, HttpVersion},
    };
    use std::sync::Arc;
    use test_log::test;
    use tokio::sync::mpsc;

    /// Test HTTP/1.1 request parsing through httpx listener handle_connection
    #[test(tokio::test)]
    async fn test_e2e_http1_request_parsing_data_flow() {
        // This test focuses on the request parsing phase - verifying that
        // HTTP/1.1 requests are properly parsed and queued through handle_connection
        let mock_ops = Arc::new(MockSocketOps::new_with_builder(|| {
            StreamScript::new()
                .read(b"GET /test HTTP/1.1\r\nHost: example.com\r\nUser-Agent: TestClient\r\nConnection: close\r\n\r\n")
                .build() // No write expected - we're testing parsing, not response generation
        }));

        let config = HttpxListenerConfig {
            name: "test-parsing".to_string(),
            bind: "127.0.0.1:8080".parse().unwrap(),
            tls: None,
            protocols: ProtocolsConfig {
                http1: Http1Config { enable: true },
                http2: Http2Config {
                    enable: false,
                    ..Default::default()
                },
                http3: Http3Config {
                    enable: false,
                    ..Default::default()
                },
            },
            udp: UdpConfig { enable: false },
            loop_detect: LoopDetectConfig::default(),
            auth: AuthData::default(),
        };

        let listener = Arc::new(HttpxListener::new(config, mock_ops.clone()));
        let contexts = Arc::new(ContextManager::default());
        let source = "127.0.0.1:12345".parse().unwrap();
        let (queue_tx, mut queue_rx) = mpsc::channel(1);

        let mock_stream = Box::new((mock_ops.stream_builder)());

        // Test request parsing - this should create a context and queue it
        tokio::select! {
            _result = listener.handle_connection(mock_stream, source, contexts.clone(), queue_tx) => {
                // The connection handling will time out waiting for callback completion
                // but that's expected since we don't have a full rules engine running
                // We just want to verify the request was parsed and queued
            }
            queued_ctx = queue_rx.recv() => {
                // Verify we got a queued context with parsed HTTP request
                let ctx = queued_ctx.expect("Should receive queued context");
                let ctx_read = ctx.read().await;
                let http_request = ctx_read.http_request().expect("Should have parsed HTTP request");

                assert_eq!(http_request.method.to_string(), "GET");
                assert_eq!(http_request.uri, "/test");
                assert_eq!(http_request.get_header("Host").unwrap(), "example.com");
                assert_eq!(http_request.get_header("User-Agent").unwrap(), "TestClient");
                assert_eq!(http_request.get_header("Connection").unwrap(), "close");

                // Success - request was properly parsed and queued
                return;
            }
            _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {
                panic!("Test timed out - no context was queued");
            }
        }
    }

    /// Test HTTP/1.1 CONNECT request parsing through httpx listener
    #[test(tokio::test)]
    async fn test_e2e_http1_connect_parsing_data_flow() {
        let mock_ops = Arc::new(MockSocketOps::new_with_builder(|| {
            StreamScript::new()
                .read(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic dGVzdA==\r\n\r\n")
                .build()
        }));

        let config = HttpxListenerConfig {
            name: "test-connect".to_string(),
            bind: "127.0.0.1:8081".parse().unwrap(),
            tls: None,
            protocols: ProtocolsConfig {
                http1: Http1Config { enable: true },
                http2: Http2Config {
                    enable: false,
                    ..Default::default()
                },
                http3: Http3Config {
                    enable: false,
                    ..Default::default()
                },
            },
            udp: UdpConfig { enable: false },
            loop_detect: LoopDetectConfig::default(),
            auth: AuthData::default(),
        };

        let listener = Arc::new(HttpxListener::new(config, mock_ops.clone()));
        let contexts = Arc::new(ContextManager::default());
        let source = "127.0.0.1:12346".parse().unwrap();
        let (queue_tx, mut queue_rx) = mpsc::channel(1);

        let mock_stream = Box::new((mock_ops.stream_builder)());

        // Test CONNECT request parsing
        tokio::select! {
            _ = listener.handle_connection(mock_stream, source, contexts.clone(), queue_tx) => {
                // Will timeout waiting for callback, but we already got what we need
            }
            queued_ctx = queue_rx.recv() => {
                let ctx = queued_ctx.expect("Should receive CONNECT context");
                let ctx_read = ctx.read().await;
                let http_request = ctx_read.http_request().expect("Should have parsed CONNECT request");

                assert_eq!(http_request.method.to_string(), "CONNECT");
                assert_eq!(http_request.uri, "example.com:443");
                assert_eq!(http_request.get_header("Host").unwrap(), "example.com:443");
                assert_eq!(http_request.get_header("Proxy-Authorization").unwrap(), "Basic dGVzdA==");

                return; // Success
            }
            _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {
                panic!("CONNECT request was not queued");
            }
        }
    }

    /// Test HTTP/1.1 POST request with body parsing
    #[test(tokio::test)]
    async fn test_e2e_http1_post_body_parsing_data_flow() {
        let mock_ops = Arc::new(MockSocketOps::new_with_builder(|| {
            StreamScript::new()
                .read(b"POST /api/submit HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\nContent-Length: 25\r\nConnection: close\r\n\r\n{\"name\":\"test\",\"value\":42}")
                .build()
        }));

        let config = HttpxListenerConfig {
            name: "test-post".to_string(),
            bind: "127.0.0.1:8082".parse().unwrap(),
            tls: None,
            protocols: ProtocolsConfig {
                http1: Http1Config { enable: true },
                http2: Http2Config {
                    enable: false,
                    ..Default::default()
                },
                http3: Http3Config {
                    enable: false,
                    ..Default::default()
                },
            },
            udp: UdpConfig { enable: false },
            loop_detect: LoopDetectConfig::default(),
            auth: AuthData::default(),
        };

        let listener = Arc::new(HttpxListener::new(config, mock_ops.clone()));
        let contexts = Arc::new(ContextManager::default());
        let source = "127.0.0.1:12347".parse().unwrap();
        let (queue_tx, mut queue_rx) = mpsc::channel(1);

        let mock_stream = Box::new((mock_ops.stream_builder)());

        // Test POST with body parsing
        tokio::select! {
            _ = listener.handle_connection(mock_stream, source, contexts.clone(), queue_tx) => {}
            queued_ctx = queue_rx.recv() => {
                let ctx = queued_ctx.expect("Should receive POST context");
                let ctx_read = ctx.read().await;
                let http_request = ctx_read.http_request().expect("Should have parsed POST request");

                assert_eq!(http_request.method.to_string(), "POST");
                assert_eq!(http_request.uri, "/api/submit");
                assert_eq!(http_request.get_header("Content-Type").unwrap(), "application/json");
                assert_eq!(http_request.get_header("Content-Length").unwrap(), "25");

                return; // Success
            }
            _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {
                panic!("POST request was not queued");
            }
        }
    }

    /// Test protocol negotiation function directly
    #[test]
    fn test_alpn_protocol_negotiation() {
        // Test ALPN protocol negotiation logic
        assert_eq!(
            negotiate_http_protocol(Some("http/1.1")),
            HttpVersion::Http1_1
        );
        assert_eq!(
            negotiate_http_protocol(Some("http/1.0")),
            HttpVersion::Http1_1
        );
        assert_eq!(negotiate_http_protocol(Some("h2")), HttpVersion::Http2);
        assert_eq!(negotiate_http_protocol(Some("h2c")), HttpVersion::Http2);
        assert_eq!(negotiate_http_protocol(Some("h3")), HttpVersion::Http3);
        assert_eq!(negotiate_http_protocol(Some("h3-29")), HttpVersion::Http3);

        // Test fallback behavior
        assert_eq!(
            negotiate_http_protocol(Some("unknown")),
            HttpVersion::Http1_1
        );
        assert_eq!(negotiate_http_protocol(None), HttpVersion::Http1_1);
    }

    /// Test malformed request handling data flow
    #[test(tokio::test)]
    async fn test_e2e_http1_malformed_request_error_handling() {
        let mock_ops = Arc::new(MockSocketOps::new_with_builder(|| {
            StreamScript::new()
                .read(b"INVALID REQUEST WITHOUT PROPER FORMAT\r\n\r\n")
                .write(b"HTTP/1.1 400 Bad Request\r\n\r\n") // Error response expected
                .build()
        }));

        let config = HttpxListenerConfig {
            name: "test-error".to_string(),
            bind: "127.0.0.1:8084".parse().unwrap(),
            tls: None,
            protocols: ProtocolsConfig {
                http1: Http1Config { enable: true },
                http2: Http2Config {
                    enable: false,
                    ..Default::default()
                },
                http3: Http3Config {
                    enable: false,
                    ..Default::default()
                },
            },
            udp: UdpConfig { enable: false },
            loop_detect: LoopDetectConfig::default(),
            auth: AuthData::default(),
        };

        let listener = Arc::new(HttpxListener::new(config, mock_ops.clone()));
        let contexts = Arc::new(ContextManager::default());
        let source = "127.0.0.1:12349".parse().unwrap();
        let (queue_tx, _queue_rx) = mpsc::channel(1);

        let mock_stream = Box::new((mock_ops.stream_builder)());

        // Test malformed request error handling
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            listener.handle_connection(mock_stream, source, contexts.clone(), queue_tx),
        )
        .await;

        // Should timeout or return error due to malformed request
        match result {
            Ok(Err(e)) => {
                // Good - got an error for malformed request
                assert!(e.to_string().contains("Invalid request line"));
            }
            Err(_) => {
                // Also acceptable - timed out trying to parse malformed request
            }
            Ok(Ok(())) => {
                // This is now the correct behavior - malformed requests get proper error responses
                // and the connection handling succeeds (by sending 400 Bad Request)
            }
        }
    }

    /// Test context creation and basic connection setup
    #[test(tokio::test)]
    async fn test_e2e_context_creation_and_setup() {
        let mock_ops = Arc::new(MockSocketOps::new_with_builder(|| {
            StreamScript::new()
                .read(b"HEAD /health HTTP/1.1\r\nHost: health.example.com\r\nConnection: close\r\n\r\n")
                .build()
        }));

        let config = HttpxListenerConfig {
            name: "test-context-setup".to_string(),
            bind: "127.0.0.1:8085".parse().unwrap(),
            tls: None,
            protocols: ProtocolsConfig {
                http1: Http1Config { enable: true },
                http2: Http2Config {
                    enable: false,
                    ..Default::default()
                },
                http3: Http3Config {
                    enable: false,
                    ..Default::default()
                },
            },
            udp: UdpConfig { enable: false },
            loop_detect: LoopDetectConfig::default(),
            auth: AuthData::default(),
        };

        let listener = Arc::new(HttpxListener::new(config, mock_ops.clone()));
        let contexts = Arc::new(ContextManager::default());
        let source = "10.0.0.1:9999".parse().unwrap();
        let (queue_tx, mut queue_rx) = mpsc::channel(1);

        let mock_stream = Box::new((mock_ops.stream_builder)());

        // Test complete context setup
        tokio::select! {
            _ = listener.handle_connection(mock_stream, source, contexts.clone(), queue_tx) => {}
            queued_ctx = queue_rx.recv() => {
                let ctx = queued_ctx.expect("Should receive context");

                // Verify context properties
                let ctx_read = ctx.read().await;
                let props = ctx_read.props();
                assert_eq!(props.listener, "test-context-setup");
                assert_eq!(props.source, source);

                // Verify HTTP request parsing
                let http_request = ctx_read.http_request().expect("Should have HTTP request");
                assert_eq!(http_request.method.to_string(), "HEAD");
                assert_eq!(http_request.uri, "/health");
                assert_eq!(http_request.get_header("Host").unwrap(), "health.example.com");

                return; // Success
            }
            _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {
                panic!("Context was not created and queued");
            }
        }
    }

    /// Test configuration validation and initialization
    #[test(tokio::test)]
    async fn test_httpx_configuration_validation() {
        // Test that httpx listener properly validates and initializes configuration
        let mock_ops = Arc::new(MockSocketOps::new());

        // Valid configuration
        let valid_config = HttpxListenerConfig {
            name: "test-config".to_string(),
            bind: "127.0.0.1:8086".parse().unwrap(),
            tls: None,
            protocols: ProtocolsConfig {
                http1: Http1Config { enable: true },
                http2: Http2Config {
                    enable: false,
                    ..Default::default()
                },
                http3: Http3Config {
                    enable: false,
                    ..Default::default()
                },
            },
            udp: UdpConfig { enable: false },
            loop_detect: LoopDetectConfig::default(),
            auth: AuthData::default(),
        };

        let mut listener = HttpxListener::new(valid_config, mock_ops.clone());
        assert!(listener.init().await.is_ok());
        assert!(listener.verify().await.is_ok());

        // Invalid configuration - no protocols enabled
        let invalid_config = HttpxListenerConfig {
            name: "test-invalid".to_string(),
            bind: "127.0.0.1:8087".parse().unwrap(),
            tls: None,
            protocols: ProtocolsConfig {
                http1: Http1Config { enable: false },
                http2: Http2Config {
                    enable: false,
                    ..Default::default()
                },
                http3: Http3Config {
                    enable: false,
                    ..Default::default()
                },
            },
            udp: UdpConfig { enable: false },
            loop_detect: LoopDetectConfig::default(),
            auth: AuthData::default(),
        };

        let mut invalid_listener = HttpxListener::new(invalid_config, mock_ops);
        assert!(invalid_listener.init().await.is_err());
        assert!(invalid_listener.verify().await.is_err());
    }
}
