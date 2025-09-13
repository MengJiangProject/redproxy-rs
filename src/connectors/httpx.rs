use crate::{
    TargetAddress,
    common::{
        connection_pool::{ConnectionManager, ConnectionPool, DefaultConnectionPool},
        socket_ops::SocketOps,
        tls::TlsClientConfig,
    },
    connectors::{Connector, ConnectorRef},
    context::{ContextRef, IOBufStream, make_buffered_stream},
    protocols::http::context_ext::HttpContextExt,
};
use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration};
use tracing::{debug, info};

/// HTTP/2 settings configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Http2Settings {
    pub header_table_size: Option<u32>,
    pub enable_push: Option<bool>,
    pub max_frame_size: Option<u32>,
    pub initial_window_size: Option<u32>,
}

/// QUIC configuration for HTTP/3
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuicConfig {
    pub max_idle_timeout: Option<Duration>,
    pub keep_alive_interval: Option<Duration>,
    pub max_bi_streams: Option<u32>,
    pub max_uni_streams: Option<u32>,
}

/// Connection pool configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolConfig {
    /// Maximum connections per target
    #[serde(default = "default_pool_max_connections")]
    pub max_connections: usize,
    /// Idle timeout for pooled connections (in seconds)  
    #[serde(default = "default_pool_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
    /// Enable connection pooling
    #[serde(default = "default_true")]
    pub enable: bool,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_connections: 100,
            idle_timeout_secs: 60,
            enable: true,
        }
    }
}

impl PoolConfig {
    /// Get idle timeout as Duration
    pub fn idle_timeout(&self) -> Duration {
        Duration::from_secs(self.idle_timeout_secs)
    }
}

/// HTTP protocol configuration with embedded protocol-specific settings
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum HttpProtocolConfig {
    /// HTTP/1.1 configuration
    #[serde(rename = "http/1.1")]
    Http1 {
        /// Enable Connection: keep-alive for connection reuse
        #[serde(default = "default_true")]
        keep_alive: bool,
    },
    /// HTTP/2 configuration
    #[serde(rename = "h2")]
    Http2 {
        /// Maximum concurrent streams per connection
        max_concurrent_streams: Option<u32>,
        /// HTTP/2 settings frame parameters
        settings: Option<Http2Settings>,
    },
    /// HTTP/3 configuration
    #[serde(rename = "h3")]
    Http3 {
        /// QUIC connection settings
        quic: Option<QuicConfig>,
    },
    /// HTTP/1.1 over QUIC (legacy)
    #[serde(rename = "http1-over-quic")]
    Http1OverQuic {
        /// Enable Connection: keep-alive for connection reuse
        #[serde(default = "default_true")]
        keep_alive: bool,
        /// QUIC connection settings
        quic: Option<QuicConfig>,
    },
}

impl HttpProtocolConfig {
    /// Get the protocol identifier string
    pub fn protocol_id(&self) -> &'static str {
        match self {
            HttpProtocolConfig::Http1 { .. } => "http/1.1",
            HttpProtocolConfig::Http2 { .. } => "h2",
            HttpProtocolConfig::Http3 { .. } => "h3",
            HttpProtocolConfig::Http1OverQuic { .. } => "http/1.1-over-quic",
        }
    }

    /// Check if this protocol requires TLS
    pub fn requires_tls(&self) -> bool {
        match self {
            HttpProtocolConfig::Http1 { .. } => false,
            HttpProtocolConfig::Http2 { .. } => true,
            HttpProtocolConfig::Http3 { .. } => true,
            HttpProtocolConfig::Http1OverQuic { .. } => true,
        }
    }

    /// Check if this protocol supports keep-alive/connection reuse
    pub fn supports_keep_alive(&self) -> bool {
        match self {
            HttpProtocolConfig::Http1 { keep_alive, .. } => *keep_alive,
            HttpProtocolConfig::Http2 { .. } => true, // HTTP/2 always supports multiplexing
            HttpProtocolConfig::Http3 { .. } => true, // HTTP/3 always supports multiplexing
            HttpProtocolConfig::Http1OverQuic { keep_alive, .. } => *keep_alive,
        }
    }
}

impl Default for HttpProtocolConfig {
    fn default() -> Self {
        HttpProtocolConfig::Http1 { keep_alive: true }
    }
}

/// HTTP authentication data for upstream proxy
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpAuthData {
    pub username: String,
    pub password: String,
}

/// HttpX connector configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpxConnectorConfig {
    /// Connector name
    pub name: String,
    /// Proxy server hostname
    pub server: String,
    /// Proxy server port
    pub port: u16,
    /// Protocol configuration (combines protocol selection and settings)
    pub protocol: HttpProtocolConfig,
    /// Enable HTTP forward proxy mode
    #[serde(default)]
    pub enable_forward_proxy: bool,
    /// Intercept WebSocket upgrades and route through CONNECT tunneling
    /// This prevents HTTP proxies from stripping WebSocket upgrade headers
    #[serde(default)]
    pub intercept_websocket_upgrades: bool,
    /// HTTP proxy authentication for upstream proxy
    pub auth: Option<HttpAuthData>,
    /// UDP protocol for legacy support
    pub udp_protocol: Option<UdpProtocol>,
    /// Connection pool configuration
    #[serde(default)]
    pub pool: PoolConfig,
    /// TLS configuration for HTTPS
    pub tls: Option<TlsClientConfig>,
    /// Connect timeout (in seconds)
    #[serde(default = "default_connect_timeout_secs")]
    pub connect_timeout_secs: u64,
    /// Resolve timeout (in seconds)
    #[serde(default = "default_resolve_timeout_secs")]
    pub resolve_timeout_secs: u64,
}

/// UDP protocol variants for legacy support
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UdpProtocol {
    /// RFC 9298 compliant
    Rfc9298,
    /// Legacy format
    Legacy,
    /// No UDP support
    None,
}

/// Unified HTTP connector supporting HTTP/1.1, HTTP/2, and HTTP/3
#[derive(Clone)]
pub struct HttpxConnector<S = crate::common::socket_ops::RealSocketOps>
where
    S: SocketOps,
{
    config: HttpxConnectorConfig,
    socket_ops: Arc<S>,
    // Connection pools for different protocols
    h1_pool: Option<Arc<DefaultConnectionPool<Http1ConnectionManager>>>,
    h2_pool: Option<Arc<DefaultConnectionPool<Http2ConnectionManager>>>,
}

impl<S: SocketOps> std::fmt::Debug for HttpxConnector<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpxConnector")
            .field("config", &self.config)
            .field("h1_pool", &self.h1_pool.as_ref().map(|_| "<pool>"))
            .field("h2_pool", &self.h2_pool.as_ref().map(|_| "<pool>"))
            .finish()
    }
}

impl<S: SocketOps> HttpxConnector<S> {
    /// Create new HttpX connector
    pub fn new(config: HttpxConnectorConfig, socket_ops: Arc<S>) -> Self {
        // Initialize connection pools based on protocol and pool config
        let h1_pool = if matches!(
            config.protocol,
            HttpProtocolConfig::Http1 { .. } | HttpProtocolConfig::Http1OverQuic { .. }
        ) && config.pool.enable
        {
            let pool_config = crate::common::connection_pool::PoolConfig {
                max_connections_per_host: config.pool.max_connections as u32,
                max_total_connections: (config.pool.max_connections * 10) as u32,
                max_idle_time: Duration::from_secs(config.pool.idle_timeout_secs),
                max_lifetime: Duration::from_secs(300),
                cleanup_interval: Duration::from_secs(30),
                max_requests_per_connection: Some(100),
            };
            Some(Arc::new(DefaultConnectionPool::new(
                pool_config,
                Http1ConnectionManager::new(config.clone()),
            )))
        } else {
            None
        };

        let h2_pool =
            if matches!(config.protocol, HttpProtocolConfig::Http2 { .. }) && config.pool.enable {
                let pool_config = crate::common::connection_pool::PoolConfig {
                    max_connections_per_host: config.pool.max_connections as u32,
                    max_total_connections: (config.pool.max_connections * 10) as u32,
                    max_idle_time: Duration::from_secs(config.pool.idle_timeout_secs),
                    max_lifetime: Duration::from_secs(300),
                    cleanup_interval: Duration::from_secs(30),
                    max_requests_per_connection: None, // HTTP/2 uses multiplexing
                };
                Some(Arc::new(DefaultConnectionPool::new(
                    pool_config,
                    Http2ConnectionManager::new(config.clone()),
                )))
            } else {
                None
            };

        Self {
            config,
            socket_ops,
            h1_pool,
            h2_pool,
        }
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<()> {
        // Check if TLS is required but not configured
        if self.config.protocol.requires_tls() && self.config.tls.is_none() {
            bail!(
                "{} requires TLS configuration",
                self.config.protocol.protocol_id()
            );
        }
        Ok(())
    }

    /// Connect using HTTP/1.1 protocol
    async fn connect_http1(&self, ctx: ContextRef, target: &TargetAddress) -> Result<()> {
        debug!(
            "{}: Connecting via HTTP/1.1 to {} using proxy {}:{}",
            self.config.name, target, self.config.server, self.config.port
        );

        // Check if this is a CONNECT request or WebSocket upgrade to determine handling mode
        // If no HTTP request exists (e.g., from reverse proxy), use CONNECT tunneling
        let is_connect = {
            let ctx_read = ctx.read().await;
            ctx_read
                .http_request()
                .map(|req| {
                    // Use CONNECT tunneling for:
                    // 1. Explicit CONNECT requests
                    // 2. WebSocket upgrade requests (if interception is enabled)
                    req.is_connect()
                        || (self.config.intercept_websocket_upgrades && req.is_websocket_upgrade())
                })
                .unwrap_or(true) // Default to CONNECT for non-HTTP traffic (e.g., reverse proxy)
        };

        // Use connection pool if enabled (for forward proxy only, CONNECT needs fresh connections)
        if let Some(pool) = &self.h1_pool
            && !is_connect
        {
            debug!(
                "{}: Using HTTP/1.1 connection pool for forward proxy to {}",
                self.config.name, target
            );

            // Try to get a pooled connection to proxy server (not target!)
            let proxy_target =
                TargetAddress::DomainPort(self.config.server.clone(), self.config.port);
            let connection = pool.get(&proxy_target, ctx.clone()).await?;

            // Set HTTP context properties and store server stream
            {
                let mut ctx_write = ctx.write().await;
                ctx_write.set_server_stream(connection);

                // Configure HTTP/1.1 context properties for forward proxy
                ctx_write
                    .set_http_protocol(self.config.protocol.protocol_id())
                    .set_http_forward_proxy(self.config.enable_forward_proxy)
                    .set_http_keep_alive(self.config.protocol.supports_keep_alive());

                // Set auth in context if available
                if let Some(auth_data) = &self.config.auth {
                    ctx_write
                        .set_extra("proxy_auth_username", &auth_data.username)
                        .set_extra("proxy_auth_password", &auth_data.password);
                }

                // Set connection pool key for reuse
                let pool_key = format!(
                    "{}://{}:{}",
                    if self.config.tls.is_some() {
                        "https"
                    } else {
                        "http"
                    },
                    self.config.server,
                    self.config.port
                );
                ctx_write.set_http_pool_key(&pool_key);

                // Configure limits
                if let Ok(max_requests) = self.config.pool.max_connections.try_into() {
                    ctx_write.set_http_max_requests(max_requests);
                }
            }

            info!(
                "{}: HTTP/1.1 pooled forward proxy connection established to {}:{}",
                self.config.name, self.config.server, self.config.port
            );
            return Ok(());
        }

        // Direct connection to proxy server (not target!)
        let socket_ops = self.socket_ops.as_ref();
        let addrs = socket_ops.resolve(&self.config.server).await?;
        let server_addr = addrs
            .first()
            .ok_or_else(|| anyhow!("No address found for proxy server {}", self.config.server))?;
        let proxy_addr = std::net::SocketAddr::new(*server_addr, self.config.port);

        debug!(
            "{}: Connecting to proxy server at {}",
            self.config.name, proxy_addr
        );
        let (stream, _local_addr, _peer_addr) = socket_ops.tcp_connect(proxy_addr, None).await?;

        let stream = if let Some(tls_config) = &self.config.tls {
            debug!(
                "{}: Performing TLS handshake for HTTP/1.1 proxy connection",
                self.config.name
            );
            self.socket_ops
                .tls_handshake_client(stream, &self.config.server, tls_config)
                .await?
        } else {
            stream
        };

        // Handle CONNECT tunneling through proxy
        if is_connect {
            debug!(
                "{}: Establishing CONNECT tunnel through proxy to {}",
                self.config.name, target
            );

            // Create buffered stream for CONNECT negotiation
            let mut buffered_stream = make_buffered_stream(stream);

            // Send CONNECT request to proxy
            let connect_request = if let Some(auth_data) = &self.config.auth {
                use base64::{engine::general_purpose::STANDARD, Engine};
                let credentials = format!("{}:{}", auth_data.username, auth_data.password);
                let encoded = STANDARD.encode(credentials.as_bytes());
                format!(
                    "CONNECT {} HTTP/1.1\r\nHost: {}\r\nProxy-Authorization: Basic {}\r\n\r\n",
                    target, target, encoded
                )
            } else {
                format!("CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n", target, target)
            };

            use tokio::io::AsyncWriteExt;
            buffered_stream
                .write_all(connect_request.as_bytes())
                .await?;
            buffered_stream.flush().await?;

            // Read CONNECT response from proxy
            use tokio::io::AsyncBufReadExt;
            let mut response_line = String::new();
            buffered_stream.read_line(&mut response_line).await?;

            if !response_line.contains("200") {
                return Err(anyhow!(
                    "CONNECT tunnel establishment failed: {}",
                    response_line.trim()
                ));
            }

            // Skip response headers until empty line
            loop {
                let mut header_line = String::new();
                buffered_stream.read_line(&mut header_line).await?;
                if header_line.trim().is_empty() || header_line == "\r\n" {
                    break;
                }
            }

            debug!(
                "{}: CONNECT tunnel established through proxy",
                self.config.name
            );

            // Set HTTP context properties for CONNECT tunnel
            {
                let mut ctx_write = ctx.write().await;
                ctx_write.set_server_stream(buffered_stream);

                // Configure for CONNECT tunnel (not forward proxy)
                ctx_write
                    .set_http_protocol(self.config.protocol.protocol_id())
                    .set_http_forward_proxy(false) // CONNECT tunnel, not forward proxy
                    .set_http_keep_alive(false); // CONNECT doesn't support keep-alive
            }
        } else {
            // Set HTTP context properties for forward proxy
            {
                let mut ctx_write = ctx.write().await;
                ctx_write.set_server_stream(make_buffered_stream(stream));

                // Configure HTTP/1.1 context properties for forward proxy
                ctx_write
                    .set_http_protocol(self.config.protocol.protocol_id())
                    .set_http_forward_proxy(self.config.enable_forward_proxy)
                    .set_http_keep_alive(self.config.protocol.supports_keep_alive());

                // Set auth in context if available
                if let Some(auth_data) = &self.config.auth {
                    ctx_write
                        .set_extra("proxy_auth_username", &auth_data.username)
                        .set_extra("proxy_auth_password", &auth_data.password);
                }

                // Set connection pool key for reuse (based on proxy, not target)
                let pool_key = format!(
                    "{}://{}:{}",
                    if self.config.tls.is_some() {
                        "https"
                    } else {
                        "http"
                    },
                    self.config.server,
                    self.config.port
                );
                ctx_write.set_http_pool_key(&pool_key);

                // Configure limits
                if let Ok(max_requests) = self.config.pool.max_connections.try_into() {
                    ctx_write.set_http_max_requests(max_requests);
                }
            }
        }

        info!(
            "{}: HTTP/1.1 connection established to proxy {}:{}",
            self.config.name, self.config.server, self.config.port
        );
        Ok(())
    }

    /// Connect using HTTP/2 protocol
    async fn connect_http2(&self, ctx: ContextRef, target: &TargetAddress) -> Result<()> {
        debug!("{}: Connecting via HTTP/2 to {}", self.config.name, target);

        // Set HTTP/2 context properties for when implementation is complete
        {
            let mut ctx_write = ctx.write().await;
            ctx_write
                .set_http_protocol(self.config.protocol.protocol_id())
                .set_http_forward_proxy(self.config.enable_forward_proxy)
                .set_http_keep_alive(self.config.protocol.supports_keep_alive());

            // Set HTTP/2 specific properties from protocol config
            if let HttpProtocolConfig::Http2 {
                max_concurrent_streams,
                ..
            } = &self.config.protocol
                && let Some(max_streams) = max_concurrent_streams
            {
                ctx_write.set_http2_max_concurrent_streams(*max_streams);
            }

            // Set connection pool key
            let pool_key = format!("h2://{}", target);
            ctx_write.set_http_pool_key(&pool_key);
        }

        // TODO: Implement HTTP/2 connection with h2 crate
        todo!("HTTP/2 connector implementation with h2 crate and connection pooling");
    }

    /// Connect using HTTP/3 protocol
    async fn connect_http3(&self, ctx: ContextRef, target: &TargetAddress) -> Result<()> {
        debug!("{}: Connecting via HTTP/3 to {}", self.config.name, target);

        // Set HTTP/3 context properties for when implementation is complete
        {
            let mut ctx_write = ctx.write().await;
            ctx_write
                .set_http_protocol(self.config.protocol.protocol_id())
                .set_http_forward_proxy(self.config.enable_forward_proxy)
                .set_http_keep_alive(self.config.protocol.supports_keep_alive());

            // Set HTTP/3 specific properties from protocol config
            if let HttpProtocolConfig::Http3 { quic } = &self.config.protocol
                && let Some(quic_config) = quic
                && let Some(max_bi_streams) = quic_config.max_bi_streams
            {
                ctx_write.set_http3_max_bi_streams(max_bi_streams);
            }

            // Set connection pool key
            let pool_key = format!("h3://{}", target);
            ctx_write.set_http_pool_key(&pool_key);
        }

        // TODO: Implement HTTP/3 connection with h3/quinn crates
        todo!("HTTP/3 connector implementation with h3/quinn crates");
    }

    /// Connect using HTTP/1.1 over QUIC (legacy)
    async fn connect_h1_over_quic(&self, ctx: ContextRef, target: &TargetAddress) -> Result<()> {
        debug!(
            "{}: Connecting via HTTP/1.1 over QUIC to {}",
            self.config.name, target
        );

        // Set HTTP/1.1 over QUIC context properties
        {
            let mut ctx_write = ctx.write().await;
            ctx_write
                .set_http_protocol(self.config.protocol.protocol_id())
                .set_http_forward_proxy(self.config.enable_forward_proxy)
                .set_http_keep_alive(self.config.protocol.supports_keep_alive());

            // Set connection pool key
            let pool_key = format!("h1-quic://{}", target);
            ctx_write.set_http_pool_key(&pool_key);
        }

        // TODO: Implement HTTP/1.1 over QUIC for legacy compatibility
        todo!("HTTP/1.1 over QUIC connector implementation for legacy support");
    }
}

#[async_trait::async_trait]
impl<S: SocketOps + Send + Sync + 'static> Connector for HttpxConnector<S> {
    fn name(&self) -> &str {
        &self.config.name
    }

    async fn connect(self: Arc<Self>, ctx: ContextRef) -> Result<()> {
        let target = {
            let ctx_guard = ctx.read().await;
            ctx_guard.target().clone()
        };

        debug!(
            "{}: Connecting to {} using protocol {}",
            self.config.name,
            target,
            self.config.protocol.protocol_id()
        );

        // Route to appropriate protocol handler
        match &self.config.protocol {
            HttpProtocolConfig::Http1 { .. } => self.connect_http1(ctx.clone(), &target).await?,
            HttpProtocolConfig::Http2 { .. } => self.connect_http2(ctx.clone(), &target).await?,
            HttpProtocolConfig::Http3 { .. } => self.connect_http3(ctx.clone(), &target).await?,
            HttpProtocolConfig::Http1OverQuic { .. } => {
                self.connect_h1_over_quic(ctx.clone(), &target).await?
            }
        }

        // Note: ctx.on_connect() is called by server.rs:460, not here
        // Removed duplicate call that was causing duplicate HTTP headers

        Ok(())
    }
}

// Connection manager placeholders for pooling
#[derive(Debug)]
struct Http1ConnectionManager {
    config: HttpxConnectorConfig,
}

impl Http1ConnectionManager {
    fn new(config: HttpxConnectorConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl ConnectionManager for Http1ConnectionManager {
    type Connection = IOBufStream;
    type Key = TargetAddress;

    async fn create(&self, _key: &Self::Key, _ctx: ContextRef) -> Result<Self::Connection> {
        // For httpx connector, we connect to the configured HTTP proxy server, not the target
        // The key represents the target, but we always connect to the proxy server
        debug!(
            "HTTP/1.1 Pool: Connecting to proxy {}:{}",
            self.config.server, self.config.port
        );

        // Use socket_ops to resolve the proxy server address and connect
        let socket_ops = Arc::new(crate::common::socket_ops::RealSocketOps);

        // Resolve the proxy server hostname to IP address
        let addrs = socket_ops.resolve(&self.config.server).await?;
        let server_addr = addrs
            .first()
            .ok_or_else(|| anyhow!("No address found for proxy server {}", self.config.server))?;
        let proxy_addr = std::net::SocketAddr::new(*server_addr, self.config.port);

        let (stream, _local_addr, _peer_addr) = socket_ops.tcp_connect(proxy_addr, None).await?;

        let stream = if let Some(tls_config) = &self.config.tls {
            debug!(
                "HTTP/1.1 Pool: Performing TLS handshake for proxy {}:{}",
                self.config.server, self.config.port
            );
            // For TLS, we use the proxy server hostname, not the target hostname
            let proxy_host = &self.config.server;
            socket_ops
                .tls_handshake_client(stream, proxy_host, tls_config)
                .await?
        } else {
            stream
        };

        debug!(
            "HTTP/1.1 Pool: Created new connection to proxy {}:{}",
            self.config.server, self.config.port
        );
        Ok(make_buffered_stream(stream))
    }

    async fn is_valid(&self, _conn: &mut Self::Connection) -> Result<bool> {
        // For HTTP/1.1, we can't easily test without sending data
        // In a real implementation, we might send a lightweight request
        Ok(true)
    }

    async fn recycle(&self, _conn: &mut Self::Connection) -> Result<()> {
        // For HTTP/1.1, no special recycling needed
        Ok(())
    }

    fn is_reusable(&self, _conn: &Self::Connection) -> bool {
        // HTTP/1.1 connections are reusable with keep-alive
        self.config.protocol.supports_keep_alive()
    }

    fn max_requests_per_connection(&self, _conn: &Self::Connection) -> Option<u32> {
        // HTTP/1.1 can handle many requests sequentially
        Some(1000)
    }
}

impl Clone for Http1ConnectionManager {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
        }
    }
}

#[derive(Debug)]
struct Http2ConnectionManager {
    config: HttpxConnectorConfig,
}

impl Http2ConnectionManager {
    fn new(config: HttpxConnectorConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl ConnectionManager for Http2ConnectionManager {
    type Connection = IOBufStream;
    type Key = TargetAddress;

    async fn create(&self, _key: &Self::Key, _ctx: ContextRef) -> Result<Self::Connection> {
        todo!("HTTP/2 connection manager implementation")
    }

    async fn is_valid(&self, _conn: &mut Self::Connection) -> Result<bool> {
        // For HTTP/2, we could send a PING frame to check
        Ok(true)
    }

    async fn recycle(&self, _conn: &mut Self::Connection) -> Result<()> {
        // For HTTP/2, no special recycling needed (streams are independent)
        Ok(())
    }

    fn is_reusable(&self, _conn: &Self::Connection) -> bool {
        // HTTP/2 connections are highly reusable through multiplexing
        true
    }

    fn max_requests_per_connection(&self, _conn: &Self::Connection) -> Option<u32> {
        // HTTP/2 can handle many concurrent streams
        if let HttpProtocolConfig::Http2 {
            max_concurrent_streams,
            ..
        } = &self.config.protocol
        {
            *max_concurrent_streams
        } else {
            None
        }
    }
}

impl Clone for Http2ConnectionManager {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
        }
    }
}

// Helper functions for defaults
fn default_true() -> bool {
    true
}

fn default_pool_max_connections() -> usize {
    100
}

fn default_connect_timeout_secs() -> u64 {
    10
}

fn default_resolve_timeout_secs() -> u64 {
    5
}

fn default_pool_idle_timeout_secs() -> u64 {
    60
}

/// Create HttpX connector from configuration value
pub fn from_value(value: &serde_yaml_ng::Value) -> Result<ConnectorRef> {
    let config: HttpxConnectorConfig =
        serde_yaml_ng::from_value(value.clone()).with_context(|| "parse httpx connector config")?;

    let socket_ops = Arc::new(crate::common::socket_ops::RealSocketOps);
    let connector = HttpxConnector::new(config, socket_ops);
    connector.validate()?;

    Ok(Box::new(connector))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_protocol_config_defaults() {
        let config = HttpProtocolConfig::default();
        assert_eq!(config.protocol_id(), "http/1.1");
        assert!(config.supports_keep_alive());
        assert!(!config.requires_tls());
    }

    #[test]
    fn test_http_protocol_config_methods() {
        // Test H1 config
        let h1_config = HttpProtocolConfig::Http1 { keep_alive: false };
        assert_eq!(h1_config.protocol_id(), "http/1.1");
        assert!(!h1_config.supports_keep_alive());
        assert!(!h1_config.requires_tls());

        // Test H2 config
        let h2_config = HttpProtocolConfig::Http2 {
            max_concurrent_streams: Some(100),
            settings: None,
        };
        assert_eq!(h2_config.protocol_id(), "h2");
        assert!(h2_config.supports_keep_alive());
        assert!(h2_config.requires_tls());

        // Test H3 config
        let h3_config = HttpProtocolConfig::Http3 { quic: None };
        assert_eq!(h3_config.protocol_id(), "h3");
        assert!(h3_config.supports_keep_alive());
        assert!(h3_config.requires_tls());

        // Test H1OverQuic config
        let h1_quic_config = HttpProtocolConfig::Http1OverQuic {
            keep_alive: true,
            quic: None,
        };
        assert_eq!(h1_quic_config.protocol_id(), "http/1.1-over-quic");
        assert!(h1_quic_config.supports_keep_alive());
        assert!(h1_quic_config.requires_tls());
    }

    #[test]
    fn test_pool_config_defaults() {
        let config = PoolConfig::default();
        assert_eq!(config.max_connections, 100);
        assert_eq!(config.idle_timeout(), Duration::from_secs(60));
        assert!(config.enable);
    }
}
