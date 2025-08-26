use crate::context::{ContextRef, IOStream};
use anyhow::Result;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

// Global session ID counter for UDP channels
static UDP_SESSION_ID: AtomicU32 = AtomicU32::new(1);

/// HTTP version enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpVersion {
    Http1,
    Http2,
    Http3,
}

impl fmt::Display for HttpVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpVersion::Http1 => write!(f, "HTTP/1.1"),
            HttpVersion::Http2 => write!(f, "HTTP/2"),
            HttpVersion::Http3 => write!(f, "HTTP/3"),
        }
    }
}

/// HTTP request method
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpMethod {
    Connect,
    Get,
    Post,
    Put,
    Delete,
    Head,
    Options,
    Patch,
    Trace,
    Other(String),
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpMethod::Connect => write!(f, "CONNECT"),
            HttpMethod::Get => write!(f, "GET"),
            HttpMethod::Post => write!(f, "POST"),
            HttpMethod::Put => write!(f, "PUT"),
            HttpMethod::Delete => write!(f, "DELETE"),
            HttpMethod::Head => write!(f, "HEAD"),
            HttpMethod::Options => write!(f, "OPTIONS"),
            HttpMethod::Patch => write!(f, "PATCH"),
            HttpMethod::Trace => write!(f, "TRACE"),
            HttpMethod::Other(s) => write!(f, "{}", s),
        }
    }
}

/// HTTP request information
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: HttpMethod,
    pub uri: String,
    pub version: HttpVersion,
    pub headers: Vec<(String, String)>,
    pub host: Option<String>,
    pub port: Option<u16>,
}

impl HttpRequest {
    pub fn new(method: HttpMethod, uri: String, version: HttpVersion) -> Self {
        Self {
            method,
            uri,
            version,
            headers: Vec::new(),
            host: None,
            port: None,
        }
    }

    pub fn add_header(&mut self, name: String, value: String) {
        self.headers.push((name, value));
    }

    pub fn get_header(&self, name: &str) -> Option<&String> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v)
    }

    pub fn is_connect(&self) -> bool {
        self.method == HttpMethod::Connect
    }

    pub fn is_websocket_upgrade(&self) -> bool {
        self.get_header("upgrade")
            .map(|v| v.eq_ignore_ascii_case("websocket"))
            .unwrap_or(false)
            && self
                .get_header("connection")
                .map(|v| v.to_lowercase().contains("upgrade"))
                .unwrap_or(false)
    }
}

/// HTTP response information
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub version: HttpVersion,
    pub status_code: u16,
    pub reason_phrase: String,
    pub headers: Vec<(String, String)>,
}

impl HttpResponse {
    pub fn new(version: HttpVersion, status_code: u16, reason_phrase: String) -> Self {
        Self {
            version,
            status_code,
            reason_phrase,
            headers: Vec::new(),
        }
    }

    pub fn add_header(&mut self, name: String, value: String) {
        self.headers.push((name, value));
    }

    pub fn ok(version: HttpVersion) -> Self {
        Self::new(version, 200, "OK".to_string())
    }

    pub fn tunnel_established(version: HttpVersion) -> Self {
        Self::new(version, 200, "Connection established".to_string())
    }
}

/// UDP proxying mode for HTTP streams
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpMode {
    /// No UDP support
    None,
    /// Inline UDP within HTTP stream
    Inline,
    /// RFC 9298: UDP over HTTP CONNECT
    Rfc9298,
    /// External UDP channel (custom framing)
    External,
}

/// Handle for a UDP channel with proper lifecycle management
#[derive(Debug, Clone)]
pub struct UdpChannelHandle {
    /// Unique session ID for this UDP channel
    pub session_id: u32,
    /// The UDP mode used for this channel
    pub mode: UdpMode,
    /// Whether the channel is currently active
    pub is_active: bool,
}

impl UdpChannelHandle {
    fn new(mode: UdpMode) -> Self {
        Self {
            session_id: UDP_SESSION_ID.fetch_add(1, Ordering::Relaxed),
            mode,
            is_active: true,
        }
    }

    /// Mark the channel as closed
    pub fn close(&mut self) {
        self.is_active = false;
    }
}

/// Abstraction over different HTTP protocol streams
#[async_trait::async_trait]
pub trait HttpStream: IOStream {
    /// Get the HTTP version of this stream
    fn version(&self) -> HttpVersion;

    /// Check if the stream supports multiplexing (HTTP/2, HTTP/3)
    fn supports_multiplexing(&self) -> bool {
        matches!(self.version(), HttpVersion::Http2 | HttpVersion::Http3)
    }

    /// Check if the stream is reusable for additional requests
    fn is_reusable(&self) -> bool {
        self.supports_multiplexing()
    }

    /// Get supported UDP modes for this stream
    fn supported_udp_modes(&self) -> &[UdpMode];

    /// Create a UDP channel for external UDP proxying
    /// Returns a handle with the session ID and channel info
    async fn create_udp_channel(&mut self) -> Result<UdpChannelHandle>;

    /// Close a specific UDP channel
    async fn close_udp_channel(&mut self, session_id: u32) -> Result<()>;

    /// Check if a UDP channel exists and is active
    fn has_udp_channel(&self, session_id: u32) -> bool;

    /// Send an HTTP response
    async fn send_response(&mut self, response: &HttpResponse) -> Result<()>;

    /// Read the next HTTP request (for server-side streams)
    async fn read_request(&mut self) -> Result<Option<HttpRequest>>;

    /// Send an HTTP request (for client-side streams)
    async fn send_request(&mut self, request: &HttpRequest) -> Result<()>;

    /// Read an HTTP response (for client-side streams)
    async fn read_response(&mut self) -> Result<HttpResponse>;

    /// Upgrade the stream for tunneling (after CONNECT)
    /// Returns raw IOStream for data copying, no longer HTTP
    async fn upgrade_to_tunnel(self: Box<Self>) -> Result<Box<dyn IOStream>>;

    /// Get the underlying connection info (peer address, etc.)
    fn connection_info(&self) -> ConnectionInfo;
}

/// Connection information
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub peer_addr: std::net::SocketAddr,
    pub local_addr: std::net::SocketAddr,
    pub tls_info: Option<TlsInfo>,
}

/// TLS connection information
#[derive(Debug, Clone)]
pub struct TlsInfo {
    pub server_name: Option<String>,
    pub alpn_protocol: Option<String>,
    pub cipher_suite: Option<String>,
}

/// Protocol-specific handler for HTTP versions
#[async_trait::async_trait]
pub trait HttpProtocolHandler: Send + Sync {
    /// The stream type this handler produces
    type Stream: HttpStream;

    /// Get the HTTP version this handler supports
    fn version(&self) -> HttpVersion;

    /// Accept an incoming connection and create a stream
    async fn accept_stream(&self, conn: Box<dyn IOStream>, ctx: ContextRef)
    -> Result<Self::Stream>;

    /// Create an outgoing connection stream
    async fn connect_stream(
        &self,
        target: &str,
        port: u16,
        ctx: ContextRef,
    ) -> Result<Self::Stream>;

    /// Perform protocol-specific handshake for listeners
    async fn listener_handshake(
        &self,
        stream: &mut Self::Stream,
        ctx: ContextRef,
    ) -> Result<HttpRequest>;

    /// Perform protocol-specific handshake for connectors
    async fn connector_handshake(
        &self,
        stream: &mut Self::Stream,
        request: &HttpRequest,
        ctx: ContextRef,
    ) -> Result<HttpResponse>;

    /// Handle forward proxy requests (non-CONNECT)
    async fn handle_forward_proxy(
        &self,
        stream: &mut Self::Stream,
        request: &HttpRequest,
        ctx: ContextRef,
    ) -> Result<()>;

    /// Check if this handler can handle the given ALPN protocol
    fn matches_alpn(&self, alpn: &str) -> bool;

    /// Get ALPN protocols this handler supports
    fn alpn_protocols(&self) -> &[&str];
}

// Type aliases to reduce trait object complexity
type HttpStreamBox = Box<dyn HttpStream>;
type HttpHandlerArc = Arc<dyn HttpProtocolHandler<Stream = HttpStreamBox>>;

/// Factory for creating protocol handlers
pub trait HttpProtocolHandlerFactory: Send + Sync {
    /// Create handler for the given ALPN protocol string
    fn create_handler_for_alpn(&self, alpn: &str) -> Result<HttpHandlerArc>;

    /// Get list of supported ALPN protocol strings
    fn supported_alpn_protocols(&self) -> &[&'static str];

    /// Legacy method for backward compatibility
    fn select_by_alpn(&self, alpn: &str) -> Option<HttpHandlerArc> {
        self.create_handler_for_alpn(alpn).ok()
    }
}
