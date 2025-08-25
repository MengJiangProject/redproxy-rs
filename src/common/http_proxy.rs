use anyhow::{Context as AnyhowContext, Error, Result, anyhow, bail};
use async_trait::async_trait;
use futures::Future;
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc::Sender;
use tracing::{trace, warn};
use url::Url;

// Helper function to encode credentials in base64
fn encode_basic_auth(username: &str, password: &str) -> String {
    use base64::Engine;
    let credentials = format!("{}:{}", username, password);
    base64::engine::general_purpose::STANDARD.encode(credentials.as_bytes())
}

// Helper function to decode and validate basic auth credentials
fn decode_basic_auth(auth_header: &str) -> Option<(String, String)> {
    use base64::Engine;
    if !auth_header.starts_with("Basic ") {
        return None;
    }

    let encoded = &auth_header[6..]; // Skip "Basic "
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    let credentials = String::from_utf8(decoded).ok()?;

    if let Some((username, password)) = credentials.split_once(':') {
        Some((username.to_string(), password.to_string()))
    } else {
        None
    }
}

use crate::{
    common::{
        auth::AuthData,
        http::{HttpRequest, HttpResponse},
    },
    context::{
        Context, ContextCallback, ContextRef, ContextRefOps, Feature, IOBufStream, TargetAddress,
    },
};

use super::frames::{FrameIO, frames_from_stream};

/// Extension trait for Context to add HTTP proxy-specific configuration methods
pub trait HttpProxyContextExt {
    /// Set the frame channel for proxy connections
    fn set_proxy_frame_channel(&mut self, channel: &str) -> &mut Self;
    /// Get the frame channel for proxy connections
    fn proxy_frame_channel(&self) -> Option<&str>;

    /// Set whether to force CONNECT tunneling for HTTP requests
    fn set_proxy_force_connect(&mut self, force_connect: bool) -> &mut Self;
    /// Get whether to force CONNECT tunneling for HTTP requests
    fn proxy_force_connect(&self) -> bool;

    /// Set the UDP protocol to use ("custom" or "rfc9298")
    fn set_proxy_udp_protocol(&mut self, protocol: &str) -> &mut Self;
    /// Get the UDP protocol to use
    fn proxy_udp_protocol(&self) -> Option<&str>;

    /// Set the RFC 9298 URI template for custom servers
    fn set_proxy_rfc9298_uri_template(&mut self, template: &str) -> &mut Self;
    /// Get the RFC 9298 URI template
    fn proxy_rfc9298_uri_template(&self) -> Option<&str>;
}

impl HttpProxyContextExt for Context {
    fn set_proxy_frame_channel(&mut self, channel: &str) -> &mut Self {
        self.set_extra("proxy_frame_channel", channel)
    }

    fn proxy_frame_channel(&self) -> Option<&str> {
        self.extra("proxy_frame_channel")
    }

    fn set_proxy_force_connect(&mut self, force_connect: bool) -> &mut Self {
        self.set_extra("proxy_force_connect", force_connect.to_string())
    }

    fn proxy_force_connect(&self) -> bool {
        self.extra("proxy_force_connect")
            .and_then(|s| s.parse().ok())
            .unwrap_or(false)
    }

    fn set_proxy_udp_protocol(&mut self, protocol: &str) -> &mut Self {
        self.set_extra("proxy_udp_protocol", protocol)
    }

    fn proxy_udp_protocol(&self) -> Option<&str> {
        self.extra("proxy_udp_protocol")
    }

    fn set_proxy_rfc9298_uri_template(&mut self, template: &str) -> &mut Self {
        self.set_extra("proxy_rfc9298_uri_template", template)
    }

    fn proxy_rfc9298_uri_template(&self) -> Option<&str> {
        self.extra("proxy_rfc9298_uri_template")
    }
}

// Helper function to check if a request is a WebSocket upgrade
pub fn is_websocket_upgrade(request: &HttpRequest) -> bool {
    let connection = request.header("Connection", "").to_lowercase();
    let upgrade = request.header("Upgrade", "").to_lowercase();

    // Check if Connection header contains "upgrade" as a separate token
    let has_upgrade_connection = connection.split(',').any(|token| token.trim() == "upgrade");

    // Check if Upgrade header is exactly "websocket"
    let has_websocket_upgrade = upgrade == "websocket";

    has_upgrade_connection && has_websocket_upgrade
}

// Helper function to send error response to client
pub async fn send_error_response(
    client_stream: &mut IOBufStream,
    status_code: u16,
    status_text: &str,
    error_message: &str,
) -> Result<()> {
    let response = HttpResponse::new(status_code, status_text)
        .with_header("Content-Type", "text/plain")
        .with_header("Connection", "close")
        .with_header("Content-Length", error_message.len().to_string());

    response
        .write_with_body(client_stream, error_message.as_bytes())
        .await
        .context("Failed to send error response to client")
}

// Helper function to send simple error response without body
pub async fn send_simple_error_response(
    client_stream: &mut IOBufStream,
    status_code: u16,
    status_text: &str,
) -> Result<()> {
    HttpResponse::new(status_code, status_text)
        .with_header("Connection", "close")
        .write_to(client_stream)
        .await
        .context("Failed to send simple error response to client")
}

pub async fn http_forward_proxy_connect<T1, T2>(
    mut server: IOBufStream,
    ctx: ContextRef,
    frame_fn: T1,
) -> Result<()>
where
    T1: FnOnce(u32) -> T2 + Sync,
    T2: Future<Output = FrameIO>,
{
    let (
        target,
        feature,
        local,
        remote,
        frame_channel,
        force_connect,
        udp_protocol,
        rfc9298_uri_template,
        auth,
    ) = {
        let ctx_read = ctx.read().await;
        let auth = ctx_read.extra("proxy_auth_username").and_then(|username| {
            ctx_read
                .extra("proxy_auth_password")
                .map(|password| (username.to_string(), password.to_string()))
        });
        (
            ctx_read.target(),
            ctx_read.feature(),
            ctx_read.local_addr(),
            ctx_read.server_addr(),
            ctx_read
                .proxy_frame_channel()
                .unwrap_or("inline")
                .to_string(),
            ctx_read.proxy_force_connect(),
            ctx_read.proxy_udp_protocol().map(|s| s.to_string()),
            ctx_read.proxy_rfc9298_uri_template().map(|s| s.to_string()),
            auth,
        )
    };

    tracing::trace!(
        "http_forward_proxy_connect: channel={}, force_connect={}",
        frame_channel,
        force_connect
    );
    match feature {
        Feature::TcpForward => {
            // Check if we have a stored HTTP request (GET, POST, etc.)
            let has_http_request = ctx.read().await.http_request().is_some();

            if has_http_request && !force_connect {
                // HTTP forwarding - no CONNECT handshake needed
                // The server stream is already connected to the target origin server
                // HttpForwardCallback will handle writing the request and reading the response
                ctx.write()
                    .await
                    .set_server_stream(server)
                    .set_local_addr(local)
                    .set_server_addr(remote);
            } else {
                // Traditional CONNECT tunneling (either forced or no HTTP request)
                let mut request = HttpRequest::new("CONNECT", &target).with_header("Host", &target);

                // Add Proxy-Authorization header if auth is provided
                if let Some((username, password)) = &auth {
                    let encoded = encode_basic_auth(username, password);
                    request =
                        request.with_header("Proxy-Authorization", format!("Basic {}", encoded));
                }

                request.write_to(&mut server).await?;
                let resp = HttpResponse::read_from(&mut server).await?;
                if resp.code != 200 {
                    bail!("upstream server failure: {:?}", resp);
                }
                ctx.write()
                    .await
                    .set_server_stream(server)
                    .set_local_addr(local)
                    .set_server_addr(remote);
            }
        }
        Feature::UdpForward | Feature::UdpBind => {
            // Check if using RFC 9298 or custom protocol
            if udp_protocol.as_deref() == Some("rfc9298") {
                // RFC 9298 HTTP/1.1 upgrade approach
                let uri_template =
                    generate_rfc9298_uri_from_template(&target, rfc9298_uri_template.as_deref());
                let mut request = HttpRequest::new("GET", &uri_template)
                    .with_header(
                        "Host",
                        format!(
                            "{}:{}",
                            match &target {
                                TargetAddress::DomainPort(host, _) => host.clone(),
                                TargetAddress::SocketAddr(addr) => addr.ip().to_string(),
                                TargetAddress::Unknown => "unknown".to_string(),
                            },
                            remote.port()
                        ),
                    )
                    .with_header("Connection", "Upgrade")
                    .with_header("Upgrade", "connect-udp");

                // Add Proxy-Authorization header if auth is provided
                if let Some((username, password)) = &auth {
                    let encoded = encode_basic_auth(username, password);
                    request =
                        request.with_header("Proxy-Authorization", format!("Basic {}", encoded));
                }

                request.write_to(&mut server).await?;
                let resp = HttpResponse::read_from(&mut server).await?;
                tracing::trace!("RFC 9298 response: {:?}", resp);

                if resp.code != 101 {
                    bail!(
                        "RFC 9298 upgrade failed - expected 101 Switching Protocols, got {}: {:?}",
                        resp.code,
                        resp
                    );
                }

                // Verify upgrade headers
                if !resp
                    .header("Connection", "")
                    .to_lowercase()
                    .contains("upgrade")
                    || !resp
                        .header("Upgrade", "")
                        .eq_ignore_ascii_case("connect-udp")
                {
                    bail!("RFC 9298 upgrade response missing proper headers");
                }

                let session_id = SESSION_ID.fetch_add(1, Ordering::Relaxed);
                ctx.write()
                    .await
                    .set_server_frames(super::frames::rfc9298_frames_from_stream(
                        session_id, server,
                    ))
                    .set_local_addr(local)
                    .set_server_addr(remote);
            } else {
                // Custom protocol (existing behavior)
                let mut request = HttpRequest::new("CONNECT", &target)
                    .with_header("Host", &target)
                    .with_header("Proxy-Protocol", "udp")
                    .with_header("Proxy-Channel", &frame_channel);

                // Add Proxy-Authorization header if auth is provided
                if let Some((username, password)) = &auth {
                    let encoded = encode_basic_auth(username, password);
                    request =
                        request.with_header("Proxy-Authorization", format!("Basic {}", encoded));
                }

                if feature == Feature::UdpBind {
                    let bind_src = ctx
                        .read()
                        .await
                        .extra("udp-bind-source")
                        .unwrap()
                        .to_owned();
                    request = request.with_header("Udp-Bind-Source", bind_src);
                }

                request.write_to(&mut server).await?;
                let resp = HttpResponse::read_from(&mut server).await?;
                tracing::trace!("Custom protocol response: {:?}", resp);
                if resp.code != 200 {
                    bail!("upstream server failure: {:?}", resp);
                }
                let session_id = resp.header("Session-Id", "0").parse().unwrap();
                ctx.write()
                    .await
                    .set_server_frames(if frame_channel.eq_ignore_ascii_case("inline") {
                        frames_from_stream(session_id, server)
                    } else {
                        frame_fn(session_id).await
                    })
                    .set_local_addr(local)
                    .set_server_addr(remote);
            }
        }
        x => bail!("not supported feature {:?}", x),
    };
    Ok(())
}

static SESSION_ID: AtomicU32 = AtomicU32::new(0);
// Global proxy identifier for this instance (for loop detection in Via header)
static PROXY_ID: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Get the proxy identifier for this instance (initialized once on first call)
fn get_proxy_id() -> &'static str {
    PROXY_ID.get_or_init(generate_proxy_id)
}

// HTTP 1.1 proxy protocol handlers
// used by http and quic listeners and connectors
pub async fn http_forward_proxy_handshake<FrameFn, T2>(
    ctx: ContextRef,
    queue: Sender<ContextRef>,
    create_frames: FrameFn,
    auth: Option<AuthData>,
) -> Result<()>
where
    FrameFn: FnOnce(&str, u32) -> T2 + Sync,
    T2: Future<Output = Result<FrameIO>>,
{
    let mut ctx_lock = ctx.write().await;
    let local_addr = ctx_lock.local_addr(); // Get local addr before borrowing socket
    let socket = ctx_lock.borrow_client_stream().unwrap();
    let request = HttpRequest::read_from(socket).await?;
    tracing::trace!("request={:?}", request);

    // Check authentication if required
    if let Some(ref auth_data) = auth {
        // Look for Proxy-Authorization or Authorization header
        let auth_header = request.header("Proxy-Authorization", "");
        let auth_header = if auth_header.is_empty() {
            request.header("Authorization", "")
        } else {
            auth_header
        };

        let user_credentials = if !auth_header.is_empty() {
            decode_basic_auth(auth_header)
        } else {
            None
        };

        if !auth_data.check(&user_credentials).await {
            if let Err(e) =
                send_simple_error_response(socket, 407, "Proxy Authentication Required").await
            {
                warn!("Failed to send authentication required response: {}", e);
            }
            bail!("Client authentication failed");
        }
    }

    // After authentication, check for proxy loops for all requests
    let proxy_id = get_proxy_id();
    if let Err(e) = check_proxy_loop(local_addr, &request, proxy_id) {
        if let Err(send_err) = send_error_response(socket, 503, "Service Unavailable", &format!("Proxy loop prevention: {}", e)).await {
            warn!("Failed to send loop prevention error response: {}", send_err);
        }
        return Err(e);
    }

    if request.method.eq_ignore_ascii_case("CONNECT") {
        let protocol = request.header("Proxy-Protocol", "tcp");
        let target = request
            .resource
            .parse()
            .with_context(|| format!("failed to parse target address: {}", request.resource))?;

        if protocol.eq_ignore_ascii_case("tcp") {
            ctx_lock
                .set_target(target)
                .set_callback(HttpConnectCallback);
        } else if protocol.eq_ignore_ascii_case("udp") {
            let session_id = SESSION_ID.fetch_add(1, Ordering::Relaxed);
            let channel = request.header("Proxy-Channel", "inline");
            let inline = channel.eq_ignore_ascii_case("inline");
            let source = request.header("Udp-Bind-Source", "");
            ctx_lock
                .set_target(target)
                .set_callback(FrameChannelCallback { session_id, inline });
            if source.is_empty() {
                ctx_lock.set_feature(Feature::UdpForward);
            } else {
                ctx_lock
                    .set_extra("udp-bind-source", source)
                    .set_feature(Feature::UdpBind);
            }

            if !inline {
                ctx_lock.set_client_frames(
                    create_frames(channel, session_id)
                        .await
                        .context("create frames")?,
                );
            }
        } else {
            if let Err(e) = send_simple_error_response(socket, 400, "Bad Request").await {
                warn!("Failed to send bad request response: {}", e);
            }
            bail!("Invalid request protocol: {}", protocol);
        }
    } else if request.method.eq_ignore_ascii_case("GET") {
        // Check for RFC 9298 UDP-over-HTTP upgrade
        let connection = request.header("Connection", "");
        let upgrade = request.header("Upgrade", "");

        if connection.to_lowercase().contains("upgrade")
            && upgrade.eq_ignore_ascii_case("connect-udp")
        {
            // RFC 9298 HTTP/1.1 UDP proxy upgrade
            drop(ctx_lock);
            return handle_rfc9298_upgrade(ctx, queue, request, create_frames).await;
        }

        // Fall through to regular HTTP forward proxy handling
        if let Err(e) = handle_http_forward_request(&mut ctx_lock, request) {
            // Get a fresh reference to the socket since we can't use the previous one
            let socket = ctx_lock.borrow_client_stream().unwrap();
            if let Err(send_err) = send_error_response(socket, 400, "Bad Request", &e.to_string()).await {
                warn!("Failed to send bad request error response: {}", send_err);
            }
            return Err(e);
        }
    } else if matches!(
        request.method.to_uppercase().as_str(),
        "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "PATCH"
    ) {
        if let Err(e) = handle_http_forward_request(&mut ctx_lock, request) {
            // Get a fresh reference to the socket since we can't use the previous one
            let socket = ctx_lock.borrow_client_stream().unwrap();
            if let Err(send_err) = send_error_response(socket, 400, "Bad Request", &e.to_string()).await {
                warn!("Failed to send bad request error response: {}", send_err);
            }
            return Err(e);
        }
    } else {
        if let Err(e) = send_simple_error_response(socket, 400, "Bad Request").await {
            warn!("Failed to send bad request response: {}", e);
        }
        bail!("Invalid request method: {}", request.method);
    }

    trace!("Request: {:?}", ctx_lock);
    drop(ctx_lock);
    ctx.enqueue(&queue).await?;
    Ok(())
}

/// Generate a random proxy identifier for Via header (per-instance, not per-request)
fn generate_proxy_id() -> String {
    use rand::Rng;
    format!("id-{:08x}",rand::rng().random::<u32>())
}

/// Check for proxy loops using multiple detection methods
fn check_proxy_loop(local_addr: std::net::SocketAddr, request: &HttpRequest, proxy_id: &str) -> Result<()> {
    const MAX_HOPS: usize = 10;
    
    // 1. Check Via header for loops and hop count
    let via_header = request.header("Via", "");
    if !via_header.is_empty() {
        let hops: Vec<&str> = via_header.split(',').map(str::trim).collect();
        
        // Check hop count limit
        if hops.len() >= MAX_HOPS {
            bail!("Request rejected: hop count limit ({}) exceeded", MAX_HOPS);
        }
        
        // Check for our own proxy ID in the Via header
        for hop in &hops {
            if hop.contains(proxy_id) {
                bail!("Request rejected: proxy loop detected (found own ID in Via header)");
            }
        }
    }
    
    // 2. Get target address for local/bind address checking
    let target_addr = if request.method.eq_ignore_ascii_case("CONNECT") {
        // CONNECT method: resource is "hostname:port"
        request.resource.parse()
            .with_context(|| format!("failed to parse CONNECT target: {}", request.resource))?
    } else if request.resource.starts_with("http://") || request.resource.starts_with("https://") {
        // Absolute URI
        let url = Url::parse(&request.resource)
            .map_err(|e| anyhow!("Failed to parse resource URI: {}", e))?;
        let host = url.host_str()
            .ok_or_else(|| anyhow!("Missing host in resource URI"))?;
        let port = url.port_or_known_default()
            .ok_or_else(|| anyhow!("Missing port in resource URI"))?;
        TargetAddress::DomainPort(host.to_string(), port)
    } else {
        // Relative path, use Host header
        let host_header = request.header("Host", "");
        if host_header.is_empty() {
            bail!("Missing Host header for relative resource path");
        }
        host_header.parse()
            .with_context(|| format!("failed to parse Host header: {}", host_header))?
    };
    
    // 3. Check if target resolves to local addresses
    match target_addr {
        TargetAddress::DomainPort(ref host, port) => {
            // Block obvious local addresses
            if host == "localhost" || host == "127.0.0.1" || host == "::1" 
                || host.starts_with("127.") || host.starts_with("::ffff:127.") {
                bail!("Request rejected: target resolves to local address ({}:{})", host, port);
            }
            
            // Check if target matches listener's bind address
            if local_addr.port() == port {
                // Check if host resolves to same address as our bind address
                if *host == local_addr.ip().to_string() {
                    bail!("Request rejected: target matches listener bind address ({}:{})", host, port);
                }
                
                // Also check for 0.0.0.0 binding (listens on all interfaces)
                if local_addr.ip().is_unspecified() && (
                    host == "0.0.0.0" || 
                    host.parse::<std::net::IpAddr>().map(|ip| ip.is_loopback()).unwrap_or(false)
                ) {
                    bail!("Request rejected: target matches listener address space ({}:{})", host, port);
                }
            }
        }
        TargetAddress::SocketAddr(socket_addr) => {
            // Check if target socket address is local
            if socket_addr.ip().is_loopback() {
                bail!("Request rejected: target resolves to local address ({})", socket_addr);
            }
            
            // Check if target matches listener's bind address exactly
            if socket_addr == local_addr {
                bail!("Request rejected: target matches listener bind address ({})", socket_addr);
            }
            
            // Also check for 0.0.0.0 binding (listens on all interfaces)
            if local_addr.ip().is_unspecified() && socket_addr.port() == local_addr.port() {
                if socket_addr.ip().is_loopback() || socket_addr.ip().is_unspecified() {
                    bail!("Request rejected: target matches listener address space ({})", socket_addr);
                }
            }
        }
        TargetAddress::Unknown => {
            // Can't check unknown targets, let them through
        }
    }
    
    Ok(())
}

// Helper function for HTTP forward proxy request handling (without loop detection)
fn handle_http_forward_request(ctx_lock: &mut Context, mut request: HttpRequest) -> Result<()> {
    // Get the proxy identifier for this instance (same for all requests from this proxy)
    let proxy_id = get_proxy_id();
    
    let target_addr =
        if request.resource.starts_with("http://") || request.resource.starts_with("https://") {
            // Absolute URI
            let url = Url::parse(&request.resource)
                .map_err(|e| anyhow!("Failed to parse resource URI: {}", e))?;
            let host = url
                .host_str()
                .ok_or_else(|| anyhow!("Missing host in resource URI"))?;
            let port = url
                .port_or_known_default()
                .ok_or_else(|| anyhow!("Missing port in resource URI"))?;
            TargetAddress::DomainPort(host.to_string(), port)
        } else {
            // Relative path, use Host header
            let host_header = request.header("Host", "");
            if host_header.is_empty() {
                bail!("Missing Host header for relative resource path");
            }
            host_header
                .parse()
                .with_context(|| format!("failed to parse Host header: {}", host_header))?
        };

    // Add Via header for RFC-compliant proxy chain tracking
    let via_value = format!("1.1 {}", proxy_id);
    let existing_via = request.header("Via", "");
    let new_via = if existing_via.is_empty() {
        via_value
    } else {
        format!("{}, {}", existing_via, via_value)
    };
    request.headers.push(("Via".to_string(), new_via));

    ctx_lock
        .set_target(target_addr)
        .set_feature(Feature::TcpForward)
        .set_http_request(request)
        .set_callback(HttpForwardCallback);

    Ok(())
}

// RFC 9298 HTTP/1.1 UDP proxy upgrade handler
async fn handle_rfc9298_upgrade<FrameFn, T2>(
    ctx: ContextRef,
    queue: Sender<ContextRef>,
    request: HttpRequest,
    _create_frames: FrameFn,
) -> Result<()>
where
    FrameFn: FnOnce(&str, u32) -> T2 + Sync,
    T2: Future<Output = Result<FrameIO>>,
{
    // Parse URI template to extract target_host and target_port
    let target = parse_rfc9298_uri_template(&request.resource)?;

    let mut ctx_lock = ctx.write().await;

    // Don't send the upgrade response yet - wait until downstream connection succeeds
    // The response will be sent in Rfc9298Callback::on_connect

    // Set up UDP proxying context with RFC 9298 callback
    let session_id = SESSION_ID.fetch_add(1, Ordering::Relaxed);
    ctx_lock
        .set_target(target)
        .set_feature(Feature::UdpForward)
        .set_callback(Rfc9298Callback { session_id });

    // Frames will be set up in on_connect callback after downstream connection succeeds

    drop(ctx_lock);
    ctx.enqueue(&queue).await?;
    Ok(())
}

// Parse RFC 9298 URI template to extract target address
pub fn parse_rfc9298_uri_template(uri: &str) -> Result<TargetAddress> {
    // RFC 9298 requires URI template with {target_host} and {target_port} variables
    // Examples:
    // - /.well-known/masque/udp/{target_host}/{target_port}/
    // - /udp-proxy/{target_host}/{target_port}
    // - /proxy?host={target_host}&port={target_port}

    // For this function, we expect the URI to contain actual resolved values, not template variables
    // Template resolution should happen before calling this function

    // Parse the URI using the url crate for proper handling
    let base_url = "http://localhost"; // Dummy base for relative URI parsing
    let full_url = if uri.starts_with('/') {
        format!("{}{}", base_url, uri)
    } else {
        uri.to_string()
    };

    let url = Url::parse(&full_url).with_context(|| format!("Failed to parse URI: {}", uri))?;

    // Helper function to decode percent-encoded strings
    let decode_percent = |s: &str| -> Result<String> {
        let bytes = s.as_bytes();
        let mut decoded = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' && i + 2 < bytes.len() {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3])
                    .with_context(|| "Invalid percent-encoding")?;
                let byte = u8::from_str_radix(hex, 16)
                    .with_context(|| "Invalid hex in percent-encoding")?;
                decoded.push(byte);
                i += 3;
            } else {
                decoded.push(bytes[i]);
                i += 1;
            }
        }
        String::from_utf8(decoded).with_context(|| "Invalid UTF-8 in percent-decoded string")
    };

    // Check for query parameter style: ?host=example.com&port=8080
    if let Some(query) = url.query() {
        let params: std::collections::HashMap<String, String> =
            url::form_urlencoded::parse(query.as_bytes())
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();

        if let (Some(host), Some(port_str)) = (
            params.get("host").or_else(|| params.get("target_host")),
            params.get("port").or_else(|| params.get("target_port")),
        ) {
            // Skip template variables
            if !host.starts_with('{')
                && !port_str.starts_with('{')
                && let Ok(port) = port_str.parse::<u16>()
            {
                // Try to parse as IP address first
                if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                    return Ok(TargetAddress::SocketAddr(std::net::SocketAddr::new(
                        ip, port,
                    )));
                }
                return Ok(TargetAddress::DomainPort(host.clone(), port));
            }
        }
    }

    // Check for path-based style: /path/host/port
    let path_segments: Vec<&str> = url
        .path_segments()
        .ok_or_else(|| anyhow!("Invalid URI path: {}", uri))?
        .filter(|s| !s.is_empty())
        .collect();

    // Try to extract from the last two non-empty path segments
    if path_segments.len() >= 2 {
        let host_encoded = path_segments[path_segments.len() - 2];
        let port_str = path_segments[path_segments.len() - 1];

        // Decode the host from percent-encoding for consistency
        let host = decode_percent(host_encoded)?;

        // Skip template variables and trailing slashes
        if !host.starts_with('{')
            && !port_str.starts_with('{')
            && !port_str.is_empty()
            && let Ok(port) = port_str.parse::<u16>()
        {
            // Try to parse as IP address first
            if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                return Ok(TargetAddress::SocketAddr(std::net::SocketAddr::new(
                    ip, port,
                )));
            }
            return Ok(TargetAddress::DomainPort(host, port));
        }
    }

    bail!(
        "Invalid or unresolvable RFC 9298 URI: {}. Expected URI with resolved host and port values.",
        uri
    );
}

// Generate RFC 9298 URI from a configurable template for connecting to a target
pub fn generate_rfc9298_uri_from_template(
    target: &TargetAddress,
    template: Option<&str>,
) -> String {
    let template = template.unwrap_or("/.well-known/masque/udp/{host}/{port}/");

    let (host, port) = match target {
        TargetAddress::DomainPort(host, port) => (host.clone(), *port),
        TargetAddress::SocketAddr(addr) => (addr.ip().to_string(), addr.port()),
        TargetAddress::Unknown => ("unknown".to_string(), 0),
    };

    // Simple template substitution - replace {host} and {port} placeholders
    template
        .replace("{host}", &host)
        .replace("{port}", &port.to_string())
        .replace("{target_host}", &host) // Support both naming conventions
        .replace("{target_port}", &port.to_string())
}

struct HttpConnectCallback;
#[async_trait]
impl ContextCallback for HttpConnectCallback {
    async fn on_connect(&self, ctx: &mut Context) {
        let socket = ctx.borrow_client_stream().unwrap();
        if let Err(e) = HttpResponse::new(200, "Connection established")
            .write_to(socket)
            .await
        {
            warn!("failed to send response: {}", e)
        }
    }
    async fn on_error(&self, ctx: &mut Context, error: Error) {
        if let Some(socket) = ctx.borrow_client_stream() {
            let error_message = format!("Error: {} Cause: {:?}", error, error.source());
            if let Err(e) =
                send_error_response(socket, 503, "Service unavailable", &error_message).await
            {
                warn!("failed to send response: {}", e);
            }
        }
    }
}

struct HttpForwardCallback;
#[async_trait]
impl ContextCallback for HttpForwardCallback {
    async fn on_connect(&self, ctx: &mut Context) {
        let client_stream = match ctx.take_client_stream() {
            Ok(stream) => stream,
            Err(e) => {
                warn!(
                    "HttpForwardCallback::on_connect: failed to take client stream: {}",
                    e
                );
                return;
            }
        };
        let server_stream = ctx.take_server_stream();
        let request = ctx.http_request();

        if server_stream.is_none() || request.is_none() {
            warn!("HttpForwardCallback::on_connect: missing server_stream or http_request");
            let mut client_stream = client_stream;
            let _ =
                send_simple_error_response(&mut client_stream, 500, "Internal Server Error").await;
            return;
        }

        let mut client_stream = client_stream;
        let mut server_stream = server_stream.unwrap();
        let mut request = request.unwrap().as_ref().clone();

        // Only add Connection: close for regular HTTP requests, not HTTP upgrades
        let connection = request.header("Connection", "").to_lowercase();
        let has_upgrade = connection.split(',').any(|token| token.trim() == "upgrade");

        if !has_upgrade {
            request = request.with_header("Connection", "close");
        }

        if let Err(e) = request.write_to(&mut server_stream).await {
            warn!("Failed to write request to server: {}", e);
            let _ =
                send_simple_error_response(&mut client_stream, 503, "Service Unavailable").await;
            return;
        }

        // Flush the server stream to ensure request is sent
        if let Err(e) = server_stream.flush().await {
            warn!("Failed to flush server stream after writing request: {}", e);
            let _ =
                send_simple_error_response(&mut client_stream, 503, "Service Unavailable").await;
            return;
        }

        // Put streams back and let copy_bidi handle everything else
        ctx.set_client_stream(client_stream);
        ctx.set_server_stream(server_stream);
    }

    async fn on_error(&self, ctx: &mut Context, error: Error) {
        warn!("HttpForwardCallback::on_error: {}", error);
        match ctx.take_client_stream() {
            Ok(mut socket) => {
                let error_message = format!("Error: {}\r\nCause: {:?}", error, error.source());
                if let Err(e) =
                    send_error_response(&mut socket, 503, "Service Unavailable", &error_message)
                        .await
                {
                    warn!("Failed to send error response to client: {}", e);
                }
            }
            Err(e) => {
                warn!(
                    "HttpForwardCallback::on_error: Failed to take client stream: {}",
                    e
                );
            }
        }
    }
}

struct FrameChannelCallback {
    session_id: u32,
    inline: bool,
}

#[async_trait]
impl ContextCallback for FrameChannelCallback {
    async fn on_connect(&self, ctx: &mut Context) {
        tracing::trace!("on_connect callback: id={} ctx={}", self.session_id, ctx);
        let mut stream = match ctx.take_client_stream() {
            Ok(stream) => stream,
            Err(e) => {
                warn!(
                    "FrameChannelCallback::on_connect: failed to take client stream: {}",
                    e
                );
                return;
            }
        };

        if let Err(e) = HttpResponse::new(200, "Connection established")
            .with_header("Session-Id", self.session_id.to_string())
            .with_header(
                "Udp-Bind-Address",
                ctx.extra("udp-bind-address").unwrap_or(""),
            )
            .write_to(&mut stream)
            .await
        {
            warn!("failed to send response: {}", e);
            return;
        }

        if self.inline {
            ctx.set_client_frames(frames_from_stream(self.session_id, stream));
        }
    }

    async fn on_error(&self, ctx: &mut Context, error: Error) {
        if let Some(socket) = ctx.borrow_client_stream() {
            let error_message = format!("Error: {} Cause: {:?}", error, error.source());
            if let Err(e) =
                send_error_response(socket, 503, "Service unavailable", &error_message).await
            {
                warn!("failed to send response: {}", e);
            }
        }
    }
}

pub struct Rfc9298Callback {
    pub session_id: u32,
}

#[async_trait]
impl ContextCallback for Rfc9298Callback {
    async fn on_connect(&self, ctx: &mut Context) {
        tracing::trace!(
            "RFC 9298 on_connect callback: id={} ctx={}",
            self.session_id,
            ctx
        );

        // Now that downstream connection succeeded, send the RFC 9298 upgrade response
        let mut stream = match ctx.take_client_stream() {
            Ok(stream) => stream,
            Err(e) => {
                warn!(
                    "Rfc9298Callback::on_connect: failed to take client stream: {}",
                    e
                );
                return;
            }
        };

        // Send 101 Switching Protocols response
        if let Err(e) = HttpResponse::new(101, "Switching Protocols")
            .with_header("Connection", "Upgrade")
            .with_header("Upgrade", "connect-udp")
            .write_to(&mut stream)
            .await
        {
            warn!("Failed to send RFC 9298 upgrade response: {}", e);
            return;
        }

        // Set up RFC 9298 capsule protocol frames using the upgraded stream
        ctx.set_client_frames(super::frames::rfc9298_frames_from_stream(
            self.session_id,
            stream,
        ));

        tracing::info!(
            "RFC 9298 UDP proxy connection established for session {}",
            self.session_id
        );
    }

    async fn on_error(&self, ctx: &mut Context, error: Error) {
        tracing::error!(
            "RFC 9298 connection error for session {}: {}",
            self.session_id,
            error
        );

        // If connection to downstream failed, send HTTP error response instead of upgrade
        if let Some(socket) = ctx.borrow_client_stream() {
            let error_message = format!("Error: {} Cause: {:?}", error, error.source());
            if let Err(e) =
                send_error_response(socket, 503, "Service Unavailable", &error_message).await
            {
                warn!("Failed to send RFC 9298 error response: {}", e);
            }
        } else {
            // If frames were already set up, close them gracefully
            if let Some(frames) = ctx.take_frames() {
                tracing::debug!(
                    "RFC 9298 session {} terminated due to error, frames closed",
                    self.session_id
                );
                drop(frames);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc9298_uri_template_parsing() {
        // Test path-based URI template
        let result = parse_rfc9298_uri_template("/proxy/example.com/8080");
        assert!(result.is_ok());
        if let Ok(TargetAddress::DomainPort(host, port)) = result {
            assert_eq!(host, "example.com");
            assert_eq!(port, 8080);
        }

        // Test query parameter style
        let result = parse_rfc9298_uri_template("/proxy?host=test.com&port=9090");
        assert!(result.is_ok());
        if let Ok(TargetAddress::DomainPort(host, port)) = result {
            assert_eq!(host, "test.com");
            assert_eq!(port, 9090);
        }

        // Test query parameter style with target_host/target_port names
        let result = parse_rfc9298_uri_template("/masque?target_host=example.org&target_port=443");
        assert!(result.is_ok());
        if let Ok(TargetAddress::DomainPort(host, port)) = result {
            assert_eq!(host, "example.org");
            assert_eq!(port, 443);
        }

        // Test URL-encoded query parameters
        let result = parse_rfc9298_uri_template("/proxy?host=test%2Ecom&port=8080");
        assert!(result.is_ok());
        if let Ok(TargetAddress::DomainPort(host, port)) = result {
            assert_eq!(host, "test.com");
            assert_eq!(port, 8080);
        }

        // Test invalid URI
        let result = parse_rfc9298_uri_template("/invalid");
        assert!(result.is_err());

        // Test URI with template variables (should fail since we expect resolved values)
        let result = parse_rfc9298_uri_template("/proxy/{target_host}/{target_port}");
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_rfc9298_uri_from_template() {
        // Test default template (domain port)
        let target = TargetAddress::DomainPort("example.com".to_string(), 8080);
        let uri = generate_rfc9298_uri_from_template(&target, None);
        assert_eq!(uri, "/.well-known/masque/udp/example.com/8080/");

        // Test custom template with {host}/{port}
        let custom_template = "/proxy/udp/{host}/{port}";
        let uri = generate_rfc9298_uri_from_template(&target, Some(custom_template));
        assert_eq!(uri, "/proxy/udp/example.com/8080");

        // Test custom template with {target_host}/{target_port}
        let custom_template = "/masque?target_host={target_host}&target_port={target_port}";
        let uri = generate_rfc9298_uri_from_template(&target, Some(custom_template));
        assert_eq!(uri, "/masque?target_host=example.com&target_port=8080");

        // Test socket address IPv4
        let target = TargetAddress::SocketAddr("127.0.0.1:9090".parse().unwrap());
        let uri = generate_rfc9298_uri_from_template(&target, None);
        assert_eq!(uri, "/.well-known/masque/udp/127.0.0.1/9090/");

        // Test socket address IPv6
        let target = TargetAddress::SocketAddr("[::1]:8080".parse().unwrap());
        let uri = generate_rfc9298_uri_from_template(&target, None);
        assert_eq!(uri, "/.well-known/masque/udp/::1/8080/");

        // Test unknown address
        let target = TargetAddress::Unknown;
        let uri = generate_rfc9298_uri_from_template(&target, None);
        assert_eq!(uri, "/.well-known/masque/udp/unknown/0/");
    }

    #[test]
    fn test_http_proxy_context_ext() {
        use crate::context::ContextManager;
        use std::sync::Arc;

        // Create a test context
        let manager = Arc::new(ContextManager::default());
        let source = "127.0.0.1:1234".parse().unwrap();

        tokio_test::block_on(async {
            let ctx = manager.create_context("test".to_string(), source).await;

            // Test the extension trait methods
            {
                let mut ctx_write = ctx.write().await;
                ctx_write
                    .set_proxy_frame_channel("test-channel")
                    .set_proxy_force_connect(true)
                    .set_proxy_udp_protocol("rfc9298")
                    .set_proxy_rfc9298_uri_template("/custom/{host}/{port}");
            }

            // Verify the values are stored correctly
            {
                let ctx_read = ctx.read().await;
                assert_eq!(ctx_read.proxy_frame_channel(), Some("test-channel"));
                assert!(ctx_read.proxy_force_connect());
                assert_eq!(ctx_read.proxy_udp_protocol(), Some("rfc9298"));
                assert_eq!(
                    ctx_read.proxy_rfc9298_uri_template(),
                    Some("/custom/{host}/{port}")
                );
            }
        });
    }

    #[test]
    fn test_websocket_detection() {
        // Valid WebSocket upgrade request
        let ws_request = HttpRequest::new("GET", "/")
            .with_header("Connection", "upgrade")
            .with_header("Upgrade", "websocket");
        assert!(is_websocket_upgrade(&ws_request));

        // Valid WebSocket upgrade with multiple Connection header values
        let ws_request_multi = HttpRequest::new("GET", "/")
            .with_header("Connection", "keep-alive, upgrade")
            .with_header("Upgrade", "websocket");
        assert!(is_websocket_upgrade(&ws_request_multi));

        // Valid WebSocket upgrade with different casing
        let ws_request_case = HttpRequest::new("GET", "/")
            .with_header("Connection", "Upgrade")
            .with_header("Upgrade", "WebSocket");
        assert!(is_websocket_upgrade(&ws_request_case));

        // Invalid: contains "upgrade" but not as separate token
        let invalid_contains = HttpRequest::new("GET", "/")
            .with_header("Connection", "keep-alive-upgrade")
            .with_header("Upgrade", "websocket");
        assert!(!is_websocket_upgrade(&invalid_contains));

        // Invalid: Upgrade header contains websocket but not exactly
        let invalid_upgrade = HttpRequest::new("GET", "/")
            .with_header("Connection", "upgrade")
            .with_header("Upgrade", "websocket-custom");
        assert!(!is_websocket_upgrade(&invalid_upgrade));

        // Invalid: Regular HTTP request
        let http_request = HttpRequest::new("GET", "/").with_header("Connection", "keep-alive");
        assert!(!is_websocket_upgrade(&http_request));

        // Invalid: Missing Connection header
        let no_connection = HttpRequest::new("GET", "/").with_header("Upgrade", "websocket");
        assert!(!is_websocket_upgrade(&no_connection));

        // Invalid: Missing Upgrade header
        let no_upgrade = HttpRequest::new("GET", "/").with_header("Connection", "upgrade");
        assert!(!is_websocket_upgrade(&no_upgrade));
    }

    #[test]
    fn test_basic_auth_encoding_decoding() {
        // Test encoding
        let encoded = encode_basic_auth("testuser", "testpass");
        assert_eq!(encoded, "dGVzdHVzZXI6dGVzdHBhc3M=");

        // Test decoding
        let decoded = decode_basic_auth("Basic dGVzdHVzZXI6dGVzdHBhc3M=");
        assert_eq!(
            decoded,
            Some(("testuser".to_string(), "testpass".to_string()))
        );

        // Test invalid auth header
        let invalid = decode_basic_auth("Bearer token123");
        assert_eq!(invalid, None);

        // Test malformed base64
        let malformed = decode_basic_auth("Basic invalid!!!");
        assert_eq!(malformed, None);

        // Test credentials without colon
        let no_colon = decode_basic_auth("Basic dGVzdA=="); // "test" in base64
        assert_eq!(no_colon, None);
    }
}
