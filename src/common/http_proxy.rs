use anyhow::{Context as AnyhowContext, Error, Result, anyhow, bail};
use async_trait::async_trait;
use futures::Future;
use std::{
    net::SocketAddr,
    sync::atomic::{AtomicU32, Ordering},
};
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
    let decoded = base64::engine::general_purpose::STANDARD.decode(encoded).ok()?;
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

// Helper function to check if a request is a WebSocket upgrade
fn is_websocket_upgrade(request: &HttpRequest) -> bool {
    let connection = request.header("Connection", "").to_lowercase();
    let upgrade = request.header("Upgrade", "").to_lowercase();

    // Check if Connection header contains "upgrade" as a separate token
    let has_upgrade_connection = connection.split(',').any(|token| token.trim() == "upgrade");

    // Check if Upgrade header is exactly "websocket"
    let has_websocket_upgrade = upgrade == "websocket";

    has_upgrade_connection && has_websocket_upgrade
}

// Helper function to send error response to client
async fn send_error_response(
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
async fn send_simple_error_response(
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
    local: SocketAddr,
    remote: SocketAddr,
    frame_channel: &str,
    frame_fn: T1,
    force_connect: bool,
    auth: Option<(String, String)>,
) -> Result<()>
where
    T1: FnOnce(u32) -> T2 + Sync,
    T2: Future<Output = FrameIO>,
{
    tracing::trace!(
        "http_forward_proxy_connect: channel={}, force_connect={}",
        frame_channel,
        force_connect
    );
    let target = ctx.read().await.target();
    let feature = ctx.read().await.feature();
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
                let mut request = HttpRequest::new("CONNECT", &target)
                    .with_header("Host", &target);
                
                // Add Proxy-Authorization header if auth is provided
                if let Some((username, password)) = &auth {
                    let encoded = encode_basic_auth(username, password);
                    request = request.with_header("Proxy-Authorization", format!("Basic {}", encoded));
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
            let mut request = HttpRequest::new("CONNECT", &target)
                .with_header("Host", &target)
                .with_header("Proxy-Protocol", "udp")
                .with_header("Proxy-Channel", frame_channel);
            
            // Add Proxy-Authorization header if auth is provided
            if let Some((username, password)) = &auth {
                let encoded = encode_basic_auth(username, password);
                request = request.with_header("Proxy-Authorization", format!("Basic {}", encoded));
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
            tracing::trace!("response: {:?}", resp);
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
        x => bail!("not supported feature {:?}", x),
    };
    Ok(())
}

static SESSION_ID: AtomicU32 = AtomicU32::new(0);

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
            if let Err(e) = send_simple_error_response(socket, 407, "Proxy Authentication Required").await {
                warn!("Failed to send authentication required response: {}", e);
            }
            bail!("Client authentication failed");
        }
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
        handle_http_forward_request(&mut ctx_lock, request)?;
    } else if matches!(
        request.method.to_uppercase().as_str(),
        "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "PATCH"
    ) {
        handle_http_forward_request(&mut ctx_lock, request)?;
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

// Helper function for common HTTP forward proxy request handling
fn handle_http_forward_request(ctx_lock: &mut Context, request: HttpRequest) -> Result<()> {
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
    let socket = ctx_lock.borrow_client_stream().unwrap();

    // Send 101 Switching Protocols response
    if let Err(e) = HttpResponse::new(101, "Switching Protocols")
        .with_header("Connection", "Upgrade")
        .with_header("Upgrade", "connect-udp")
        .write_to(socket)
        .await
    {
        warn!("Failed to send upgrade response: {}", e);
        bail!("Failed to send upgrade response");
    }

    // Set up UDP proxying context with RFC 9298 callback
    let session_id = SESSION_ID.fetch_add(1, Ordering::Relaxed);
    ctx_lock
        .set_target(target)
        .set_feature(Feature::UdpForward)
        .set_callback(Rfc9298Callback { session_id });

    // Set up capsule protocol frames
    ctx_lock.set_client_frames(
        create_rfc9298_frames(session_id)
            .await
            .context("create RFC 9298 frames")?,
    );

    drop(ctx_lock);
    ctx.enqueue(&queue).await?;
    Ok(())
}

// Parse RFC 9298 URI template to extract target address
fn parse_rfc9298_uri_template(uri: &str) -> Result<TargetAddress> {
    // RFC 9298 requires URI template with {target_host} and {target_port} variables
    // Examples:
    // - /.well-known/masque/udp/{target_host}/{target_port}/
    // - /udp-proxy/{target_host}/{target_port}
    // - /proxy?host={target_host}&port={target_port}

    // For now, implement a simple parser that handles common URI template patterns
    // This should be enhanced to use a proper RFC 6570 URI template library

    // Check for query parameter style: ?host={target_host}&port={target_port}
    if uri.contains('?') {
        let (_, query) = uri.split_once('?').unwrap();
        let mut host: Option<&str> = None;
        let mut port: Option<&str> = None;

        for param in query.split('&') {
            if let Some((key, value)) = param.split_once('=') {
                match key {
                    "host" | "target_host" => {
                        host = Some(value.trim_matches('{').trim_matches('}'));
                    }
                    "port" | "target_port" => {
                        port = Some(value.trim_matches('{').trim_matches('}'));
                    }
                    _ => {}
                }
            }
        }

        if let (Some(h), Some(p)) = (host, port)
            && let Ok(port_num) = p.parse::<u16>()
        {
            return Ok(TargetAddress::DomainPort(h.to_string(), port_num));
        }
    }

    // Check for path-based style: /path/{target_host}/{target_port}
    let path_parts: Vec<&str> = uri.split('/').collect();
    for i in 0..path_parts.len().saturating_sub(1) {
        let current = path_parts[i];
        let next = path_parts.get(i + 1);

        // Look for {target_host} and {target_port} patterns
        if (current == "{target_host}" || current.contains("target_host"))
            && next.is_some()
            && (next.unwrap().contains("target_port") || next.unwrap().starts_with('{'))
        {
            // Extract actual values - for now assume they are literal values
            // In a real implementation, this would be resolved from the actual request
            if i >= 2 && path_parts.len() > i + 2 {
                let host_val = path_parts[i - 1];
                let port_val = path_parts[i + 1];

                if !host_val.is_empty()
                    && !port_val.starts_with('{')
                    && let Ok(port_num) = port_val.parse::<u16>()
                {
                    return Ok(TargetAddress::DomainPort(host_val.to_string(), port_num));
                }
            }
        }
    }

    // Fallback: Try to extract from the last two non-empty path segments
    let non_empty_parts: Vec<&str> = path_parts
        .iter()
        .filter(|s| !s.is_empty())
        .copied()
        .collect();
    if non_empty_parts.len() >= 2 {
        let host = non_empty_parts[non_empty_parts.len() - 2];
        let port_str = non_empty_parts[non_empty_parts.len() - 1];

        // Skip template variables
        if !host.starts_with('{')
            && !port_str.starts_with('{')
            && let Ok(port) = port_str.parse::<u16>()
        {
            return Ok(TargetAddress::DomainPort(host.to_string(), port));
        }
    }

    bail!(
        "Invalid or unresolvable RFC 9298 URI template: {}. Expected template with target_host and target_port variables.",
        uri
    );
}

// Create RFC 9298 capsule protocol frames
async fn create_rfc9298_frames(session_id: u32) -> Result<FrameIO> {
    // Create a duplex stream for RFC 9298 capsule protocol
    use tokio::io::duplex;
    let (client_stream, _server_stream) = duplex(8192);

    // Create RFC 9298-aware frame readers/writers
    let frame_io = super::frames::rfc9298_frames_from_stream(session_id, client_stream);

    // TODO: Connect server_stream to the actual network transport
    // For now, we'll let the frames_from_stream handle the RFC 9298 protocol
    tracing::info!("Created RFC 9298 frames for session {}", session_id);

    Ok(frame_io)
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

        // Only add Connection: close for regular HTTP requests, not WebSocket upgrades
        let is_websocket_upgrade = is_websocket_upgrade(&request);

        if !is_websocket_upgrade {
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

struct Rfc9298Callback {
    session_id: u32,
}

#[async_trait]
impl ContextCallback for Rfc9298Callback {
    async fn on_connect(&self, ctx: &mut Context) {
        tracing::trace!(
            "RFC 9298 on_connect callback: id={} ctx={}",
            self.session_id,
            ctx
        );

        // For RFC 9298, the upgrade response was already sent during handshake
        // Here we just need to set up the capsule protocol frames if not already done

        // TODO: Implement proper RFC 9298 capsule protocol setup
        tracing::info!(
            "RFC 9298 UDP proxy connection established for session {}",
            self.session_id
        );
    }

    async fn on_error(&self, _ctx: &mut Context, error: Error) {
        tracing::error!(
            "RFC 9298 connection error for session {}: {}",
            self.session_id,
            error
        );

        // For RFC 9298, we should send appropriate capsule frames to signal errors
        // TODO: Implement RFC 9298 error handling via capsule protocol
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

        // Test invalid URI
        let result = parse_rfc9298_uri_template("/invalid");
        assert!(result.is_err());
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
        assert_eq!(decoded, Some(("testuser".to_string(), "testpass".to_string())));
        
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
