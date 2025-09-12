use anyhow::{Result, anyhow};

use super::context_ext::HttpContextExt;
use crate::context::{Context, TargetAddress};
use crate::protocols::http::{HttpMessage, HttpMethod, HttpRequest, HttpVersion};

/// HTTP request processing mode
#[derive(Debug, Clone, PartialEq)]
pub enum RequestMode {
    /// CONNECT tunneling (HTTP CONNECT method)
    Connect,
    /// HTTP forward proxy (absolute URI: http://example.com/path)
    ForwardAbsolute,
    /// HTTP forward proxy (relative path with Host header: GET /path)
    ForwardRelative,
    /// Direct HTTP request (used when connector connects directly to origin)
    Direct,
}

/// Determine the appropriate request processing mode based on context and request
///
/// This function analyzes the request method, URI format, and context properties
/// to determine how the request should be processed by protocol handlers.
///
/// **Logic:**
/// 1. CONNECT method → Connect mode (always tunneling)
/// 2. Absolute URI (http://host/path) → ForwardAbsolute mode  
/// 3. Relative path + forward proxy context → ForwardRelative mode
/// 4. Otherwise → Direct mode (connector connects to origin directly)
pub fn determine_request_mode(ctx: &Context, request: &HttpRequest) -> RequestMode {
    // CONNECT method is always tunneling
    if request.method == HttpMethod::Connect {
        return RequestMode::Connect;
    }

    // Check URI format for forward proxy detection
    if request.uri.starts_with("http://") || request.uri.starts_with("https://") {
        return RequestMode::ForwardAbsolute;
    }

    // Relative path - check if we're in forward proxy mode
    if ctx.http_forward_proxy() {
        return RequestMode::ForwardRelative;
    }

    // Default to direct mode
    RequestMode::Direct
}

/// Build the appropriate request URI based on processing mode
///
/// Transforms the original request URI into the format needed for the target server:
/// - Connect: Returns host:port format
/// - ForwardAbsolute: Returns absolute URI as-is  
/// - ForwardRelative: Returns relative path (Host header provides destination)
/// - Direct: Returns relative path for direct origin connection
pub fn build_request_uri(request: &HttpRequest, mode: RequestMode) -> String {
    match mode {
        RequestMode::Connect => {
            // CONNECT requests should already have host:port format
            request.uri.clone()
        }
        RequestMode::ForwardAbsolute => {
            // Forward proxy with absolute URI - send as-is
            request.uri.clone()
        }
        RequestMode::ForwardRelative => {
            // Relative path for forward proxy - Host header provides destination
            if request.uri.starts_with('/') {
                request.uri.clone()
            } else {
                format!("/{}", request.uri)
            }
        }
        RequestMode::Direct => {
            // Direct connection - preserve original URI format
            request.uri.clone()
        }
    }
}

/// Add proxy authentication header to request if configured
///
/// Checks context for HTTP proxy authentication credentials and adds
/// the appropriate Proxy-Authorization header using Basic authentication.
pub fn add_proxy_auth(request: &mut HttpRequest, ctx: &Context) -> Result<()> {
    if let Some(credentials) = ctx.http_proxy_auth() {
        // Parse credentials in "username:password" format
        if let Some((username, password)) = credentials.split_once(':') {
            let encoded = encode_basic_auth(username, password);
            request.set_header(
                "Proxy-Authorization".to_string(),
                format!("Basic {}", encoded),
            );
        } else {
            return Err(anyhow!(
                "Invalid proxy auth format, expected 'username:password'"
            ));
        }
    }
    Ok(())
}

/// Add standard proxy headers (Via, X-Forwarded-For) to request
///
/// These headers provide transparency about the proxy chain for debugging
/// and compliance with HTTP proxy specifications.
pub fn add_proxy_headers(request: &mut HttpRequest, _ctx: &Context, client_ip: std::net::IpAddr) {
    // Add Via header for proxy chain tracking
    let proxy_id = get_proxy_identifier();
    let via_value = format!("1.1 {}", proxy_id);

    if let Some(existing_via) = request.get_header("Via") {
        request.set_header(
            "Via".to_string(),
            format!("{}, {}", existing_via, via_value),
        );
    } else {
        request.add_header("Via".to_string(), via_value);
    }

    // Add X-Forwarded-For header
    let client_ip_str = client_ip.to_string();
    if let Some(existing_xff) = request.get_header("X-Forwarded-For") {
        request.set_header(
            "X-Forwarded-For".to_string(),
            format!("{}, {}", existing_xff, client_ip_str),
        );
    } else {
        request.add_header("X-Forwarded-For".to_string(), client_ip_str);
    }
}

/// Set connection management headers based on protocol and keep-alive settings
///
/// Configures Connection and Keep-Alive headers appropriately for the target protocol:
/// - HTTP/1.1: Connection: keep-alive or close based on context settings
/// - HTTP/2+: Connection header not needed (multiplexed protocols)
/// - WebSocket: Preserves Connection: Upgrade header
pub fn set_connection_headers(request: &mut HttpRequest, ctx: &Context) {
    let protocol = ctx.http_protocol().unwrap_or("http/1.1");

    // Check if this is a WebSocket upgrade request
    if is_websocket_upgrade_request(request) {
        // Preserve Connection: Upgrade for WebSocket
        request.set_header("Connection".to_string(), "Upgrade".to_string());
        return;
    }

    match protocol {
        "http/1.1" => {
            if ctx.http_keep_alive() {
                request.set_header("Connection".to_string(), "keep-alive".to_string());
            } else {
                request.set_header("Connection".to_string(), "close".to_string());
            }
        }
        "h2" | "h3" => {
            // HTTP/2 and HTTP/3 don't use Connection header
            request.remove_header("Connection");
            request.remove_header("Keep-Alive");
        }
        _ => {
            // Unknown protocol - default to close for safety
            request.set_header("Connection".to_string(), "close".to_string());
        }
    }
}

/// Extract target address from HTTP request for connection establishment
///
/// Analyzes the request to determine the target server address:
/// - CONNECT: Parses host:port from request URI
/// - Absolute URI: Extracts host and port from URL
/// - Relative path: Uses Host header with default port inference
pub fn extract_target_from_request(request: &HttpRequest) -> Result<TargetAddress> {
    if request.method == HttpMethod::Connect {
        // CONNECT request: target is in URI (host:port format)
        parse_connect_target(&request.uri)
    } else if request.uri.starts_with("http://") || request.uri.starts_with("https://") {
        // Absolute URI
        parse_absolute_uri(&request.uri)
    } else {
        // Relative path: use Host header
        parse_host_header(request)
    }
}

/// Check if request is a WebSocket upgrade
fn is_websocket_upgrade_request(request: &HttpRequest) -> bool {
    let connection = request
        .get_header("Connection")
        .map(|h| h.to_lowercase())
        .unwrap_or_default();
    let upgrade = request
        .get_header("Upgrade")
        .map(|h| h.to_lowercase())
        .unwrap_or_default();

    // Check if Connection header contains "upgrade" as a token
    let has_upgrade_connection = connection.split(',').any(|token| token.trim() == "upgrade");

    has_upgrade_connection && upgrade == "websocket"
}

/// Parse CONNECT target in "host:port" format
fn parse_connect_target(uri: &str) -> Result<TargetAddress> {
    if let Some(colon_pos) = uri.find(':') {
        let host = &uri[..colon_pos];
        let port_str = &uri[colon_pos + 1..];
        let port: u16 = port_str
            .parse()
            .map_err(|e| anyhow!("Failed to parse CONNECT port '{}': {}", port_str, e))?;
        Ok(TargetAddress::DomainPort(host.to_string(), port))
    } else {
        Err(anyhow!(
            "Invalid CONNECT target format '{}', expected 'host:port'",
            uri
        ))
    }
}

/// Parse absolute URI to extract target address
fn parse_absolute_uri(uri: &str) -> Result<TargetAddress> {
    let url = url::Url::parse(uri)
        .map_err(|e| anyhow!("Failed to parse resource URI '{}': {}", uri, e))?;

    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("Missing host in resource URI '{}'", uri))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow!("Missing port in resource URI '{}'", uri))?;

    Ok(TargetAddress::DomainPort(host.to_string(), port))
}

/// Parse Host header to extract target address
fn parse_host_header(request: &HttpRequest) -> Result<TargetAddress> {
    let host_header = request.get_header("Host").ok_or_else(|| {
        anyhow!(
            "Missing Host header for relative resource path '{}'",
            request.uri
        )
    })?;

    // Add default port if missing
    let target_with_port = if host_header.contains(':') {
        host_header.clone()
    } else {
        // Default to port 80 for HTTP requests
        format!("{}:80", host_header)
    };

    target_with_port
        .parse()
        .map_err(|e| anyhow!("Failed to parse Host header '{}': {}", host_header, e))
}

/// Encode credentials for Basic authentication
fn encode_basic_auth(username: &str, password: &str) -> String {
    use base64::Engine;
    let credentials = format!("{}:{}", username, password);
    base64::engine::general_purpose::STANDARD.encode(credentials.as_bytes())
}

/// Get proxy identifier for Via header (cached per process)
fn get_proxy_identifier() -> &'static str {
    use std::sync::OnceLock;
    static PROXY_ID: OnceLock<String> = OnceLock::new();

    PROXY_ID.get_or_init(|| {
        use rand::Rng;
        format!("redproxy-{:08x}", rand::rng().random::<u32>())
    })
}

/// Check if HTTP version supports keep-alive
pub fn supports_keep_alive(version: &HttpVersion) -> bool {
    match version {
        HttpVersion::Http1_0 => false, // HTTP/1.0 defaults to close
        HttpVersion::Http1_1 => true,  // HTTP/1.1 defaults to keep-alive
        HttpVersion::Http2 => true,    // HTTP/2 supports multiplexing
        HttpVersion::Http3 => true,    // HTTP/3 supports multiplexing over QUIC
    }
}

/// Determine if connection should be kept alive based on request and response
pub fn should_keep_alive(
    request: &HttpRequest,
    response: Option<&crate::protocols::http::HttpResponse>,
) -> bool {
    // Check request Connection header first
    if let Some(conn) = request.get_header("Connection") {
        let conn_lower = conn.to_lowercase();
        if conn_lower.contains("close") {
            return false;
        }
        if conn_lower.contains("keep-alive") {
            return true;
        }
    }

    // Check Proxy-Connection header for compatibility
    if let Some(proxy_conn) = request.get_header("Proxy-Connection") {
        let conn_lower = proxy_conn.to_lowercase();
        if conn_lower.contains("close") {
            return false;
        }
        if conn_lower.contains("keep-alive") {
            return true;
        }
    }

    // Check response if available
    if let Some(resp) = response
        && let Some(conn) = resp.get_header("Connection")
    {
        let conn_lower = conn.to_lowercase();
        if conn_lower.contains("close") {
            return false;
        }
        if conn_lower.contains("keep-alive") {
            return true;
        }
    }

    // Default based on HTTP version
    supports_keep_alive(&request.version)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::ContextManager;
    use std::sync::Arc;

    async fn create_test_context(forward_proxy: bool) -> Arc<tokio::sync::RwLock<Context>> {
        let manager = Arc::new(ContextManager::default());
        let source = "127.0.0.1:1234".parse().unwrap();
        let ctx = manager.create_context("test".to_string(), source).await;

        if forward_proxy {
            ctx.write().await.set_http_forward_proxy(true);
        }

        ctx
    }

    #[tokio::test]
    async fn test_determine_request_mode() {
        let ctx = create_test_context(false).await;
        let ctx_guard = ctx.read().await;

        // CONNECT method
        let connect_req = HttpRequest::new(
            HttpMethod::Connect,
            "example.com:443".to_string(),
            HttpVersion::Http1_1,
        );
        assert_eq!(
            determine_request_mode(&ctx_guard, &connect_req),
            RequestMode::Connect
        );

        // Absolute URI
        let abs_req = HttpRequest::new(
            HttpMethod::Get,
            "http://example.com/path".to_string(),
            HttpVersion::Http1_1,
        );
        assert_eq!(
            determine_request_mode(&ctx_guard, &abs_req),
            RequestMode::ForwardAbsolute
        );

        // Relative path without forward proxy
        let rel_req = HttpRequest::new(HttpMethod::Get, "/path".to_string(), HttpVersion::Http1_1);
        assert_eq!(
            determine_request_mode(&ctx_guard, &rel_req),
            RequestMode::Direct
        );

        drop(ctx_guard);

        // Test with forward proxy enabled
        let ctx_fp = create_test_context(true).await;
        let ctx_fp_guard = ctx_fp.read().await;
        assert_eq!(
            determine_request_mode(&ctx_fp_guard, &rel_req),
            RequestMode::ForwardRelative
        );
    }

    #[tokio::test]
    async fn test_build_request_uri() {
        let request = HttpRequest::new(
            HttpMethod::Get,
            "http://example.com/path".to_string(),
            HttpVersion::Http1_1,
        );

        assert_eq!(
            build_request_uri(&request, RequestMode::ForwardAbsolute),
            "http://example.com/path"
        );
        assert_eq!(
            build_request_uri(&request, RequestMode::Direct),
            "http://example.com/path"
        );

        let rel_request =
            HttpRequest::new(HttpMethod::Get, "/path".to_string(), HttpVersion::Http1_1);
        assert_eq!(
            build_request_uri(&rel_request, RequestMode::ForwardRelative),
            "/path"
        );
        assert_eq!(
            build_request_uri(&rel_request, RequestMode::Direct),
            "/path"
        );
    }

    #[tokio::test]
    async fn test_extract_target_from_request() {
        // CONNECT request
        let connect_req = HttpRequest::new(
            HttpMethod::Connect,
            "example.com:443".to_string(),
            HttpVersion::Http1_1,
        );
        let target = extract_target_from_request(&connect_req).unwrap();
        assert_eq!(
            target,
            TargetAddress::DomainPort("example.com".to_string(), 443)
        );

        // Absolute URI
        let abs_req = HttpRequest::new(
            HttpMethod::Get,
            "https://example.com:8080/path".to_string(),
            HttpVersion::Http1_1,
        );
        let target = extract_target_from_request(&abs_req).unwrap();
        assert_eq!(
            target,
            TargetAddress::DomainPort("example.com".to_string(), 8080)
        );

        // Relative path with Host header
        let mut rel_req =
            HttpRequest::new(HttpMethod::Get, "/path".to_string(), HttpVersion::Http1_1);
        rel_req.add_header("Host".to_string(), "example.com".to_string());
        let target = extract_target_from_request(&rel_req).unwrap();
        assert_eq!(
            target,
            TargetAddress::DomainPort("example.com".to_string(), 80)
        );
    }

    #[tokio::test]
    async fn test_add_proxy_auth() {
        let ctx = create_test_context(false).await;
        {
            let mut ctx_write = ctx.write().await;
            ctx_write.set_http_proxy_auth("testuser:testpass");
        }

        let mut request =
            HttpRequest::new(HttpMethod::Get, "/path".to_string(), HttpVersion::Http1_1);

        let ctx_read = ctx.read().await;
        add_proxy_auth(&mut request, &ctx_read).unwrap();

        assert!(request.get_header("Proxy-Authorization").is_some());
        let auth_header = request.get_header("Proxy-Authorization").unwrap();
        assert!(auth_header.starts_with("Basic "));
    }

    #[test]
    fn test_supports_keep_alive() {
        assert!(!supports_keep_alive(&HttpVersion::Http1_0));
        assert!(supports_keep_alive(&HttpVersion::Http1_1));
    }

    #[test]
    fn test_should_keep_alive() {
        let mut request =
            HttpRequest::new(HttpMethod::Get, "/path".to_string(), HttpVersion::Http1_1);

        // Default HTTP/1.1 should keep alive
        assert!(should_keep_alive(&request, None));

        // Explicit Connection: close should not keep alive
        request.add_header("Connection".to_string(), "close".to_string());
        assert!(!should_keep_alive(&request, None));

        // HTTP/1.0 should not keep alive by default
        request.version = HttpVersion::Http1_0;
        request.remove_header("Connection");
        assert!(!should_keep_alive(&request, None));
    }
}
