use anyhow::{Result, bail};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tracing::{debug, warn};

use crate::context::{ContextManager, ContextRef, ContextRefOps, IOBufStream};
use crate::protocols::http::common::{
    add_proxy_headers, extract_target_from_request, set_connection_headers,
};
use crate::protocols::http::{HttpMessage, HttpMethod, HttpRequest, HttpResponse, HttpVersion};

use super::callback::{Http1Callback, HttpProxyMode};

/// Parse HTTP request line into components
async fn parse_request_line(line: &str) -> Result<(HttpMethod, String, HttpVersion)> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() != 3 {
        bail!("Invalid request line: {}", line);
    }

    let method = match parts[0] {
        "CONNECT" => HttpMethod::Connect,
        "GET" => HttpMethod::Get,
        "POST" => HttpMethod::Post,
        "PUT" => HttpMethod::Put,
        "DELETE" => HttpMethod::Delete,
        "HEAD" => HttpMethod::Head,
        "OPTIONS" => HttpMethod::Options,
        "PATCH" => HttpMethod::Patch,
        "TRACE" => HttpMethod::Trace,
        other => HttpMethod::Other(other.to_string()),
    };

    let uri = parts[1].to_string();
    let version = match parts[2] {
        "HTTP/1.1" => HttpVersion::Http1_1,
        "HTTP/1.0" => HttpVersion::Http1_0,
        other => bail!("Unsupported HTTP version: {}", other),
    };

    Ok((method, uri, version))
}

/// Parse HTTP status line into components
async fn parse_status_line(line: &str) -> Result<(HttpVersion, u16, String)> {
    let parts: Vec<&str> = line.splitn(3, ' ').collect();
    if parts.len() < 2 {
        bail!("Invalid status line: {}", line);
    }

    let version = match parts[0] {
        "HTTP/1.1" => HttpVersion::Http1_1,
        "HTTP/1.0" => HttpVersion::Http1_0,
        other => bail!("Unsupported HTTP version: {}", other),
    };

    let status_code: u16 = parts[1]
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid status code: {}", parts[1]))?;

    let reason_phrase = if parts.len() > 2 {
        parts[2].to_string()
    } else {
        String::new()
    };

    Ok((version, status_code, reason_phrase))
}

/// Read HTTP headers from stream with size limits
async fn read_headers(stream: &mut crate::io::IOBufStream) -> Result<Vec<(String, String)>> {
    const MAX_HEADER_LINE_SIZE: usize = 16384; // 16KB limit per header line
    const MAX_TOTAL_HEADERS_SIZE: usize = 65536; // 64KB total limit
    const MAX_HEADERS_COUNT: usize = 100; // Maximum number of headers

    let mut headers = Vec::new();
    let mut total_size = 0;

    loop {
        let mut line = String::new();

        // Use the new limited read method from BufferedStream
        let bytes_read = stream
            .read_line_limited(&mut line, MAX_HEADER_LINE_SIZE)
            .await
            .map_err(|e| anyhow::anyhow!("Header line too large: {}", e))?;

        if bytes_read == 0 {
            break; // EOF
        }

        total_size += line.len();

        // Check total size
        if total_size > MAX_TOTAL_HEADERS_SIZE {
            bail!(
                "Request headers too large: {} bytes (max {} bytes)",
                total_size,
                MAX_TOTAL_HEADERS_SIZE
            );
        }

        // Check header count
        if headers.len() >= MAX_HEADERS_COUNT {
            bail!(
                "Too many headers: {} (max {})",
                headers.len() + 1,
                MAX_HEADERS_COUNT
            );
        }

        let line_trimmed = line.trim_end();

        if line_trimmed.is_empty() {
            break; // End of headers
        }

        if let Some(colon_pos) = line_trimmed.find(':') {
            let name = line_trimmed[..colon_pos].trim().to_string();
            let value = line_trimmed[colon_pos + 1..].trim().to_string();
            headers.push((name, value));
        } else {
            bail!("Invalid header line: {}", line_trimmed);
        }
    }

    Ok(headers)
}

/// Handle HTTP/1.1 listener connection with keep-alive support
pub async fn handle_listener_connection(
    stream: Box<dyn crate::context::IOStream>,
    contexts: std::sync::Arc<ContextManager>,
    queue: tokio::sync::mpsc::Sender<ContextRef>,
    listener_name: String,
    source: std::net::SocketAddr,
) -> Result<()> {
    // Convert raw stream to IOBufStream immediately and use throughout
    let mut current_stream = crate::context::make_buffered_stream(stream);

    // HTTP/1.1 keep-alive loop: handle multiple requests on same connection
    loop {
        // Read request with error handling - current_stream is already buffered
        let request = match read_request(&mut current_stream).await {
            Ok(Some(req)) => req,
            Ok(None) => {
                debug!("HTTP/1.1: Client closed connection gracefully");
                break;
            }
            Err(e) => {
                warn!("HTTP/1.1: Request parsing error: {}", e);
                send_error_response_and_close(&mut current_stream, 400, "Bad Request").await;
                break;
            }
        };

        debug!(
            "HTTP/1.1: Processing request {} {}",
            request.method, request.uri
        );

        // Determine proxy mode
        let proxy_mode = if request.is_connect() {
            HttpProxyMode::Connect
        } else {
            HttpProxyMode::Forward
        };

        // Validate request before processing
        if proxy_mode == HttpProxyMode::Forward
            && let Err(e) = validate_forward_request(&request)
        {
            warn!("HTTP/1.1: Request validation failed: {}", e);
            send_error_response_and_close(&mut current_stream, 400, "Bad Request").await;
            break;
        }

        // Extract target address using common infrastructure
        let target = match extract_target_from_request(&request) {
            Ok(target) => target,
            Err(e) => {
                warn!("HTTP/1.1: Failed to extract target: {}", e);
                send_error_response_and_close(&mut current_stream, 400, "Bad Request").await;
                break;
            }
        };

        // Create context for this request
        let ctx = contexts.create_context(listener_name.clone(), source).await;

        // Create completion channel for keep-alive management
        let (completion_tx, completion_rx) = tokio::sync::oneshot::channel();
        let callback = Http1Callback::new(completion_tx, proxy_mode);

        // Set context data with the buffered stream directly
        {
            let mut ctx_guard = ctx.write().await;
            ctx_guard.set_http_request(request);
            ctx_guard.set_target(target);
            ctx_guard.set_client_stream(current_stream);
            ctx_guard.set_feature(crate::context::Feature::TcpForward);
            ctx_guard.set_callback(callback);
        }

        // Queue for rules engine processing
        if let Err(e) = ctx.enqueue(&queue).await {
            warn!("HTTP/1.1: Failed to enqueue context: {}", e);
            break;
        }

        // Wait for completion signal
        match completion_rx.await {
            Ok(Some(returned_stream)) => {
                debug!("HTTP/1.1: Request completed, stream returned for keep-alive");
                current_stream = returned_stream; // Reuse IOBufStream for next request
                continue; // Continue keep-alive loop
            }
            Ok(None) => {
                debug!("HTTP/1.1: Request completed, no keep-alive (tunnel/error/close)");
                break; // End keep-alive loop
            }
            Err(_) => {
                debug!("HTTP/1.1: Ending keep-alive loop due to channel error");
                break;
            }
        }
    }

    debug!("HTTP/1.1: Connection handling completed for {}", source);
    Ok(())
}

/// Read HTTP request from stream
pub async fn read_request(stream: &mut crate::io::IOBufStream) -> Result<Option<HttpRequest>> {
    let mut line = String::new();

    // Read request line with the same size limit as headers
    let bytes_read = stream
        .read_line_limited(&mut line, 16384)
        .await
        .map_err(|e| anyhow::anyhow!("Request line too large: {}", e))?;
    if bytes_read == 0 {
        return Ok(None); // Connection closed
    }

    let line = line.trim_end();
    debug!("HTTP/1.1: Parsing request line: '{}'", line);

    let (method, uri, version) = parse_request_line(line).await?;

    // Parse headers
    let headers = read_headers(stream).await?;

    let mut request = HttpRequest::new(method, uri, version);
    for (name, value) in headers {
        request.add_header(name, value);
    }

    // Validate Host header for HTTP/1.1 requests
    if request.version == HttpVersion::Http1_1 {
        let mut host_found = false;
        for (name, value) in &request.headers {
            if name.to_lowercase() == "host" {
                host_found = true;
                if value.trim().is_empty() {
                    bail!("Empty Host header in HTTP/1.1 request");
                }
                break;
            }
        }
        if !host_found {
            bail!("Missing Host header in HTTP/1.1 request");
        }
    }

    Ok(Some(request))
}

/// Send HTTP request to stream
pub async fn send_request(stream: &mut IOBufStream, request: &HttpRequest) -> Result<()> {
    debug!(
        "HTTP/1.1: send_request called - sending headers for {} {}",
        request.method, request.uri
    );
    let request_line = format!("{} {} {}\r\n", request.method, request.uri, request.version);
    AsyncWriteExt::write_all(stream, request_line.as_bytes()).await?;

    for (name, value) in &request.headers {
        let header_line = format!("{}: {}\r\n", name, value);
        AsyncWriteExt::write_all(stream, header_line.as_bytes()).await?;
    }

    AsyncWriteExt::write_all(stream, b"\r\n").await?;
    AsyncWriteExt::flush(stream).await?;
    debug!(
        "HTTP/1.1: send_request completed - headers sent for {} {}",
        request.method, request.uri
    );

    Ok(())
}

/// Read HTTP response from stream
pub async fn read_response(stream: &mut IOBufStream) -> Result<HttpResponse> {
    let mut line = String::new();

    // Read status line
    let bytes_read = stream.read_line(&mut line).await?;
    if bytes_read == 0 {
        bail!("Unexpected end of stream");
    }

    let line = line.trim_end();
    let (version, status_code, reason_phrase) = parse_status_line(line).await?;

    // Parse headers
    let headers = read_headers(stream).await?;

    let mut response = HttpResponse::new(version, status_code, reason_phrase);
    for (name, value) in headers {
        response.add_header(name, value);
    }

    Ok(response)
}

/// Send HTTP response to stream
pub async fn send_response(stream: &mut IOBufStream, response: &HttpResponse) -> Result<()> {
    let status_line = format!(
        "{} {} {}\r\n",
        response.version, response.status_code, response.reason_phrase
    );
    AsyncWriteExt::write_all(stream, status_line.as_bytes()).await?;

    for (name, value) in &response.headers {
        let header_line = format!("{}: {}\r\n", name, value);
        AsyncWriteExt::write_all(stream, header_line.as_bytes()).await?;
    }

    AsyncWriteExt::write_all(stream, b"\r\n").await?;
    AsyncWriteExt::flush(stream).await?;

    Ok(())
}

/// Handle HTTP listener request
pub async fn handle_listener(stream: &mut IOBufStream, _ctx: ContextRef) -> Result<HttpRequest> {
    match read_request(stream).await? {
        Some(request) => Ok(request),
        None => bail!("No request received from client"),
    }
}

/// Handle HTTP connector request  
pub async fn handle_connector(stream: &mut IOBufStream, ctx: ContextRef) -> Result<()> {
    let ctx_read = ctx.read().await;

    // Check if we have an existing HTTP request (forward proxy case)
    let request = if let Some(http_request) = ctx_read.http_request() {
        // HTTP Forward Proxy: use existing request
        debug!("HTTP/1.1: handle_connector - HTTP forward proxy case, using existing request");
        http_request.as_ref().clone()
    } else {
        // SOCKS/Other → HTTP: create CONNECT request from target
        debug!("HTTP/1.1: handle_connector - SOCKS->HTTP case, creating CONNECT request");
        let target = ctx_read.target();
        HttpRequest::new(
            HttpMethod::Connect,
            target.to_string(),
            HttpVersion::Http1_1,
        )
    };

    drop(ctx_read); // Release the lock

    // Send the request
    debug!(
        "HTTP/1.1: handle_connector - calling send_request for {} {}",
        request.method, request.uri
    );
    send_request(stream, &request).await?;

    // Read the response
    let response = read_response(stream).await?;

    // For CONNECT requests, expect 200 Connection Established
    if request.is_connect() && response.status_code != 200 {
        bail!(
            "HTTP CONNECT failed: {} {}",
            response.status_code,
            response.reason_phrase
        );
    }

    Ok(())
}

/// Send error response and close connection
async fn send_error_response_and_close(
    stream: &mut IOBufStream,
    status_code: u16,
    status_text: &str,
) {
    debug!(
        "HTTP/1.1: Sending {} {} error response",
        status_code, status_text
    );
    let error_response =
        HttpResponse::new(HttpVersion::Http1_1, status_code, status_text.to_string());

    if let Err(e) = send_response(stream, &error_response).await {
        warn!("HTTP/1.1: Failed to send error response: {}", e);
        return;
    }

    debug!("HTTP/1.1: Error response sent successfully, flushing");
    // Ensure error response is sent immediately
    if let Err(e) = stream.flush().await {
        warn!("HTTP/1.1: Failed to flush error response: {}", e);
    } else {
        debug!("HTTP/1.1: Error response flushed successfully");
    }
}

/// Validate forward proxy request for early error detection
fn validate_forward_request(request: &HttpRequest) -> Result<()> {
    // Extract target address from forward proxy request for validation
    if request.uri.starts_with("http://") || request.uri.starts_with("https://") {
        // Absolute URI - validate URL parsing
        let url = url::Url::parse(&request.uri).map_err(|e| {
            anyhow::anyhow!("Failed to parse resource URI '{}': {}", request.uri, e)
        })?;

        if url.host_str().is_none() {
            return Err(anyhow::anyhow!(
                "Missing host in resource URI '{}'",
                request.uri
            ));
        }

        if url.port_or_known_default().is_none() {
            return Err(anyhow::anyhow!(
                "Missing port in resource URI '{}'",
                request.uri
            ));
        }
    } else {
        // Relative path: validate Host header
        let host_header = request.get_header("Host").ok_or_else(|| {
            anyhow::anyhow!(
                "Missing Host header for relative resource path '{}'",
                request.uri
            )
        })?;

        // Validate Host header format - add default port if missing
        let target_with_port = if host_header.contains(':') {
            host_header.clone()
        } else {
            // Default to port 80 for HTTP requests
            format!("{}:80", host_header)
        };

        target_with_port
            .parse::<crate::context::TargetAddress>()
            .map_err(|e| anyhow::anyhow!("Failed to parse Host header '{}': {}", host_header, e))?;
    }

    Ok(())
}

/// Check if client expects 100 Continue response
pub fn expects_100_continue(request: &HttpRequest) -> bool {
    if let Some(expect_header) = request.get_header("Expect") {
        expect_header.to_lowercase().contains("100-continue")
    } else {
        false
    }
}

/// Check if HTTP connection should stay alive based on request/response headers
pub fn should_keep_alive(request: &HttpRequest, _response: &HttpResponse) -> bool {
    // Check request Connection header
    if let Some(conn) = request.get_header("Connection") {
        return conn.to_lowercase().contains("keep-alive");
    }
    // Check Proxy-Connection header for compatibility with older clients
    if let Some(proxy_conn) = request.get_header("Proxy-Connection") {
        return proxy_conn.to_lowercase().contains("keep-alive");
    }
    if request.version == HttpVersion::Http1_0 {
        // HTTP/1.0 defaults to close unless keep-alive is specified
        return false;
    }
    // HTTP/1.1 defaults to keep-alive
    true
}

/// Prepare HTTP response for sending to client
pub fn prepare_client_response(response: &mut HttpResponse, client_keep_alive: bool) {
    // Special handling for WebSocket upgrade responses (101 Switching Protocols)
    if response.status_code == 101 {
        // For WebSocket upgrades, preserve the Upgrade and Connection headers
        // Only remove other hop-by-hop headers
        response.remove_header("Keep-Alive");
        response.remove_header("Proxy-Authenticate");
        // Do NOT remove Connection or Upgrade headers for WebSocket upgrades
        return;
    }

    // Remove server hop-by-hop headers for normal HTTP responses
    response.remove_header("Connection");
    response.remove_header("Keep-Alive");
    response.remove_header("Proxy-Authenticate");

    // Set client connection behavior for normal HTTP responses
    if client_keep_alive {
        response.set_header("Connection".to_string(), "keep-alive".to_string());
    } else {
        response.set_header("Connection".to_string(), "close".to_string());
    }
}

/// Prepare HTTP request for sending to server using common infrastructure
pub fn prepare_server_request(
    request: &mut HttpRequest,
    ctx: &crate::context::Context,
    client_addr: std::net::SocketAddr,
) {
    // Remove hop-by-hop headers first
    request.remove_header("Proxy-Authorization");
    request.remove_header("Proxy-Authenticate");
    request.remove_header("TE");
    request.remove_header("Trailer");
    // Connection and Keep-Alive will be set by set_connection_headers()
    // Keep "Upgrade" for WebSocket support - set_connection_headers handles this

    // Add proxy identification and forwarding headers using common functions
    add_proxy_headers(request, ctx, client_addr.ip());

    // Set connection management headers based on protocol and context
    set_connection_headers(request, ctx);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{IOBufStream, make_buffered_stream};
    use crate::protocols::http::context_ext::HttpContextExt;
    use std::sync::Arc;
    use test_log::test;
    use tokio_test::io::Builder;

    fn make_test_stream(data: &[u8]) -> IOBufStream {
        let mock_stream = Builder::new().read(data).build();
        make_buffered_stream(mock_stream)
    }

    #[test(tokio::test)]
    async fn test_parse_request_line() {
        let result = parse_request_line("GET /path HTTP/1.1").await.unwrap();
        assert_eq!(result.0, HttpMethod::Get);
        assert_eq!(result.1, "/path");
        assert_eq!(result.2, HttpVersion::Http1_1);

        let result = parse_request_line("CONNECT example.com:443 HTTP/1.1")
            .await
            .unwrap();
        assert_eq!(result.0, HttpMethod::Connect);
        assert_eq!(result.1, "example.com:443");
        assert_eq!(result.2, HttpVersion::Http1_1);

        // Test invalid request line
        assert!(parse_request_line("INVALID").await.is_err());
    }

    #[test(tokio::test)]
    async fn test_parse_status_line() {
        let result = parse_status_line("HTTP/1.1 200 OK").await.unwrap();
        assert_eq!(result.0, HttpVersion::Http1_1);
        assert_eq!(result.1, 200);
        assert_eq!(result.2, "OK");

        let result = parse_status_line("HTTP/1.1 404 Not Found").await.unwrap();
        assert_eq!(result.0, HttpVersion::Http1_1);
        assert_eq!(result.1, 404);
        assert_eq!(result.2, "Not Found");

        // Test invalid status line
        assert!(parse_status_line("INVALID").await.is_err());
    }

    #[test(tokio::test)]
    async fn test_read_headers() {
        let data = b"Content-Type: application/json\r\nContent-Length: 123\r\n\r\n";
        let mut stream = make_test_stream(data);

        let headers = read_headers(&mut stream).await.unwrap();
        assert_eq!(headers.len(), 2);
        assert_eq!(
            headers[0],
            ("Content-Type".to_string(), "application/json".to_string())
        );
        assert_eq!(
            headers[1],
            ("Content-Length".to_string(), "123".to_string())
        );
    }

    #[test(tokio::test)]
    async fn test_read_request() {
        let data = b"GET /test HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive\r\n\r\n";
        let mut stream = make_test_stream(data);

        let request = read_request(&mut stream).await.unwrap().unwrap();
        assert_eq!(request.method, HttpMethod::Get);
        assert_eq!(request.uri, "/test");
        assert_eq!(request.version, HttpVersion::Http1_1);
        assert_eq!(request.get_header("Host").unwrap(), "example.com");
        assert_eq!(request.get_header("Connection").unwrap(), "keep-alive");
    }

    #[test(tokio::test)]
    async fn test_read_response() {
        let data = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\n\r\n";
        let mut stream = make_test_stream(data);

        let response = read_response(&mut stream).await.unwrap();
        assert_eq!(response.version, HttpVersion::Http1_1);
        assert_eq!(response.status_code, 200);
        assert_eq!(response.reason_phrase, "OK");
        assert_eq!(response.get_header("Content-Type").unwrap(), "text/html");
        assert_eq!(response.get_header("Content-Length").unwrap(), "5");
    }

    #[test(tokio::test)]
    async fn test_read_request_connection_closed() {
        let data = b""; // Empty data simulates closed connection
        let mut stream = make_test_stream(data);

        let result = read_request(&mut stream).await.unwrap();
        assert!(result.is_none()); // Should return None for closed connection
    }

    #[test(tokio::test)]
    async fn test_invalid_http_version_error_handling() {
        // Test that invalid HTTP version triggers proper error response

        // Test with invalid HTTP version
        let invalid_request = "GET /test HTTP/999.999\r\nHost: example.com\r\n\r\n";
        let mut stream = make_test_stream(invalid_request.as_bytes());

        let result = read_request(&mut stream).await;
        assert!(result.is_err());

        // Verify the error message contains information about unsupported HTTP version
        let error_msg = result.err().unwrap().to_string();
        assert!(error_msg.contains("Unsupported HTTP version"));
        assert!(error_msg.contains("HTTP/999.999"));
    }

    #[test(tokio::test)]
    async fn test_invalid_request_line_error_handling() {
        // Test that malformed request line triggers proper error response

        // Test with invalid request line (missing parts)
        let invalid_request = "INVALID REQUEST\r\nHost: example.com\r\n\r\n";
        let mut stream = make_test_stream(invalid_request.as_bytes());

        let result = read_request(&mut stream).await;
        assert!(result.is_err());

        // Verify the error message contains information about invalid request line
        let error_msg = result.err().unwrap().to_string();
        assert!(error_msg.contains("Invalid request line"));
    }

    #[test]
    fn test_expects_100_continue_detection() {
        // Test the expects_100_continue helper function
        let mut request = HttpRequest::new(
            HttpMethod::Post,
            "http://example.com/test".to_string(),
            HttpVersion::Http1_1,
        );

        // No Expect header
        assert!(!expects_100_continue(&request));

        // With 100-continue (lowercase)
        request.add_header("Expect".to_string(), "100-continue".to_string());
        assert!(expects_100_continue(&request));

        // With 100-continue (mixed case)
        request.set_header("Expect".to_string(), "100-Continue".to_string());
        assert!(expects_100_continue(&request));

        // With other expect value
        request.set_header("Expect".to_string(), "something-else".to_string());
        assert!(!expects_100_continue(&request));
    }

    #[test]
    fn test_should_keep_alive() {
        let mut request = HttpRequest::new(
            HttpMethod::Get,
            "http://example.com/test".to_string(),
            HttpVersion::Http1_1,
        );
        let mut response = HttpResponse::new(HttpVersion::Http1_1, 200, "OK".to_string());

        // Default HTTP/1.1 should keep alive
        assert!(should_keep_alive(&request, &response));

        // Response Connection: close should not override request keep-alive
        response.set_header("Connection".to_string(), "close".to_string());
        assert!(should_keep_alive(&request, &response));

        // Request Connection: keep-alive should work when response doesn't specify
        response.remove_header("Connection");
        request.add_header("Connection".to_string(), "keep-alive".to_string());
        assert!(should_keep_alive(&request, &response));
    }

    #[test]
    fn test_should_keep_alive_proxy_connection() {
        let mut request = HttpRequest::new(
            HttpMethod::Get,
            "http://example.com/test".to_string(),
            HttpVersion::Http1_1,
        );
        let response = HttpResponse::new(HttpVersion::Http1_1, 200, "OK".to_string());

        // Test 1: Proxy-Connection: keep-alive should keep connection alive
        request.add_header("Proxy-Connection".to_string(), "keep-alive".to_string());
        assert!(should_keep_alive(&request, &response));

        // Test 2: Proxy-Connection: close should NOT keep connection alive
        request.set_header("Proxy-Connection".to_string(), "close".to_string());
        assert!(!should_keep_alive(&request, &response));

        // Test 3: Connection header takes precedence over Proxy-Connection
        request.add_header("Connection".to_string(), "keep-alive".to_string());
        request.set_header("Proxy-Connection".to_string(), "close".to_string());
        assert!(should_keep_alive(&request, &response));

        // Test 4: Case insensitive Proxy-Connection header
        request.remove_header("Connection");
        request.set_header("Proxy-Connection".to_string(), "Keep-Alive".to_string());
        assert!(should_keep_alive(&request, &response));

        // Test 5: Proxy-Connection with multiple values containing keep-alive
        request.set_header(
            "Proxy-Connection".to_string(),
            "upgrade, keep-alive".to_string(),
        );
        assert!(should_keep_alive(&request, &response));

        // Test 6: Clear request for default HTTP/1.1 behavior after Proxy-Connection tests
        request.remove_header("Proxy-Connection");
        assert!(should_keep_alive(&request, &response));
    }

    #[tokio::test]
    async fn test_prepare_server_request() {
        let mut request = HttpRequest::new(
            HttpMethod::Get,
            "http://example.com/test".to_string(),
            HttpVersion::Http1_1,
        );

        // Add some hop-by-hop headers
        request.add_header("Connection".to_string(), "keep-alive".to_string());
        request.add_header(
            "Proxy-Authorization".to_string(),
            "Bearer token".to_string(),
        );

        // Create a test context with HTTP properties
        let contexts = Arc::new(ContextManager::default());
        let source = "127.0.0.1:1234".parse().unwrap();
        let ctx = contexts.create_context("test".to_string(), source).await;
        {
            let mut ctx_write = ctx.write().await;
            ctx_write
                .set_http_protocol("http/1.1")
                .set_http_keep_alive(true);
        }

        let client_addr = "192.168.1.100:12345".parse().unwrap();
        let ctx_read = ctx.read().await;
        prepare_server_request(&mut request, &ctx_read, client_addr);

        // Hop-by-hop headers should be removed
        assert!(request.get_header("Proxy-Authorization").is_none());

        // Should have Via header (with redproxy identifier)
        assert!(request.get_header("Via").is_some());
        let via_header = request.get_header("Via").unwrap();
        assert!(via_header.starts_with("1.1 redproxy-")); // Random ID suffix

        // Should have X-Forwarded-For
        assert!(request.get_header("X-Forwarded-For").is_some());
        assert_eq!(
            request.get_header("X-Forwarded-For").unwrap(),
            "192.168.1.100"
        );

        // Should have Connection: keep-alive based on context setting
        assert_eq!(request.get_header("Connection").unwrap(), "keep-alive");
    }

    #[tokio::test]
    async fn test_prepare_server_request_websocket() {
        let mut request = HttpRequest::new(
            HttpMethod::Get,
            "ws://example.com/websocket".to_string(),
            HttpVersion::Http1_1,
        );

        // Add WebSocket upgrade headers
        request.add_header("Connection".to_string(), "Upgrade".to_string());
        request.add_header("Upgrade".to_string(), "websocket".to_string());
        request.add_header("Sec-WebSocket-Key".to_string(), "test-key".to_string());
        request.add_header(
            "Proxy-Authorization".to_string(),
            "Bearer token".to_string(),
        );

        // Create a test context
        let contexts = Arc::new(ContextManager::default());
        let source = "127.0.0.1:1234".parse().unwrap();
        let ctx = contexts.create_context("test".to_string(), source).await;
        {
            let mut ctx_write = ctx.write().await;
            ctx_write.set_http_protocol("http/1.1");
        }

        let client_addr = "192.168.1.100:12345".parse().unwrap();
        let ctx_read = ctx.read().await;
        prepare_server_request(&mut request, &ctx_read, client_addr);

        // Hop-by-hop headers should be removed except for WebSocket-specific ones
        assert!(request.get_header("Proxy-Authorization").is_none());

        // Should have Via header (with redproxy identifier)
        assert!(request.get_header("Via").is_some());
        let via_header = request.get_header("Via").unwrap();
        assert!(via_header.starts_with("1.1 redproxy-")); // Random ID suffix

        // Should have X-Forwarded-For
        assert!(request.get_header("X-Forwarded-For").is_some());
        assert_eq!(
            request.get_header("X-Forwarded-For").unwrap(),
            "192.168.1.100"
        );

        // WebSocket headers should be preserved
        assert_eq!(request.get_header("Upgrade").unwrap(), "websocket");
        assert_eq!(request.get_header("Sec-WebSocket-Key").unwrap(), "test-key");

        // Connection header should be preserved as Upgrade for WebSocket requests
        assert_eq!(request.get_header("Connection").unwrap(), "Upgrade");
    }

    #[test]
    fn test_prepare_client_response_websocket_handling() {
        // Test that prepare_client_response handles WebSocket 101 responses correctly
        // Test 1: Normal HTTP response should get Connection: close
        let mut normal_response = HttpResponse::new(HttpVersion::Http1_1, 200, "OK".to_string());
        normal_response.add_header("Connection".to_string(), "keep-alive".to_string());
        normal_response.add_header("Keep-Alive".to_string(), "timeout=5".to_string());

        prepare_client_response(&mut normal_response, false);

        assert_eq!(normal_response.get_header("Connection").unwrap(), "close");
        assert!(
            normal_response.get_header("Keep-Alive").is_none(),
            "Keep-Alive should be removed"
        );

        // Test 2: WebSocket 101 response should preserve Connection: Upgrade
        let mut ws_response =
            HttpResponse::new(HttpVersion::Http1_1, 101, "Switching Protocols".to_string());
        ws_response.add_header("Connection".to_string(), "Upgrade".to_string());
        ws_response.add_header("Upgrade".to_string(), "websocket".to_string());
        ws_response.add_header(
            "Sec-WebSocket-Accept".to_string(),
            "test-accept".to_string(),
        );
        ws_response.add_header("Keep-Alive".to_string(), "timeout=5".to_string());

        prepare_client_response(&mut ws_response, false); // client_keep_alive doesn't matter for 101

        // WebSocket headers should be preserved
        assert_eq!(
            ws_response.get_header("Connection").unwrap(),
            "Upgrade",
            "Connection: Upgrade should be preserved"
        );
        assert_eq!(
            ws_response.get_header("Upgrade").unwrap(),
            "websocket",
            "Upgrade header should be preserved"
        );
        assert_eq!(
            ws_response.get_header("Sec-WebSocket-Accept").unwrap(),
            "test-accept",
            "WebSocket-specific headers should be preserved"
        );

        // Other hop-by-hop headers should still be removed
        assert!(
            ws_response.get_header("Keep-Alive").is_none(),
            "Keep-Alive should be removed even for WebSocket"
        );

        // Test 3: WebSocket 101 response with client_keep_alive=true should still preserve WebSocket headers
        let mut ws_response2 =
            HttpResponse::new(HttpVersion::Http1_1, 101, "Switching Protocols".to_string());
        ws_response2.add_header("Connection".to_string(), "Upgrade".to_string());
        ws_response2.add_header("Upgrade".to_string(), "websocket".to_string());

        prepare_client_response(&mut ws_response2, true); // Should not affect WebSocket handling

        assert_eq!(
            ws_response2.get_header("Connection").unwrap(),
            "Upgrade",
            "WebSocket Connection header should be preserved regardless of keep_alive"
        );
        assert_eq!(
            ws_response2.get_header("Upgrade").unwrap(),
            "websocket",
            "WebSocket Upgrade header should be preserved"
        );
    }
}
