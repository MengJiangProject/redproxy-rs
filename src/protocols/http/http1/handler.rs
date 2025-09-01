use anyhow::{Result, bail};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tracing::{debug, warn};

use crate::context::{ContextManager, ContextRef, ContextRefOps, IOBufStream, TargetAddress};
use crate::protocols::http::{HttpMessage, HttpMethod, HttpRequest, HttpResponse, HttpVersion};

use super::callback::{Http1Callback, HttpProxyMode};

/// HTTP/1.1 protocol handler
#[derive(Debug, Default)]
pub struct Http1Handler;

impl Http1Handler {
    pub fn new() -> Self {
        Self
    }

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

    pub async fn handle_listener_connection(
        &self,
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
            let request = match self.read_request(&mut current_stream).await {
                Ok(Some(req)) => req,
                Ok(None) => {
                    debug!("HTTP/1.1: Client closed connection gracefully");
                    break;
                }
                Err(e) => {
                    warn!("HTTP/1.1: Request parsing error: {}", e);
                    self.send_error_response_and_close(&mut current_stream, 400, "Bad Request")
                        .await;
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
                && let Err(e) = self.validate_forward_request(&request)
            {
                warn!("HTTP/1.1: Request validation failed: {}", e);
                self.send_error_response_and_close(&mut current_stream, 400, "Bad Request")
                    .await;
                break;
            }

            // Extract target address
            let target = match self.extract_target(&request) {
                Ok(target) => target,
                Err(e) => {
                    warn!("HTTP/1.1: Failed to extract target: {}", e);
                    self.send_error_response_and_close(&mut current_stream, 400, "Bad Request")
                        .await;
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

    pub async fn read_request(
        &self,
        stream: &mut crate::io::IOBufStream,
    ) -> Result<Option<HttpRequest>> {
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
        let (method, uri, version) = Self::parse_request_line(line).await?;

        // Parse headers
        let headers = Self::read_headers(stream).await?;

        let mut request = HttpRequest::new(method, uri, version);
        for (name, value) in headers {
            request.add_header(name, value);
        }

        Ok(Some(request))
    }

    pub async fn send_request(
        &self,
        stream: &mut IOBufStream,
        request: &HttpRequest,
    ) -> Result<()> {
        let request_line = format!("{} {} {}\r\n", request.method, request.uri, request.version);
        AsyncWriteExt::write_all(stream, request_line.as_bytes()).await?;

        for (name, value) in &request.headers {
            let header_line = format!("{}: {}\r\n", name, value);
            AsyncWriteExt::write_all(stream, header_line.as_bytes()).await?;
        }

        AsyncWriteExt::write_all(stream, b"\r\n").await?;
        AsyncWriteExt::flush(stream).await?;

        Ok(())
    }

    pub async fn read_response(&self, stream: &mut IOBufStream) -> Result<HttpResponse> {
        let mut line = String::new();

        // Read status line
        let bytes_read = stream.read_line(&mut line).await?;
        if bytes_read == 0 {
            bail!("Unexpected end of stream");
        }

        let line = line.trim_end();
        let (version, status_code, reason_phrase) = Self::parse_status_line(line).await?;

        // Parse headers
        let headers = Self::read_headers(stream).await?;

        let mut response = HttpResponse::new(version, status_code, reason_phrase);
        for (name, value) in headers {
            response.add_header(name, value);
        }

        Ok(response)
    }

    pub async fn send_response(
        &self,
        stream: &mut IOBufStream,
        response: &HttpResponse,
    ) -> Result<()> {
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

    pub async fn handle_listener(
        &self,
        stream: &mut IOBufStream,
        _ctx: ContextRef,
    ) -> Result<HttpRequest> {
        match self.read_request(stream).await? {
            Some(request) => Ok(request),
            None => bail!("No request received from client"),
        }
    }

    pub async fn handle_connector(&self, stream: &mut IOBufStream, ctx: ContextRef) -> Result<()> {
        let ctx_read = ctx.read().await;

        // Check if we have an existing HTTP request (forward proxy case)
        let request = if let Some(http_request) = ctx_read.http_request() {
            // HTTP Forward Proxy: use existing request
            http_request.as_ref().clone()
        } else {
            // SOCKS/Other → HTTP: create CONNECT request from target
            let target = ctx_read.target();
            HttpRequest::new(
                HttpMethod::Connect,
                target.to_string(),
                HttpVersion::Http1_1,
            )
        };

        drop(ctx_read); // Release the lock

        // Send the request
        self.send_request(stream, &request).await?;

        // Read the response
        let response = self.read_response(stream).await?;

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
        &self,
        stream: &mut IOBufStream,
        status_code: u16,
        status_text: &str,
    ) {
        let error_response =
            HttpResponse::new(HttpVersion::Http1_1, status_code, status_text.to_string());

        if let Err(e) = self.send_response(stream, &error_response).await {
            warn!("HTTP/1.1: Failed to send error response: {}", e);
        }
    }

    /// Extract target address from HTTP request
    fn extract_target(&self, request: &HttpRequest) -> Result<TargetAddress> {
        if request.is_connect() {
            // CONNECT request: target is in URI (host:port format)
            if let Some(colon_pos) = request.uri.find(':') {
                let host = &request.uri[..colon_pos];
                let port_str = &request.uri[colon_pos + 1..];
                let port: u16 = port_str.parse().map_err(|e| {
                    anyhow::anyhow!("Failed to parse CONNECT port '{}': {}", port_str, e)
                })?;
                Ok(TargetAddress::DomainPort(host.to_string(), port))
            } else {
                Err(anyhow::anyhow!(
                    "Invalid CONNECT target format '{}', expected 'host:port'",
                    request.uri
                ))
            }
        } else {
            // Forward proxy request
            if request.uri.starts_with("http://") || request.uri.starts_with("https://") {
                // Absolute URI
                let url = url::Url::parse(&request.uri).map_err(|e| {
                    anyhow::anyhow!("Failed to parse resource URI '{}': {}", request.uri, e)
                })?;
                let host = url.host_str().ok_or_else(|| {
                    anyhow::anyhow!("Missing host in resource URI '{}'", request.uri)
                })?;
                let port = url.port_or_known_default().ok_or_else(|| {
                    anyhow::anyhow!("Missing port in resource URI '{}'", request.uri)
                })?;
                Ok(TargetAddress::DomainPort(host.to_string(), port))
            } else {
                // Relative path: use Host header
                let host_header = request.get_header("Host").ok_or_else(|| {
                    anyhow::anyhow!(
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

                target_with_port.parse().map_err(|e| {
                    anyhow::anyhow!("Failed to parse Host header '{}': {}", host_header, e)
                })
            }
        }
    }

    /// Validate forward proxy request for early error detection
    fn validate_forward_request(&self, request: &HttpRequest) -> Result<()> {
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
                .map_err(|e| {
                    anyhow::anyhow!("Failed to parse Host header '{}': {}", host_header, e)
                })?;
        }

        Ok(())
    }

    // This method is no longer needed - unified handling in handle_listener_connection

    // This method is no longer needed - unified handling in handle_listener_connection
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{IOBufStream, make_buffered_stream};
    use test_log::test;
    use tokio_test::io::Builder;

    fn make_test_stream(data: &[u8]) -> IOBufStream {
        let mock_stream = Builder::new().read(data).build();
        make_buffered_stream(mock_stream)
    }

    #[test(tokio::test)]
    async fn test_parse_request_line() {
        let result = Http1Handler::parse_request_line("GET /path HTTP/1.1")
            .await
            .unwrap();
        assert_eq!(result.0, HttpMethod::Get);
        assert_eq!(result.1, "/path");
        assert_eq!(result.2, HttpVersion::Http1_1);

        let result = Http1Handler::parse_request_line("CONNECT example.com:443 HTTP/1.1")
            .await
            .unwrap();
        assert_eq!(result.0, HttpMethod::Connect);
        assert_eq!(result.1, "example.com:443");
        assert_eq!(result.2, HttpVersion::Http1_1);

        // Test invalid request line
        assert!(Http1Handler::parse_request_line("INVALID").await.is_err());
    }

    #[test(tokio::test)]
    async fn test_parse_status_line() {
        let result = Http1Handler::parse_status_line("HTTP/1.1 200 OK")
            .await
            .unwrap();
        assert_eq!(result.0, HttpVersion::Http1_1);
        assert_eq!(result.1, 200);
        assert_eq!(result.2, "OK");

        let result = Http1Handler::parse_status_line("HTTP/1.1 404 Not Found")
            .await
            .unwrap();
        assert_eq!(result.0, HttpVersion::Http1_1);
        assert_eq!(result.1, 404);
        assert_eq!(result.2, "Not Found");

        // Test invalid status line
        assert!(Http1Handler::parse_status_line("INVALID").await.is_err());
    }

    #[test(tokio::test)]
    async fn test_read_headers() {
        let data = b"Content-Type: application/json\r\nContent-Length: 123\r\n\r\n";
        let mut stream = make_test_stream(data);

        let headers = Http1Handler::read_headers(&mut stream).await.unwrap();
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
        let handler = Http1Handler::new();

        let request = handler.read_request(&mut stream).await.unwrap().unwrap();
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
        let handler = Http1Handler::new();

        let response = handler.read_response(&mut stream).await.unwrap();
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
        let handler = Http1Handler::new();

        let result = handler.read_request(&mut stream).await.unwrap();
        assert!(result.is_none()); // Should return None for closed connection
    }

    #[test(tokio::test)]
    async fn test_invalid_http_version_error_handling() {
        // Test that invalid HTTP version triggers proper error response
        let handler = Http1Handler::new();

        // Test with invalid HTTP version
        let invalid_request = "GET /test HTTP/999.999\r\nHost: example.com\r\n\r\n";
        let mut stream = make_test_stream(invalid_request.as_bytes());

        let result = handler.read_request(&mut stream).await;
        assert!(result.is_err());

        // Verify the error message contains information about unsupported HTTP version
        let error_msg = result.err().unwrap().to_string();
        assert!(error_msg.contains("Unsupported HTTP version"));
        assert!(error_msg.contains("HTTP/999.999"));
    }

    #[test(tokio::test)]
    async fn test_invalid_request_line_error_handling() {
        // Test that malformed request line triggers proper error response
        let handler = Http1Handler::new();

        // Test with invalid request line (missing parts)
        let invalid_request = "INVALID REQUEST\r\nHost: example.com\r\n\r\n";
        let mut stream = make_test_stream(invalid_request.as_bytes());

        let result = handler.read_request(&mut stream).await;
        assert!(result.is_err());

        // Verify the error message contains information about invalid request line
        let error_msg = result.err().unwrap().to_string();
        assert!(error_msg.contains("Invalid request line"));
    }
}
