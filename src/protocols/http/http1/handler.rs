use anyhow::{Result, bail};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tracing::{debug, warn};

use crate::context::{ContextManager, ContextRef, ContextRefOps, IOBufStream, TargetAddress};
use crate::protocols::http::{HttpMethod, HttpRequest, HttpResponse, HttpVersion};

use super::callback::{Http1ResponseCallback, HttpProxyMode};
use super::stream::HttpClientStream;

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
            "HTTP/1.1" => HttpVersion::Http1,
            "HTTP/1.0" => HttpVersion::Http1,
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
            "HTTP/1.1" => HttpVersion::Http1,
            "HTTP/1.0" => HttpVersion::Http1,
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

    async fn read_headers<T>(stream: &mut T) -> Result<Vec<(String, String)>>
    where
        T: AsyncBufReadExt + Unpin,
    {
        let mut headers = Vec::new();
        let mut line = String::new();

        loop {
            line.clear();
            let bytes_read = stream.read_line(&mut line).await?;
            if bytes_read == 0 {
                bail!("Unexpected end of stream");
            }

            let line = line.trim_end();
            if line.is_empty() {
                break; // End of headers
            }

            if let Some(colon_pos) = line.find(':') {
                let name = line[..colon_pos].trim().to_string();
                let value = line[colon_pos + 1..].trim().to_string();
                headers.push((name, value));
            } else {
                bail!("Invalid header line: {}", line);
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
        let mut current_stream = stream;

        // HTTP/1.1 keep-alive loop: handle multiple requests on same connection
        loop {
            // 1. Create temporary buffered stream for reading this request
            let mut temp_buffered = BufReader::new(BufWriter::new(current_stream));

            // 2. Read next request from connection with error handling
            let request = match self.read_request(&mut temp_buffered).await {
                Ok(Some(req)) => req,
                Ok(None) => {
                    debug!("HTTP/1.1: Client closed connection");
                    break; // Connection closed by client
                }
                Err(e) => {
                    // HTTP parsing error - send 400 Bad Request response
                    warn!("HTTP/1.1: Request parsing error: {}", e);
                    
                    // Extract stream to send error response
                    let extracted_stream = {
                        let mut buf_writer = temp_buffered.into_inner();
                        if let Err(flush_err) = buf_writer.flush().await {
                            warn!("HTTP/1.1: Failed to flush before sending error response: {}", flush_err);
                        }
                        buf_writer.into_inner()
                    };
                    
                    // Send 400 Bad Request response
                    let mut stream_for_error = crate::context::make_buffered_stream(extracted_stream);
                    let error_response = crate::protocols::http::HttpResponse::new(
                        crate::protocols::http::HttpVersion::Http1,
                        400,
                        "Bad Request".to_string()
                    );
                    
                    if let Err(send_err) = self.send_response(&mut stream_for_error, &error_response).await {
                        warn!("HTTP/1.1: Failed to send error response: {}", send_err);
                    }
                    
                    break; // Close connection after sending error response
                }
            };

            debug!(
                "HTTP/1.1: Received request {} {} on keep-alive connection",
                request.method, request.uri
            );

            // 3. Check if client wants keep-alive
            let should_keep_alive = self.should_keep_alive(&request);

            // 4. Create context for THIS REQUEST (not connection!)
            let ctx = contexts.create_context(listener_name.clone(), source).await;

            // 5. Handle this single request
            if request.is_connect() {
                // CONNECT tunneling: pass buffered stream directly and end keep-alive loop
                self.handle_connect_request(ctx, request, temp_buffered, &queue)
                    .await?;
                break; // End keep-alive loop - connection is now tunneled
            } else {
                // Forward proxy: extract stream and use oneshot channel for ownership transfer
                let (completion_tx, completion_rx) =
                    tokio::sync::oneshot::channel::<Box<dyn crate::context::IOStream>>();

                // Extract any buffered body data before unwrapping the BufReader
                let buffered_body_data = {
                    let buffer = temp_buffered.buffer();
                    if buffer.is_empty() {
                        None
                    } else {
                        Some(buffer.to_vec())
                    }
                };

                // Validate forward proxy request before creating wrapper
                if let Err(e) = self.validate_forward_request(&request) {
                    warn!("HTTP/1.1: Forward request validation failed: {}", e);
                    
                    // Send error response using the extracted stream directly
                    let extracted_stream = {
                        let mut buf_writer = temp_buffered.into_inner();
                        buf_writer.flush().await?;
                        buf_writer.into_inner()
                    };
                    
                    let mut error_stream = crate::context::make_buffered_stream(extracted_stream);
                    let error_response = crate::protocols::http::HttpResponse::new(
                        crate::protocols::http::HttpVersion::Http1,
                        400,
                        "Bad Request".to_string()
                    );
                    
                    if let Err(send_err) = self.send_response(&mut error_stream, &error_response).await {
                        warn!("HTTP/1.1: Failed to send error response: {}", send_err);
                    }
                    
                    break; // Close connection after error response
                }

                // Extract the original stream from buffered wrapper
                let extracted_stream = {
                    // Flush any pending writes
                    let mut buf_writer = temp_buffered.into_inner();
                    buf_writer.flush().await?;
                    buf_writer.into_inner()
                };

                // Create wrapper that will return the stream via oneshot channel
                let mut wrapper = HttpClientStream::new(
                    extracted_stream,
                    Box::new(move |stream| {
                        let _ = completion_tx.send(stream); // Send the extracted stream back
                    }),
                );

                // Pre-populate the wrapper with any buffered body data
                if let Some(body_data) = buffered_body_data {
                    debug!("HTTP/1.1: Pre-populating client stream with {} bytes of buffered body data", body_data.len());
                    wrapper.pre_populate_read_buffer(&body_data);
                }

                // Create buffered stream from wrapper for context
                let wrapped_client_stream = crate::context::make_buffered_stream(wrapper);

                // Handle forward request - validation already done above
                self.handle_forward_request(ctx, request, wrapped_client_stream, &queue)
                    .await?;

                // Wait for response completion and stream return before processing next request
                match completion_rx.await {
                    Ok(returned_stream) => {
                        debug!("HTTP/1.1: Request completed successfully");
                        current_stream = returned_stream; // Get stream back for next keep-alive request
                    }
                    Err(_) => {
                        warn!("HTTP/1.1: Request completion notification failed");
                        break; // Connection likely broken
                    }
                }

                if !should_keep_alive {
                    debug!("HTTP/1.1: Connection close requested, ending keep-alive loop");
                    break;
                }
            }
            // Loop continues with same TCP connection for next request
        }

        debug!("HTTP/1.1: Connection handling completed for {}", source);
        Ok(())
    }

    pub async fn read_request<T>(&self, stream: &mut T) -> Result<Option<HttpRequest>>
    where
        T: AsyncBufReadExt + Unpin,
    {
        let mut line = String::new();

        // Read request line
        let bytes_read = stream.read_line(&mut line).await?;
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
            HttpRequest::new(HttpMethod::Connect, target.to_string(), HttpVersion::Http1)
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

    /// Check if client wants keep-alive connection
    fn should_keep_alive(&self, request: &HttpRequest) -> bool {
        match request.get_header("Connection") {
            Some(value) if value.eq_ignore_ascii_case("close") => false,
            Some(value) if value.eq_ignore_ascii_case("keep-alive") => true,
            None => {
                // HTTP/1.1 defaults to keep-alive, HTTP/1.0 defaults to close
                matches!(request.version, HttpVersion::Http1)
            }
            _ => false,
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
                return Err(anyhow::anyhow!("Missing host in resource URI '{}'", request.uri));
            }
            
            if url.port_or_known_default().is_none() {
                return Err(anyhow::anyhow!("Missing port in resource URI '{}'", request.uri));
            }
        } else {
            // Relative path: validate Host header
            let host_header = request.get_header("Host").ok_or_else(|| {
                anyhow::anyhow!(
                    "Missing Host header for relative resource path '{}'",
                    request.uri
                )
            })?;
            
            // Validate Host header format
            host_header.parse::<crate::context::TargetAddress>().map_err(|e| {
                anyhow::anyhow!("Failed to parse Host header '{}': {}", host_header, e)
            })?;
        }
        
        Ok(())
    }

    /// Handle CONNECT tunneling request
    async fn handle_connect_request(
        &self,
        ctx: ContextRef,
        request: HttpRequest,
        stream: IOBufStream,
        queue: &tokio::sync::mpsc::Sender<ContextRef>,
    ) -> Result<()> {
        // Extract target address from CONNECT request
        let target_addr = if let Some(colon_pos) = request.uri.find(':') {
            let host = &request.uri[..colon_pos];
            let port_str = &request.uri[colon_pos + 1..];
            let port: u16 = port_str.parse().map_err(|e| {
                anyhow::anyhow!("Failed to parse CONNECT port '{}': {}", port_str, e)
            })?;
            TargetAddress::DomainPort(host.to_string(), port)
        } else {
            return Err(anyhow::anyhow!(
                "Invalid CONNECT target format '{}', expected 'host:port'",
                request.uri
            ));
        };

        // Create dummy callback (no completion needed for CONNECT)
        let (dummy_tx, _dummy_rx) = tokio::sync::oneshot::channel();
        let callback = Http1ResponseCallback::new(dummy_tx, HttpProxyMode::Connect);

        // Store request, target address, client stream, and callback in context
        {
            let mut ctx_guard = ctx.write().await;
            ctx_guard.set_http_request(request);
            ctx_guard.set_target(target_addr);
            ctx_guard.set_client_stream(stream);
            ctx_guard.set_feature(crate::context::Feature::TcpForward);
            ctx_guard.set_callback(callback);
        }

        // Queue for rules engine processing
        if let Err(e) = ctx.enqueue(queue).await {
            warn!("HTTP/1.1: Failed to enqueue CONNECT context: {}", e);
            return Err(e);
        }

        Ok(())
    }

    /// Handle HTTP forward proxy request
    async fn handle_forward_request(
        &self,
        ctx: ContextRef,
        request: HttpRequest,
        wrapped_client_stream: IOBufStream,
        queue: &tokio::sync::mpsc::Sender<ContextRef>,
    ) -> Result<()> {
        // Extract target address from forward proxy request
        let target_addr =
            if request.uri.starts_with("http://") || request.uri.starts_with("https://") {
                // Absolute URI (e.g., "http://example.com/path")
                let url = url::Url::parse(&request.uri).map_err(|e| {
                    anyhow::anyhow!("Failed to parse resource URI '{}': {}", request.uri, e)
                })?;
                let host = url.host_str().ok_or_else(|| {
                    anyhow::anyhow!("Missing host in resource URI '{}'", request.uri)
                })?;
                let port = url.port_or_known_default().ok_or_else(|| {
                    anyhow::anyhow!("Missing port in resource URI '{}'", request.uri)
                })?;
                TargetAddress::DomainPort(host.to_string(), port)
            } else {
                // Relative path: use Host header
                let host_header = request.get_header("Host").ok_or_else(|| {
                    anyhow::anyhow!(
                        "Missing Host header for relative resource path '{}'",
                        request.uri
                    )
                })?;
                host_header.parse().map_err(|e| {
                    anyhow::anyhow!("Failed to parse Host header '{}': {}", host_header, e)
                })?
            };

        // Create dummy callback (completion handled by wrapper)
        let (dummy_tx, _dummy_rx) = tokio::sync::oneshot::channel();
        let callback = Http1ResponseCallback::new(dummy_tx, HttpProxyMode::Forward);

        // Store request, target address, wrapped client stream, and callback in context
        {
            let mut ctx_guard = ctx.write().await;
            ctx_guard.set_http_request(request);
            ctx_guard.set_target(target_addr);
            ctx_guard.set_client_stream(wrapped_client_stream);
            ctx_guard.set_feature(crate::context::Feature::TcpForward);
            ctx_guard.set_callback(callback);
        }

        // Queue for rules engine processing
        if let Err(e) = ctx.enqueue(queue).await {
            warn!("HTTP/1.1: Failed to enqueue forward context: {}", e);
            return Err(e);
        }

        Ok(())
    }
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
        assert_eq!(result.2, HttpVersion::Http1);

        let result = Http1Handler::parse_request_line("CONNECT example.com:443 HTTP/1.1")
            .await
            .unwrap();
        assert_eq!(result.0, HttpMethod::Connect);
        assert_eq!(result.1, "example.com:443");
        assert_eq!(result.2, HttpVersion::Http1);

        // Test invalid request line
        assert!(Http1Handler::parse_request_line("INVALID").await.is_err());
    }

    #[test(tokio::test)]
    async fn test_parse_status_line() {
        let result = Http1Handler::parse_status_line("HTTP/1.1 200 OK")
            .await
            .unwrap();
        assert_eq!(result.0, HttpVersion::Http1);
        assert_eq!(result.1, 200);
        assert_eq!(result.2, "OK");

        let result = Http1Handler::parse_status_line("HTTP/1.1 404 Not Found")
            .await
            .unwrap();
        assert_eq!(result.0, HttpVersion::Http1);
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
        assert_eq!(request.version, HttpVersion::Http1);
        assert_eq!(request.get_header("Host").unwrap(), "example.com");
        assert_eq!(request.get_header("Connection").unwrap(), "keep-alive");
    }

    #[test(tokio::test)]
    async fn test_read_response() {
        let data = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\n\r\n";
        let mut stream = make_test_stream(data);
        let handler = Http1Handler::new();

        let response = handler.read_response(&mut stream).await.unwrap();
        assert_eq!(response.version, HttpVersion::Http1);
        assert_eq!(response.status_code, 200);
        assert_eq!(response.reason_phrase, "OK");
        assert_eq!(response.get_header("Content-Type").unwrap(), "text/html");
        assert_eq!(response.get_header("Content-Length").unwrap(), "5");
    }

    #[test]
    fn test_should_keep_alive() {
        let handler = Http1Handler::new();

        // Test explicit close
        let mut request = HttpRequest::new(HttpMethod::Get, "/".to_string(), HttpVersion::Http1);
        request.add_header("Connection".to_string(), "close".to_string());
        assert!(!handler.should_keep_alive(&request));

        // Test explicit keep-alive
        let mut request = HttpRequest::new(HttpMethod::Get, "/".to_string(), HttpVersion::Http1);
        request.add_header("Connection".to_string(), "keep-alive".to_string());
        assert!(handler.should_keep_alive(&request));

        // Test HTTP/1.1 default (should be keep-alive)
        let request = HttpRequest::new(HttpMethod::Get, "/".to_string(), HttpVersion::Http1);
        assert!(handler.should_keep_alive(&request));
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
