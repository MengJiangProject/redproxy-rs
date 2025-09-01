#[cfg(feature = "metrics")]
use crate::copy::io_metrics;
use crate::{
    config::IoParams,
    context::{ContextRef, ContextState, ContextStatistics, IOBufStream},
    protocols::http::{HttpMessage, HttpRequest, HttpResponse},
};
use anyhow::{Result, anyhow, bail};
use bytes::BytesMut;
use std::{sync::Arc, time::Duration};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use tracing::{debug, warn};

/// Pair of streams for HTTP body forwarding  
pub type StreamPair = (IOBufStream, IOBufStream);

/// Statistics and metrics context for HTTP operations
#[derive(Clone)]
pub struct StatsContext {
    pub stat: Arc<ContextStatistics>,
    #[cfg(feature = "metrics")]
    pub counter: prometheus::core::GenericCounter<prometheus::core::AtomicU64>,
}

impl Default for StatsContext {
    fn default() -> Self {
        Self {
            stat: Arc::new(ContextStatistics::default()),
            #[cfg(feature = "metrics")]
            counter: prometheus::core::GenericCounter::new("dummy", "dummy").unwrap(),
        }
    }
}

impl StatsContext {
    pub fn new(
        stat: Arc<ContextStatistics>,
        #[cfg(feature = "metrics")] counter: prometheus::core::GenericCounter<
            prometheus::core::AtomicU64,
        >,
    ) -> Self {
        Self {
            stat,
            #[cfg(feature = "metrics")]
            counter,
        }
    }

    pub fn record_bytes(&self, bytes: usize) {
        self.stat.incr_sent_bytes(bytes);
        #[cfg(feature = "metrics")]
        self.counter.inc_by(bytes as u64);
    }
}

/// Forward HTTP body using BufferedStream API
async fn forward_http_body(
    streams: StreamPair,
    http_message: &impl HttpMessage,
    params: &IoParams,
    stats: &StatsContext,
    idle_timeout: Duration,
    cancellation_token: &tokio_util::sync::CancellationToken,
) -> Result<StreamPair> {
    if let Some(content_length_str) = http_message.get_header("Content-Length") {
        let content_length: usize = content_length_str
            .parse()
            .map_err(|e| anyhow!("Invalid Content-Length '{}': {}", content_length_str, e))?;

        if content_length > 0 {
            debug!(
                "HTTP/1.1: Forwarding body with Content-Length: {}",
                content_length
            );
            forward_content_length_body(
                streams,
                content_length,
                params,
                stats,
                idle_timeout,
                cancellation_token,
            )
            .await
        } else {
            // No body to forward
            debug!("HTTP/1.1: Content-Length is 0, no body to forward");
            Ok(streams)
        }
    } else if let Some(transfer_encoding) = http_message.get_header("Transfer-Encoding") {
        debug!(
            "HTTP/1.1: Forwarding body with Transfer-Encoding: {}",
            transfer_encoding
        );
        if transfer_encoding.to_lowercase().contains("chunked") {
            // Chunked: requires parsing - use manual approach
            forward_chunked_body(streams, params, stats, idle_timeout, cancellation_token).await
        } else {
            // Unknown transfer encoding
            Ok(streams)
        }
    } else {
        // No body transfer needed
        debug!("HTTP/1.1: No Content-Length or Transfer-Encoding, no body to forward");
        Ok(streams)
    }
}

/// Forward body with known Content-Length using BufferedStream copy operation
async fn forward_content_length_body(
    streams: StreamPair,
    content_length: usize,
    params: &IoParams,
    stats: &StatsContext,
    idle_timeout: Duration,
    cancellation_token: &tokio_util::sync::CancellationToken,
) -> Result<StreamPair> {
    debug!(
        "HTTP/1.1: Forwarding Content-Length body: {} bytes",
        content_length
    );
    let stats = stats.clone();
    // Use BufferedStream copy operation with size limit and real-time stats
    let (src_stream, dst_stream) = streams;
    let (bytes_copied, src_stream, dst_stream) = src_stream
        .copy_to(dst_stream)
        .max_bytes(content_length)
        .with_io_params(params)
        .idle_timeout(idle_timeout)
        .cancellation_token(cancellation_token.clone())
        .with_stats({
            move |bytes| {
                stats.record_bytes(bytes);
            }
        })
        .execute()
        .await?;

    if bytes_copied != content_length as u64 {
        bail!(
            "HTTP/1.1: Content-Length mismatch: expected {}, copied {}",
            content_length,
            bytes_copied
        );
    }

    debug!(
        "HTTP/1.1: Successfully forwarded Content-Length body: {} bytes",
        bytes_copied
    );

    Ok((src_stream, dst_stream))
}

/// Forward chunked transfer encoding body (requires manual parsing)
/// Returns an error that should cause connection termination
async fn forward_chunked_body(
    streams: StreamPair,
    params: &IoParams,
    stats: &StatsContext,
    idle_timeout: Duration,
    cancellation_token: &tokio_util::sync::CancellationToken,
) -> Result<StreamPair> {
    let (mut src_stream, mut dst_stream) = streams;
    let mut buffer = BytesMut::with_capacity(params.buffer_size);
    buffer.resize(params.buffer_size, 0);
    let mut interval = tokio::time::interval(Duration::from_secs(1));

    loop {
        // Read chunk size line with timeout
        let mut chunk_size_line = String::new();
        tokio::select! {
            biased;
            _ = cancellation_token.cancelled() => {
                bail!("Operation cancelled during chunked transfer");
            }
            result = src_stream.read_line(&mut chunk_size_line) => result?,
            _ = interval.tick(), if !idle_timeout.is_zero() => {
                if stats.stat.is_timeout(idle_timeout) {
                    bail!("Idle timeout during chunked transfer");
                }
                continue;
            }
        };

        // Forward chunk size line
        dst_stream.write_all(chunk_size_line.as_bytes()).await?;

        // Update stats for chunk size line
        stats.record_bytes(chunk_size_line.len());

        let chunk_size_str = chunk_size_line
            .trim()
            .split(';')
            .next()
            .unwrap_or("")
            .trim();

        let chunk_size = usize::from_str_radix(chunk_size_str, 16).map_err(|e| {
            anyhow!(
                "HTTP/1.1: Failed to parse chunk size '{}': {}",
                chunk_size_str,
                e
            )
        })?;

        if chunk_size == 0 {
            // Read trailing headers
            loop {
                let mut trailer_line = String::new();
                src_stream.read_line(&mut trailer_line).await?;
                dst_stream.write_all(trailer_line.as_bytes()).await?;

                // Update stats for trailer
                stats.record_bytes(trailer_line.len());

                if trailer_line.trim().is_empty() {
                    break;
                }
            }
            break;
        }

        // Forward chunk data + CRLF with real-time stats
        let mut remaining = chunk_size + 2; // +2 for CRLF after chunk data

        while remaining > 0 {
            let to_read = buffer.len().min(remaining);
            let bytes_read = tokio::select! {
                biased;
                _ = cancellation_token.cancelled() => {
                    bail!("Operation cancelled during chunk transfer");
                }
                result = src_stream.read(&mut buffer[..to_read]) => result?,
                _ = interval.tick(), if !idle_timeout.is_zero() => {
                    if stats.stat.is_timeout(idle_timeout) {
                        bail!("Idle timeout during chunk transfer");
                    }
                    continue;
                }
            };

            if bytes_read == 0 {
                bail!("Unexpected end of stream while reading chunk");
            }

            dst_stream.write_all(&buffer[..bytes_read]).await?;
            remaining -= bytes_read;

            // Update statistics in real-time
            stats.record_bytes(bytes_read);
        }
    }

    dst_stream.flush().await?;

    debug!("HTTP/1.1: Forwarded body with chunked encoding");

    Ok((src_stream, dst_stream))
}

/// HTTP-specific IO loop that handles ONE request/response cycle
pub fn http_io_loop(
    ctx: ContextRef,
    params: &IoParams,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send>> {
    let params = params.clone();

    Box::pin(async move {
        use crate::protocols::http::http1::handler::Http1Handler;

        // Setup (same pattern as copy_bidi)
        let mut ctx_lock = ctx.write().await;
        let (client_stream, server_stream) = match ctx_lock.take_streams() {
            Some(streams) => streams,
            None => {
                bail!("No streams available for HTTP IO loop");
            }
        };
        let client_stat = ctx_lock.props().client_stat.clone();
        let server_stat = ctx_lock.props().server_stat.clone();
        let request = ctx_lock
            .http_request()
            .ok_or_else(|| anyhow!("No HTTP request in context"))?;
        let idle_timeout = ctx_lock.idle_timeout();
        let cancellation_token = ctx_lock.cancellation_token().clone();

        #[cfg(feature = "metrics")]
        let client_label = ctx_lock.props().listener.clone();
        #[cfg(feature = "metrics")]
        let server_label = ctx_lock
            .props()
            .connector
            .as_ref()
            .ok_or_else(|| anyhow!("No connector information available"))?
            .clone();
        drop(ctx_lock);

        let handler = Http1Handler::new();

        let client_stats = StatsContext::new(
            client_stat.clone(),
            #[cfg(feature = "metrics")]
            io_metrics()
                .client_bytes
                .with_label_values(&[client_label.as_str()]),
        );

        // Forward request body (headers were already sent by callback)
        // Skip body forwarding if client expects 100 Continue (body will be sent after server confirms)
        let (mut client_stream, mut server_stream) = if expects_100_continue(&request) {
            debug!("HTTP/1.1: Skipping initial body forwarding - client expects 100 Continue");
            (client_stream, server_stream)
        } else {
            debug!("HTTP/1.1: Forwarding request body if present");
            match forward_http_body(
                (client_stream, server_stream),
                request.as_ref(),
                &params,
                &client_stats,
                idle_timeout,
                &cancellation_token,
            )
            .await
            {
                Ok(streams) => streams,
                Err(e) => {
                    // Try to send error response to client if parsing failed
                    if let Some(mut client_stream) = ctx.write().await.take_client_stream() {
                        let _ = send_error_response_and_close(
                            &mut client_stream,
                            400,
                            "Bad Request",
                            &format!("Request body parsing failed: {}", e),
                        )
                        .await;
                    }
                    return Err(e);
                }
            }
        };

        // Read server response (handle potential 100 Continue interim responses)
        let mut response = if expects_100_continue(&request) {
            // Client expects 100 Continue - may need to handle interim responses
            debug!("HTTP/1.1: Client expects 100 Continue, handling interim responses");
            loop {
                match handler.read_response(&mut server_stream).await {
                    Ok(resp) => {
                        if resp.status_code == 100 {
                            // 100 Continue interim response - forward to client and then forward body
                            debug!(
                                "HTTP/1.1: Received 100 Continue interim response, forwarding to client"
                            );
                            if let Err(e) = handler.send_response(&mut client_stream, &resp).await {
                                warn!("HTTP/1.1: Failed to forward 100 Continue response: {}", e);
                                return Err(e);
                            }

                            // Now forward the request body from client to server
                            debug!("HTTP/1.1: Forwarding request body after 100 Continue");
                            match forward_http_body(
                                (client_stream, server_stream),
                                request.as_ref(),
                                &params,
                                &client_stats,
                                idle_timeout,
                                &cancellation_token,
                            )
                            .await
                            {
                                Ok((new_client_stream, new_server_stream)) => {
                                    client_stream = new_client_stream;
                                    server_stream = new_server_stream;
                                }
                                Err(e) => {
                                    // Body parsing failed after 100 Continue - connection is in bad state
                                    warn!(
                                        "HTTP/1.1: Request body parsing failed after 100 Continue: {}",
                                        e
                                    );
                                    return Err(e);
                                }
                            }

                            // Continue reading for the actual response
                            continue;
                        } else {
                            // This is the final response
                            debug!(
                                "HTTP/1.1: Received final response: {} {}",
                                resp.status_code, resp.reason_phrase
                            );
                            break resp;
                        }
                    }
                    Err(e) => {
                        warn!("HTTP/1.1: Failed to read response: {}", e);
                        return Err(e);
                    }
                }
            }
        } else {
            // Normal case - read single response
            match handler.read_response(&mut server_stream).await {
                Ok(resp) => resp,
                Err(e) => {
                    warn!("HTTP/1.1: Failed to read response: {}", e);
                    return Err(e);
                }
            }
        };

        let keep_alive = should_keep_alive(&request, &response);
        prepare_client_response(&mut response, keep_alive);

        // Send response to client
        if let Err(e) = handler.send_response(&mut client_stream, &response).await {
            warn!("HTTP/1.1: Failed to send response: {}", e);
            return Err(e);
        }
        debug!(
            "HTTP/1.1: Sent response to client: {} {}",
            response.status_code, response.reason_phrase
        );

        // Check if this is a protocol upgrade (WebSocket 101 Switching Protocols)
        if request.is_websocket_upgrade() && response.status_code == 101 {
            debug!("HTTP/1.1: WebSocket upgrade successful, switching to tunnel mode");

            // Put streams back and switch to copy_bidi for transparent tunneling
            ctx.write().await.set_client_stream(client_stream);
            ctx.write().await.set_server_stream(server_stream);

            // Use copy_bidi for the rest of the connection (WebSocket frames)
            return crate::copy::copy_bidi(ctx, &params).await;
        }

        // Forward response body
        debug!("HTTP/1.1: Forwarding response body if present");
        let server_stats = StatsContext::new(
            server_stat.clone(),
            #[cfg(feature = "metrics")]
            io_metrics()
                .server_bytes
                .with_label_values(&[server_label.as_str()]),
        );
        let (_server_stream, client_stream) = forward_http_body(
            (server_stream, client_stream),
            &response,
            &params,
            &server_stats,
            idle_timeout,
            &cancellation_token,
        )
        .await?;

        // For keep-alive connections, put client stream back so on_finish can return it
        debug!("HTTP/1.1: Connection keep-alive: {}", keep_alive);
        if keep_alive {
            ctx.write().await.set_client_stream(client_stream);
        }

        // Set completion state
        ctx.write().await.set_state(ContextState::ClientShutdown);

        debug!("HTTP/1.1: Request/response cycle completed");
        Ok(())
    })
}

/// Send error response to client and close connection on parsing failures
async fn send_error_response_and_close(
    client_stream: &mut IOBufStream,
    status_code: u16,
    reason: &str,
    error_detail: &str,
) -> Result<()> {
    use crate::protocols::http::http1::handler::Http1Handler;
    use crate::protocols::http::{HttpResponse, HttpVersion};

    warn!(
        "HTTP/1.1: Sending error response {}: {}",
        status_code, error_detail
    );

    let mut error_response =
        HttpResponse::new(HttpVersion::Http1_1, status_code, reason.to_string());

    // Add standard error headers
    error_response.add_header("Connection".to_string(), "close".to_string());
    error_response.add_header("Content-Length".to_string(), "0".to_string());
    error_response.add_header("Cache-Control".to_string(), "no-cache".to_string());

    let handler = Http1Handler::new();
    handler
        .send_response(client_stream, &error_response)
        .await?;

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

/// Prepare HTTP request for sending to server (strip hop-by-hop headers, etc.)
pub fn prepare_server_request(request: &mut HttpRequest, client_addr: std::net::SocketAddr) {
    // Check if this is a WebSocket upgrade BEFORE removing headers
    let is_websocket = request.is_websocket_upgrade();

    // Remove hop-by-hop headers
    request.remove_header("Connection");
    request.remove_header("Keep-Alive");
    request.remove_header("Proxy-Authorization");
    request.remove_header("Proxy-Authenticate");
    request.remove_header("TE");
    request.remove_header("Trailer");
    // Keep "Upgrade" for WebSocket support

    // Add Via header for proxy identification
    let via_value = "1.1 redproxy".to_string();
    if let Some(existing_via) = request.get_header("Via") {
        request.set_header(
            "Via".to_string(),
            format!("{}, {}", existing_via, via_value),
        );
    } else {
        request.add_header("Via".to_string(), via_value);
    }

    // Add X-Forwarded-For
    let client_ip = client_addr.ip().to_string();
    if let Some(existing_xff) = request.get_header("X-Forwarded-For") {
        request.set_header(
            "X-Forwarded-For".to_string(),
            format!("{}, {}", existing_xff, client_ip),
        );
    } else {
        request.add_header("X-Forwarded-For".to_string(), client_ip);
    }

    // Handle Connection header based on request type
    if is_websocket {
        // WebSocket upgrade: preserve Connection: Upgrade
        request.set_header("Connection".to_string(), "Upgrade".to_string());
    } else {
        // Regular HTTP: force Connection: close (no connection pooling yet)
        request.set_header("Connection".to_string(), "close".to_string());
    }
}

#[cfg(test)]
#[path = "io_test.rs"]
mod test;
