use async_trait::async_trait;
use tokio::sync::Mutex;
use tokio::sync::oneshot::Sender;
use tracing::{debug, trace, warn};

use super::{handler::prepare_server_request, io::http_io_loop};
use crate::protocols::http::{HttpResponse, HttpVersion, http1::send_response};
use crate::{
    context::{Context, ContextCallback, IOBufStream},
    protocols::http::HttpMessage,
};

/// HTTP/1.1 proxy mode
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HttpProxyMode {
    Connect, // CONNECT tunneling
    Forward, // HTTP forward proxy
}

type CompletionSender = Sender<Option<IOBufStream>>;
/// HTTP/1.1 response callback handler
/// Handles sending response back to client connection with completion notification
pub struct Http1Callback {
    completion_tx: Mutex<Option<CompletionSender>>,
    proxy_mode: HttpProxyMode,
}

impl Http1Callback {
    pub fn new(completion_tx: CompletionSender, proxy_mode: HttpProxyMode) -> Self {
        Self {
            completion_tx: Mutex::new(Some(completion_tx)),
            proxy_mode,
        }
    }

    pub async fn notify_completion(&self, returned_stream: Option<IOBufStream>) {
        if let Some(tx) = self.completion_tx.lock().await.take() {
            let _ = tx.send(returned_stream); // Send back client stream for keep-alive or None
        }
    }

    /// Handle CONNECT tunneling - simple tunnel establishment
    async fn handle_connect_tunnel(&self, ctx: &mut Context) {
        let mut client_stream = match ctx.take_client_stream() {
            Some(stream) => stream,
            None => {
                warn!("HTTP/1.1: Failed to take client stream for CONNECT");
                self.notify_completion(None).await;
                return;
            }
        };

        // Send 200 Connection Established to client
        let response = HttpResponse::tunnel_established(HttpVersion::Http1_1);
        if let Err(e) = send_response(&mut client_stream, &response).await {
            warn!("HTTP/1.1: Failed to send CONNECT response: {}", e);
            // Cannot recover - CONNECT response partially sent or client disconnected
            self.notify_completion(None).await;
            return;
        }

        debug!("HTTP/1.1: CONNECT tunnel established");

        // Put streams back for bidirectional copying
        ctx.set_client_stream(client_stream);
        // server_stream already set by connector

        // CONNECT tunnels don't support keep-alive - connection becomes opaque
        self.notify_completion(None).await;
    }

    /// Handle HTTP forward proxy by setting up custom IO loop
    async fn handle_forward_proxy(&self, ctx: &mut Context) {
        let (mut client_stream, mut server_stream) =
            match (ctx.take_client_stream(), ctx.take_server_stream()) {
                (Some(client), Some(server)) => (client, server),
                (None, _) => {
                    warn!("HTTP/1.1: No client stream available");
                    self.notify_completion(None).await;
                    return;
                }
                (Some(mut client), None) => {
                    warn!("HTTP/1.1: No server stream available");
                    self.send_error_to_client(&mut client, 502, "Bad Gateway")
                        .await;
                    self.notify_completion(None).await;
                    return;
                }
            };

        let request = match ctx.http_request() {
            Some(req) => req.as_ref().clone(),
            None => {
                warn!("HTTP/1.1: No HTTP request in context");
                self.send_error_to_client(&mut client_stream, 400, "Bad Request")
                    .await;
                self.notify_completion(None).await;
                return;
            }
        };

        // Prepare and send ONLY request headers to server
        let mut prepared_request = request.clone();
        let client_addr = ctx.props().source;
        prepare_server_request(&mut prepared_request, client_addr);

        trace!(
            "HTTP/1.1: Sending request to server: {:?}",
            prepared_request
        );
        if let Err(e) = crate::protocols::http::http1::handler::send_request(
            &mut server_stream,
            &prepared_request,
        )
        .await
        {
            warn!("HTTP/1.1: Failed to send request headers to server: {}", e);
            self.send_error_to_client(&mut client_stream, 503, "Service Unavailable")
                .await;
            self.notify_completion(None).await;
            return;
        }

        debug!("HTTP/1.1: Request headers sent, setting up HTTP IO loop");

        // Put streams back for the HTTP IO loop to handle body forwarding and responses
        ctx.set_client_stream(client_stream);
        ctx.set_server_stream(server_stream);

        // Set the custom HTTP IO loop instead of using copy_bidi
        ctx.set_io_loop(http_io_loop);

        // DO NOT notify completion here - let http_io_loop handle completion when it's actually done
        // The HTTP IO loop will take over from here and handle the actual request/response cycle
    }

    /// Send error response to client with proper headers
    async fn send_error_to_client(
        &self,
        client_stream: &mut crate::context::IOBufStream,
        status_code: u16,
        reason: &str,
    ) {
        let mut error_response = crate::protocols::http::HttpResponse::new(
            crate::protocols::http::HttpVersion::Http1_1,
            status_code,
            reason.to_string(),
        );

        // Add standard error response headers
        error_response.add_header("Content-Length".to_string(), "0".to_string());
        error_response.add_header("Connection".to_string(), "close".to_string());
        error_response.add_header("Cache-Control".to_string(), "no-cache".to_string());

        if let Err(e) =
            crate::protocols::http::http1::handler::send_response(client_stream, &error_response)
                .await
        {
            warn!("HTTP/1.1: Failed to send error response: {}", e);
            // Error sending error response - connection likely broken, nothing more we can do
        }
    }
}

#[async_trait]
impl ContextCallback for Http1Callback {
    async fn on_connect(&self, ctx: &mut Context) {
        debug!("HTTP/1.1: Connection established, processing request");

        match self.proxy_mode {
            HttpProxyMode::Connect => {
                self.handle_connect_tunnel(ctx).await;
            }
            HttpProxyMode::Forward => {
                self.handle_forward_proxy(ctx).await;
            }
        }
    }

    async fn on_error(&self, _ctx: &mut Context, error: anyhow::Error) {
        warn!("HTTP/1.1: Connection error: {}", error);

        // Send error response if client stream is available
        if let Some(mut client_stream) = _ctx.take_client_stream() {
            let response = HttpResponse::new(HttpVersion::Http1_1, 502, "Bad Gateway".to_string());

            if let Err(e) = send_response(&mut client_stream, &response).await {
                warn!("HTTP/1.1: Failed to send error response: {}", e);
            }
        }

        self.notify_completion(None).await;
    }

    async fn on_finish(&self, ctx: &mut Context) {
        debug!("HTTP/1.1: Request processing finished");

        // Check if we should return client stream for keep-alive
        if let Some(client_stream) = ctx.take_client_stream() {
            debug!("HTTP/1.1: Returning BufferedStream for keep-alive");
            // Keep it as IOBufStream throughout - no conversion needed
            self.notify_completion(Some(client_stream)).await;
        } else {
            debug!("HTTP/1.1: No client stream to return, closing connection");
            self.notify_completion(None).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{
        ContextManager, IOBufStream, IOLoopFn, TargetAddress, make_buffered_stream,
    };
    use crate::protocols::http::{HttpMethod, HttpRequest, HttpVersion};
    use std::sync::Arc;
    use test_log::test;
    use tokio::sync::oneshot;
    use tokio_test::io::Builder;

    fn make_test_stream(data: &[u8]) -> IOBufStream {
        let mock_stream = Builder::new().read(data).build();
        make_buffered_stream(mock_stream)
    }

    fn make_test_stream_with_write(read_data: &[u8], write_data: &[u8]) -> IOBufStream {
        let mock_stream = Builder::new().read(read_data).write(write_data).build();
        make_buffered_stream(mock_stream)
    }

    #[tokio::test]
    async fn test_callback_creation() {
        let (tx, _rx) = oneshot::channel();
        let callback = Http1Callback::new(tx, HttpProxyMode::Forward);

        // Verify callback was created successfully
        assert!(callback.completion_tx.lock().await.is_some());
    }

    #[tokio::test]
    async fn test_notify_completion() {
        let (tx, mut rx) = oneshot::channel();
        let callback = Http1Callback::new(tx, HttpProxyMode::Forward);

        // Notify completion
        callback.notify_completion(None).await;

        // Verify completion was signaled
        assert!(callback.completion_tx.lock().await.is_none());

        // Check that receiver got the signal
        let result = rx.try_recv();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_notify_completion_idempotent() {
        let (tx, mut rx) = oneshot::channel();
        let callback = Http1Callback::new(tx, HttpProxyMode::Forward);

        // Notify completion twice
        callback.notify_completion(None).await;
        callback.notify_completion(None).await;

        // Should still work correctly
        assert!(callback.completion_tx.lock().await.is_none());
        assert!(rx.try_recv().is_ok());
    }

    #[test(tokio::test)]
    async fn test_on_connection_established_connect_mode() {
        let (tx, mut rx) = oneshot::channel();
        let callback = Http1Callback::new(tx, HttpProxyMode::Connect);

        let contexts = Arc::new(ContextManager::default());
        let ctx = contexts
            .create_context("test".to_string(), "127.0.0.1:8080".parse().unwrap())
            .await;

        // Set up test streams - client stream expects CONNECT response write
        let expected_response = b"HTTP/1.1 200 Connection established\r\n\r\n";
        let client_stream = make_test_stream_with_write(b"", expected_response);
        let server_stream = make_test_stream(b"");

        // Create a minimal context for testing
        {
            let mut ctx_guard = ctx.write().await;
            ctx_guard.set_target(TargetAddress::DomainPort("example.com".to_string(), 443));
        }

        {
            let mut ctx_guard = ctx.write().await;
            ctx_guard.set_client_stream(client_stream);
            ctx_guard.set_server_stream(server_stream);
        }
        {
            let mut ctx_guard = ctx.write().await;
            callback.on_connect(&mut ctx_guard).await;
        }

        // For CONNECT mode, completion should be notified after tunnel establishment
        assert!(rx.try_recv().is_ok());
    }

    #[test(tokio::test)]
    async fn test_on_connection_established_forward_mode_close() {
        let (tx, mut rx) = oneshot::channel();
        let callback = Http1Callback::new(tx, HttpProxyMode::Forward);

        let contexts = Arc::new(ContextManager::default());
        let ctx = contexts
            .create_context("test".to_string(), "127.0.0.1:8080".parse().unwrap())
            .await;

        // Create request with Connection: close
        let mut request = HttpRequest::new(
            HttpMethod::Get,
            "http://example.com/test".to_string(),
            HttpVersion::Http1_1,
        );
        request.add_header("Connection".to_string(), "close".to_string());

        // Create test streams - server stream needs to accept the request headers write
        let client_stream = make_test_stream(b"");
        let server_stream = make_test_stream_with_write(b"", b"GET http://example.com/test HTTP/1.1\r\nVia: 1.1 redproxy\r\nX-Forwarded-For: 127.0.0.1\r\nConnection: close\r\n\r\n");

        // Set up context
        {
            let mut ctx_guard = ctx.write().await;
            ctx_guard.set_target(TargetAddress::DomainPort("example.com".to_string(), 80));
            ctx_guard.set_http_request(request);
            ctx_guard.set_client_stream(client_stream);
            ctx_guard.set_server_stream(server_stream);
        }

        // Test that on_connect sets up the IO loop without error
        {
            let mut ctx_guard = ctx.write().await;
            callback.on_connect(&mut ctx_guard).await;

            let http_io_loop_ptr: IOLoopFn = http_io_loop;
            // Verify IO loop was set (this is the main behavior we're testing)
            assert!(std::ptr::fn_addr_eq(http_io_loop_ptr, ctx_guard.io_loop()));
        }

        // In the new architecture, completion notification happens after on_finish
        // This test verifies that on_connect doesn't immediately notify completion
        let result = rx.try_recv();
        assert!(result.is_err()); // Should NOT have completion notification yet
    }

    #[test(tokio::test)]
    async fn test_on_error() {
        let (tx, mut rx) = oneshot::channel();
        let callback = Http1Callback::new(tx, HttpProxyMode::Forward);

        let contexts = Arc::new(ContextManager::default());
        let ctx = contexts
            .create_context("test".to_string(), "127.0.0.1:8080".parse().unwrap())
            .await;

        // Set up client stream to expect error response write
        let expected_error_response = b"HTTP/1.1 502 Bad Gateway\r\n\r\n";
        let client_stream = make_test_stream_with_write(b"", expected_error_response);
        {
            let mut ctx_guard = ctx.write().await;
            ctx_guard.set_client_stream(client_stream);
        }

        let error = anyhow::anyhow!("Test error");
        {
            let mut ctx_guard = ctx.write().await;
            callback.on_error(&mut ctx_guard, error).await;
        }

        // Error should trigger completion notification
        assert!(rx.try_recv().is_ok());
    }
}
