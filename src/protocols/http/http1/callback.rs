use async_trait::async_trait;
use tracing::{debug, warn};

use super::Http1Handler;
use crate::context::{Context, ContextCallback};
use crate::protocols::http::{HttpResponse, HttpVersion};

/// HTTP/1.1 proxy mode
#[derive(Debug, Clone, Copy)]
pub enum HttpProxyMode {
    Connect, // CONNECT tunneling
    Forward, // HTTP forward proxy
}

/// HTTP/1.1 response callback handler
/// Handles sending response back to client connection with completion notification
pub struct Http1ResponseCallback {
    completion_tx: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    proxy_mode: HttpProxyMode,
}

impl Http1ResponseCallback {
    pub fn new(completion_tx: tokio::sync::oneshot::Sender<()>, proxy_mode: HttpProxyMode) -> Self {
        Self {
            completion_tx: std::sync::Mutex::new(Some(completion_tx)),
            proxy_mode,
        }
    }

    fn notify_completion(&self) {
        if let Some(tx) = self.completion_tx.lock().unwrap().take() {
            let _ = tx.send(()); // Ignore send errors (receiver might be dropped)
        }
    }
}

#[async_trait]
impl ContextCallback for Http1ResponseCallback {
    async fn on_connect(&self, ctx: &mut Context) {
        debug!("HTTP/1.1: Connection established, handling response");

        match self.proxy_mode {
            HttpProxyMode::Connect => {
                // CONNECT tunneling: send 200 response, then transparent proxy
                if let Ok(mut client_stream) = ctx.take_client_stream() {
                    // Send CONNECT response
                    let response = HttpResponse::tunnel_established(HttpVersion::Http1);
                    let handler = Http1Handler::new();

                    if let Err(e) = handler.send_response(&mut client_stream, &response).await {
                        warn!("HTTP/1.1: Failed to send CONNECT response: {}", e);
                        self.notify_completion();
                        return;
                    }

                    debug!("HTTP/1.1: CONNECT response sent, starting tunnel");

                    // Put client stream back for tunneling
                    ctx.set_client_stream(client_stream);

                    // For CONNECT tunneling, do NOT notify completion immediately
                    // The tunnel should remain open until the connection naturally closes
                    // Completion will be notified when the tunnel ends (on_finish or on_error)
                } else {
                    warn!("HTTP/1.1: Failed to take client stream for CONNECT");
                    self.notify_completion();
                }
            }
            HttpProxyMode::Forward => {
                // HTTP forward proxy: send request to server, then relay response
                if let (Ok(mut client_stream), Some(mut server_stream)) = 
                    (ctx.take_client_stream(), ctx.take_server_stream()) 
                {
                    // Get the HTTP request from context
                    if let Some(request) = ctx.http_request() {
                        let mut request = request.as_ref().clone();
                        
                        // Modify headers for forward proxy
                        let connection = request.get_header("Connection").map_or("", |v| v).to_lowercase();
                        let has_upgrade = connection.split(',').any(|token| token.trim() == "upgrade");
                        
                        if !has_upgrade && request.get_header("Connection").is_none() {
                            // Add Connection: close for non-upgrade requests (only if not already present)
                            request.add_header("Connection".to_string(), "close".to_string());
                        }
                        
                        // Send request to upstream server
                        let handler = Http1Handler::new();
                        if let Err(e) = handler.send_request(&mut server_stream, &request).await {
                            warn!("HTTP/1.1: Failed to send forward request to server: {}", e);
                            
                            // Send error response to client
                            let error_response = HttpResponse::new(HttpVersion::Http1, 503, "Service Unavailable".to_string());
                            if let Err(e2) = handler.send_response(&mut client_stream, &error_response).await {
                                warn!("HTTP/1.1: Failed to send error response to client: {}", e2);
                            }
                            
                            self.notify_completion();
                            return;
                        }
                        
                        debug!("HTTP/1.1: Forward request sent, starting response relay");
                        
                        // Put streams back for bidirectional copying
                        ctx.set_client_stream(client_stream);
                        ctx.set_server_stream(server_stream);
                        
                        // Do NOT notify completion here - completion happens in on_finish
                    } else {
                        warn!("HTTP/1.1: No HTTP request found in context for forward proxy");
                        self.notify_completion();
                    }
                } else {
                    warn!("HTTP/1.1: Failed to take streams for forward proxy");
                    self.notify_completion();
                }
            }
        }
    }

    async fn on_error(&self, _ctx: &mut Context, error: anyhow::Error) {
        warn!("HTTP/1.1: Connection error: {}", error);

        // Send error response if client stream is available
        if let Ok(mut client_stream) = _ctx.take_client_stream() {
            let response = HttpResponse::new(HttpVersion::Http1, 502, "Bad Gateway".to_string());
            let handler = Http1Handler::new();

            if let Err(e) = handler.send_response(&mut client_stream, &response).await {
                warn!("HTTP/1.1: Failed to send error response: {}", e);
            }
        }

        self.notify_completion();
    }

    async fn on_finish(&self, _ctx: &mut Context) {
        debug!("HTTP/1.1: Request processing finished");
        self.notify_completion();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{ContextManager, IOBufStream, TargetAddress, make_buffered_stream};
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

    #[test]
    fn test_callback_creation() {
        let (tx, _rx) = oneshot::channel();
        let callback = Http1ResponseCallback::new(tx, HttpProxyMode::Forward);

        // Verify callback was created successfully
        assert!(callback.completion_tx.lock().unwrap().is_some());
    }

    #[test]
    fn test_notify_completion() {
        let (tx, mut rx) = oneshot::channel();
        let callback = Http1ResponseCallback::new(tx, HttpProxyMode::Forward);

        // Notify completion
        callback.notify_completion();

        // Verify completion was signaled
        assert!(callback.completion_tx.lock().unwrap().is_none());

        // Check that receiver got the signal
        let result = rx.try_recv();
        assert!(result.is_ok());
    }

    #[test]
    fn test_notify_completion_idempotent() {
        let (tx, mut rx) = oneshot::channel();
        let callback = Http1ResponseCallback::new(tx, HttpProxyMode::Forward);

        // Notify completion twice
        callback.notify_completion();
        callback.notify_completion();

        // Should still work correctly
        assert!(callback.completion_tx.lock().unwrap().is_none());
        assert!(rx.try_recv().is_ok());
    }

    #[test(tokio::test)]
    async fn test_on_connection_established_connect_mode() {
        let (tx, mut rx) = oneshot::channel();
        let callback = Http1ResponseCallback::new(tx, HttpProxyMode::Connect);

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

        // For CONNECT mode, completion should NOT be notified immediately (happens in on_finish)
        assert!(rx.try_recv().is_err());
    }

    #[test(tokio::test)]
    async fn test_on_connection_established_forward_mode_close() {
        let (tx, mut rx) = oneshot::channel();
        let callback = Http1ResponseCallback::new(tx, HttpProxyMode::Forward);

        let contexts = Arc::new(ContextManager::default());
        let ctx = contexts
            .create_context("test".to_string(), "127.0.0.1:8080".parse().unwrap())
            .await;

        // Create request with Connection: close
        let mut request = HttpRequest::new(
            HttpMethod::Get,
            "http://example.com/test".to_string(),
            HttpVersion::Http1,
        );
        request.add_header("Connection".to_string(), "close".to_string());

        // Expected HTTP request that should be sent to server
        let expected_request = b"GET http://example.com/test HTTP/1.1\r\nConnection: close\r\n\r\n";

        // Set up test streams - server stream expects the HTTP request write
        let client_stream = make_test_stream(b"");
        let server_stream = make_test_stream_with_write(b"", expected_request);

        // Set up context
        {
            let mut ctx_guard = ctx.write().await;
            ctx_guard.set_target(TargetAddress::DomainPort("example.com".to_string(), 80));
            ctx_guard.set_http_request(request);
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

        // For forward mode, completion should NOT be notified immediately (happens in on_finish)
        assert!(rx.try_recv().is_err());
    }

    #[test(tokio::test)]
    async fn test_on_error() {
        let (tx, mut rx) = oneshot::channel();
        let callback = Http1ResponseCallback::new(tx, HttpProxyMode::Forward);

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
