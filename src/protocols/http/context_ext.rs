use crate::context::Context;

/// Extension trait for Context to add HTTP protocol-specific methods
///
/// This trait provides consistent access to HTTP-related properties across
/// all HTTP protocol implementations (HTTP/1.1, HTTP/2, HTTP/3).
///
/// **Design Philosophy:**
/// - Consistent naming across all HTTP protocols
/// - Context as configuration carrier, not implementation
/// - Protocol handlers use these properties to make routing decisions
pub trait HttpContextExt {
    /// Set the HTTP protocol version used by this connection
    /// Values: "http/1.1", "h2", "h3"
    fn set_http_protocol(&mut self, protocol: &str) -> &mut Self;

    /// Get the HTTP protocol version
    fn http_protocol(&self) -> Option<&str>;

    /// Enable/disable HTTP forward proxy mode
    /// When true, HTTP requests will be processed as forward proxy requests
    fn set_http_forward_proxy(&mut self, enabled: bool) -> &mut Self;

    /// Check if HTTP forward proxy mode is enabled
    fn http_forward_proxy(&self) -> bool;

    /// Set HTTP connection keep-alive support
    /// Used by protocol handlers to determine connection reuse strategy
    fn set_http_keep_alive(&mut self, enabled: bool) -> &mut Self;

    /// Check if HTTP keep-alive is supported
    fn http_keep_alive(&self) -> bool;

    /// Set proxy authentication credentials
    /// Format: "username:password" (will be base64 encoded when sent)
    fn set_http_proxy_auth(&mut self, credentials: &str) -> &mut Self;

    /// Get proxy authentication credentials
    fn http_proxy_auth(&self) -> Option<&str>;

    /// Set HTTP ALPN (Application-Layer Protocol Negotiation) result
    /// Used to track negotiated protocol after TLS handshake
    fn set_http_alpn(&mut self, alpn: &str) -> &mut Self;

    /// Get HTTP ALPN result
    fn http_alpn(&self) -> Option<&str>;

    /// Set connection pool key for reusing connections
    /// Format: "protocol://host:port" (e.g., "https://example.com:443")
    fn set_http_pool_key(&mut self, key: &str) -> &mut Self;

    /// Get connection pool key
    fn http_pool_key(&self) -> Option<&str>;

    /// Set maximum requests per connection (HTTP/1.1 pipelining, HTTP/2 streams)
    fn set_http_max_requests(&mut self, max: u32) -> &mut Self;

    /// Get maximum requests per connection
    fn http_max_requests(&self) -> Option<u32>;

    /// Set HTTP/2 specific settings
    fn set_http2_max_concurrent_streams(&mut self, max: u32) -> &mut Self;

    /// Get HTTP/2 max concurrent streams
    fn http2_max_concurrent_streams(&self) -> Option<u32>;

    /// Set HTTP/3 specific settings  
    fn set_http3_max_bi_streams(&mut self, max: u32) -> &mut Self;

    /// Get HTTP/3 max bidirectional streams
    fn http3_max_bi_streams(&self) -> Option<u32>;
}

impl HttpContextExt for Context {
    fn set_http_protocol(&mut self, protocol: &str) -> &mut Self {
        self.http_mut().set_protocol(protocol);
        self
    }

    fn http_protocol(&self) -> Option<&str> {
        self.http().and_then(|h| h.protocol.as_deref())
    }

    fn set_http_forward_proxy(&mut self, enabled: bool) -> &mut Self {
        self.http_mut().forward_proxy = enabled;
        self
    }

    fn http_forward_proxy(&self) -> bool {
        self.http().map(|h| h.forward_proxy).unwrap_or(false)
    }

    fn set_http_keep_alive(&mut self, enabled: bool) -> &mut Self {
        self.http_mut().keep_alive = enabled;
        self
    }

    fn http_keep_alive(&self) -> bool {
        self.http().map(|h| h.keep_alive).unwrap_or(true) // Default to true for HTTP/1.1
    }

    fn set_http_proxy_auth(&mut self, credentials: &str) -> &mut Self {
        let _ = self.http_mut().set_proxy_auth_from_str(credentials);
        self
    }

    fn http_proxy_auth(&self) -> Option<&str> {
        self.http()
            .and_then(|h| h.proxy_auth.as_ref())
            .map(|auth| auth.original_credentials.as_str())
    }

    fn set_http_alpn(&mut self, alpn: &str) -> &mut Self {
        self.http_mut().alpn = Some(alpn.to_string());
        self
    }

    fn http_alpn(&self) -> Option<&str> {
        self.http().and_then(|h| h.alpn.as_deref())
    }

    fn set_http_pool_key(&mut self, key: &str) -> &mut Self {
        self.http_mut().pool_key = Some(key.to_string());
        self
    }

    fn http_pool_key(&self) -> Option<&str> {
        self.http().and_then(|h| h.pool_key.as_deref())
    }

    fn set_http_max_requests(&mut self, max: u32) -> &mut Self {
        self.http_mut().max_requests = Some(max);
        self
    }

    fn http_max_requests(&self) -> Option<u32> {
        self.http().and_then(|h| h.max_requests)
    }

    fn set_http2_max_concurrent_streams(&mut self, max: u32) -> &mut Self {
        self.http_mut().h2_max_concurrent_streams = Some(max);
        self
    }

    fn http2_max_concurrent_streams(&self) -> Option<u32> {
        self.http().and_then(|h| h.h2_max_concurrent_streams)
    }

    fn set_http3_max_bi_streams(&mut self, max: u32) -> &mut Self {
        self.http_mut().h3_max_bi_streams = Some(max);
        self
    }

    fn http3_max_bi_streams(&self) -> Option<u32> {
        self.http().and_then(|h| h.h3_max_bi_streams)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::ContextManager;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_http_context_ext_basic_properties() {
        let manager = Arc::new(ContextManager::default());
        let source = "127.0.0.1:1234".parse().unwrap();
        let ctx = manager.create_context("test".to_string(), source).await;

        {
            let mut ctx_write = ctx.write().await;
            ctx_write
                .set_http_protocol("h2")
                .set_http_forward_proxy(true)
                .set_http_keep_alive(false);
        }

        let ctx_read = ctx.read().await;
        assert_eq!(ctx_read.http_protocol(), Some("h2"));
        assert!(ctx_read.http_forward_proxy());
        assert!(!ctx_read.http_keep_alive());
    }

    #[tokio::test]
    async fn test_http_context_ext_auth_and_alpn() {
        let manager = Arc::new(ContextManager::default());
        let source = "127.0.0.1:1234".parse().unwrap();
        let ctx = manager.create_context("test".to_string(), source).await;

        {
            let mut ctx_write = ctx.write().await;
            ctx_write
                .set_http_proxy_auth("user:pass")
                .set_http_alpn("h2")
                .set_http_pool_key("https://example.com:443");
        }

        let ctx_read = ctx.read().await;
        assert_eq!(ctx_read.http_proxy_auth(), Some("user:pass"));
        assert_eq!(ctx_read.http_alpn(), Some("h2"));
        assert_eq!(ctx_read.http_pool_key(), Some("https://example.com:443"));
    }

    #[tokio::test]
    async fn test_http_context_ext_defaults() {
        let manager = Arc::new(ContextManager::default());
        let source = "127.0.0.1:1234".parse().unwrap();
        let ctx = manager.create_context("test".to_string(), source).await;

        let ctx_read = ctx.read().await;
        assert_eq!(ctx_read.http_protocol(), None);
        assert!(!ctx_read.http_forward_proxy()); // Default false
        assert!(ctx_read.http_keep_alive()); // Default true for HTTP/1.1
        assert_eq!(ctx_read.http_proxy_auth(), None);
        assert_eq!(ctx_read.http_alpn(), None);
    }

    #[tokio::test]
    async fn test_http_context_ext_numeric_properties() {
        let manager = Arc::new(ContextManager::default());
        let source = "127.0.0.1:1234".parse().unwrap();
        let ctx = manager.create_context("test".to_string(), source).await;

        {
            let mut ctx_write = ctx.write().await;
            ctx_write
                .set_http_max_requests(100)
                .set_http2_max_concurrent_streams(256)
                .set_http3_max_bi_streams(128);
        }

        let ctx_read = ctx.read().await;
        assert_eq!(ctx_read.http_max_requests(), Some(100));
        assert_eq!(ctx_read.http2_max_concurrent_streams(), Some(256));
        assert_eq!(ctx_read.http3_max_bi_streams(), Some(128));
    }
}
