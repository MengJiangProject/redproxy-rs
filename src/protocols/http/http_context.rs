use std::sync::Arc;

use crate::protocols::http::{HttpRequest, HttpResponse};

/// HTTP-specific authentication credentials
#[derive(Debug, Clone, PartialEq)]
pub struct ProxyAuth {
    pub username: String,
    pub password: String,
    /// Original credentials string for compatibility
    pub original_credentials: String,
}

impl ProxyAuth {
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        let username = username.into();
        let password = password.into();
        Self {
            original_credentials: format!("{}:{}", username, password),
            username,
            password,
        }
    }

    /// Parse from "username:password" format
    pub fn from_credentials(credentials: &str) -> Option<Self> {
        credentials
            .split_once(':')
            .map(|(username, password)| Self {
                username: username.to_string(),
                password: password.to_string(),
                original_credentials: credentials.to_string(),
            })
    }

    /// Encode as Basic authentication header value
    pub fn encode_basic(&self) -> String {
        use base64::Engine;
        let credentials = format!("{}:{}", self.username, self.password);
        base64::engine::general_purpose::STANDARD.encode(credentials.as_bytes())
    }
}

/// HTTP-specific context that consolidates all HTTP state
///
/// This structure contains all HTTP-related configuration and state,
/// providing type safety and performance benefits over string-based storage.
#[derive(Debug, Clone)]
pub struct HttpContext {
    /// The parsed HTTP request being processed
    pub request: Option<Arc<HttpRequest>>,

    /// The received HTTP response (for clients/proxies)  
    pub response: Option<Arc<HttpResponse>>,

    /// HTTP protocol version in use ("http/1.1", "h2", "h3")
    pub protocol: Option<String>,

    /// Connection management settings
    pub keep_alive: bool,
    pub forward_proxy: bool,

    /// Authentication credentials for proxy
    pub proxy_auth: Option<ProxyAuth>,

    /// ALPN (Application-Layer Protocol Negotiation) result
    pub alpn: Option<String>,

    /// Connection pool information
    pub pool_key: Option<String>,
    pub max_requests: Option<u32>,

    /// HTTP/2 specific settings
    pub h2_max_concurrent_streams: Option<u32>,

    /// HTTP/3 specific settings  
    pub h3_max_bi_streams: Option<u32>,
}

impl Default for HttpContext {
    fn default() -> Self {
        Self {
            request: None,
            response: None,
            protocol: None,
            keep_alive: true, // Default to true for HTTP/1.1
            forward_proxy: false,
            proxy_auth: None,
            alpn: None,
            pool_key: None,
            max_requests: None,
            h2_max_concurrent_streams: None,
            h3_max_bi_streams: None,
        }
    }
}

impl HttpContext {
    /// Create new HttpContext with default settings
    pub fn new() -> Self {
        Self::default()
    }

    /// Create HttpContext for specific protocol
    pub fn for_protocol(protocol: &str) -> Self {
        Self {
            protocol: Some(protocol.to_string()),
            keep_alive: match protocol {
                "http/1.0" => false, // HTTP/1.0 defaults to close
                _ => true,           // HTTP/1.1+ defaults to keep-alive
            },
            ..Default::default()
        }
    }

    /// Set HTTP request (convenience method)
    pub fn set_request(&mut self, request: HttpRequest) {
        self.request = Some(Arc::new(request));
    }

    /// Set HTTP response (convenience method)
    pub fn set_response(&mut self, response: HttpResponse) {
        self.response = Some(Arc::new(response));
    }

    /// Set protocol version
    pub fn set_protocol(&mut self, protocol: &str) {
        self.protocol = Some(protocol.to_string());

        // Adjust keep_alive default based on protocol
        if protocol == "http/1.0" {
            self.keep_alive = false;
        }
    }

    /// Get protocol version, defaulting to HTTP/1.1
    pub fn protocol(&self) -> &str {
        self.protocol.as_deref().unwrap_or("http/1.1")
    }

    /// Set proxy authentication from credentials string
    pub fn set_proxy_auth_from_str(&mut self, credentials: &str) -> Result<(), &'static str> {
        match ProxyAuth::from_credentials(credentials) {
            Some(auth) => {
                self.proxy_auth = Some(auth);
                Ok(())
            }
            None => Err("Invalid credentials format, expected 'username:password'"),
        }
    }

    /// Check if this context supports keep-alive
    pub fn supports_keep_alive(&self) -> bool {
        !matches!(self.protocol(), "http/1.0")
    }

    /// Check if protocol requires TLS
    pub fn requires_tls(&self) -> bool {
        matches!(self.protocol(), "h2" | "h3")
    }

    /// Check if protocol supports multiplexing
    pub fn supports_multiplexing(&self) -> bool {
        matches!(self.protocol(), "h2" | "h3")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::http::{HttpMethod, HttpVersion};

    #[test]
    fn test_proxy_auth() {
        let auth = ProxyAuth::from_credentials("testuser:testpass").unwrap();
        assert_eq!(auth.username, "testuser");
        assert_eq!(auth.password, "testpass");

        let encoded = auth.encode_basic();
        assert!(!encoded.is_empty());

        // Test invalid format
        assert!(ProxyAuth::from_credentials("invalid").is_none());
    }

    #[test]
    fn test_http_context_defaults() {
        let ctx = HttpContext::default();
        assert!(ctx.keep_alive);
        assert!(!ctx.forward_proxy);
        assert_eq!(ctx.protocol(), "http/1.1");
        assert!(ctx.supports_keep_alive());
        assert!(!ctx.requires_tls());
    }

    #[test]
    fn test_http_context_for_protocol() {
        let h1_ctx = HttpContext::for_protocol("http/1.1");
        assert!(h1_ctx.keep_alive);
        assert!(h1_ctx.supports_keep_alive());
        assert!(!h1_ctx.requires_tls());

        let h2_ctx = HttpContext::for_protocol("h2");
        assert!(h2_ctx.keep_alive);
        assert!(h2_ctx.supports_multiplexing());
        assert!(h2_ctx.requires_tls());

        let h10_ctx = HttpContext::for_protocol("http/1.0");
        assert!(!h10_ctx.keep_alive);
        assert!(!h10_ctx.supports_keep_alive());
    }

    #[test]
    fn test_request_response_handling() {
        let mut ctx = HttpContext::new();

        let request = HttpRequest::new(HttpMethod::Get, "/test".to_string(), HttpVersion::Http1_1);
        ctx.set_request(request.clone());

        assert!(ctx.request.is_some());
        assert_eq!(ctx.request.as_ref().unwrap().uri, "/test");
    }

    #[test]
    fn test_proxy_auth_from_str() {
        let mut ctx = HttpContext::new();

        // Valid credentials
        assert!(ctx.set_proxy_auth_from_str("user:pass").is_ok());
        assert!(ctx.proxy_auth.is_some());

        let auth = ctx.proxy_auth.as_ref().unwrap();
        assert_eq!(auth.username, "user");
        assert_eq!(auth.password, "pass");

        // Invalid credentials
        let mut ctx2 = HttpContext::new();
        assert!(ctx2.set_proxy_auth_from_str("invalid").is_err());
        assert!(ctx2.proxy_auth.is_none());
    }
}
