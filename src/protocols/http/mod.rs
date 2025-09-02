use std::fmt;

pub mod http1;
//pub mod http2;
//pub mod http3;

/// HTTP version enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpVersion {
    Http1_0,
    Http1_1,
    Http2,
    Http3,
}

impl fmt::Display for HttpVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpVersion::Http1_0 => write!(f, "HTTP/1.0"),
            HttpVersion::Http1_1 => write!(f, "HTTP/1.1"),
            HttpVersion::Http2 => write!(f, "HTTP/2"),
            HttpVersion::Http3 => write!(f, "HTTP/3"),
        }
    }
}

/// HTTP request method
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpMethod {
    Connect,
    Get,
    Post,
    Put,
    Delete,
    Head,
    Options,
    Patch,
    Trace,
    Other(String),
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpMethod::Connect => write!(f, "CONNECT"),
            HttpMethod::Get => write!(f, "GET"),
            HttpMethod::Post => write!(f, "POST"),
            HttpMethod::Put => write!(f, "PUT"),
            HttpMethod::Delete => write!(f, "DELETE"),
            HttpMethod::Head => write!(f, "HEAD"),
            HttpMethod::Options => write!(f, "OPTIONS"),
            HttpMethod::Patch => write!(f, "PATCH"),
            HttpMethod::Trace => write!(f, "TRACE"),
            HttpMethod::Other(s) => write!(f, "{}", s),
        }
    }
}

/// HTTP request information
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: HttpMethod,
    pub uri: String,
    pub version: HttpVersion,
    pub headers: Vec<(String, String)>,
}

impl From<crate::common::http::HttpRequestV1> for HttpRequest {
    fn from(request: crate::common::http::HttpRequestV1) -> Self {
        let method = match request.method.to_uppercase().as_str() {
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

        let version = if request.version.starts_with("HTTP/1.") {
            HttpVersion::Http1_1
        } else if request.version == "HTTP/2" {
            HttpVersion::Http2
        } else if request.version == "HTTP/3" {
            HttpVersion::Http3
        } else {
            HttpVersion::Http1_1 // Default fallback
        };

        let mut http_request = HttpRequest::new(method, request.resource, version);

        // Copy headers
        for (name, value) in request.headers {
            http_request.add_header(name, value);
        }

        http_request
    }
}

impl From<HttpRequest> for crate::common::http::HttpRequestV1 {
    fn from(request: HttpRequest) -> Self {
        let method = request.method.to_string();
        let resource = request.uri;
        let version = request.version.to_string();
        let headers = request.headers;

        crate::common::http::HttpRequestV1 {
            method,
            resource,
            version,
            headers,
        }
    }
}

impl HttpRequest {
    pub fn new(method: HttpMethod, uri: String, version: HttpVersion) -> Self {
        Self {
            method,
            uri,
            version,
            headers: Vec::new(),
        }
    }

    pub fn is_connect(&self) -> bool {
        self.method == HttpMethod::Connect
    }

    pub fn is_websocket_upgrade(&self) -> bool {
        self.get_header("upgrade")
            .map(|v| v.eq_ignore_ascii_case("websocket"))
            .unwrap_or(false)
            && self
                .get_header("connection")
                .map(|v| v.to_lowercase().contains("upgrade"))
                .unwrap_or(false)
    }
}

/// HTTP response information
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub version: HttpVersion,
    pub status_code: u16,
    pub reason_phrase: String,
    pub headers: Vec<(String, String)>,
}

impl HttpResponse {
    pub fn new(version: HttpVersion, status_code: u16, reason_phrase: String) -> Self {
        Self {
            version,
            status_code,
            reason_phrase,
            headers: Vec::new(),
        }
    }

    pub fn ok(version: HttpVersion) -> Self {
        Self::new(version, 200, "OK".to_string())
    }

    pub fn tunnel_established(version: HttpVersion) -> Self {
        Self::new(version, 200, "Connection established".to_string())
    }
}

/// Trait for common HTTP message operations (requests and responses)
pub trait HttpMessage {
    fn get_headers_mut(&mut self) -> &mut Vec<(String, String)>;
    fn get_headers(&self) -> &Vec<(String, String)>;
    fn add_header(&mut self, name: String, value: String) {
        self.get_headers_mut().push((name, value));
    }
    fn get_header(&self, name: &str) -> Option<&String> {
        self.get_headers()
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v)
    }
    fn remove_header(&mut self, name: &str) {
        self.get_headers_mut()
            .retain(|(header_name, _)| !header_name.eq_ignore_ascii_case(name));
    }
    fn set_header(&mut self, name: String, value: String) {
        self.remove_header(&name);
        self.add_header(name, value);
    }
}

impl HttpMessage for HttpRequest {
    fn get_headers_mut(&mut self) -> &mut Vec<(String, String)> {
        &mut self.headers
    }
    fn get_headers(&self) -> &Vec<(String, String)> {
        &self.headers
    }
}

impl HttpMessage for HttpResponse {
    fn get_headers_mut(&mut self) -> &mut Vec<(String, String)> {
        &mut self.headers
    }
    fn get_headers(&self) -> &Vec<(String, String)> {
        &self.headers
    }
}
