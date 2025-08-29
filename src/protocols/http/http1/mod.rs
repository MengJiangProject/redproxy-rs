// HTTP/1.1 handler and internal modules
mod callback;
mod handler;
mod parser;
mod stream;

// Re-export main handler
pub use handler::Http1Handler;

// Re-export HTTP/1.1 components (for internal use)
pub use callback::{Http1ResponseCallback, HttpProxyMode};
pub use stream::HttpClientStream;
