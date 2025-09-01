// HTTP/1.1 handler and internal modules
mod callback;
mod handler;
mod io;

// Re-export main handler
pub use handler::Http1Handler;

// Re-export HTTP/1.1 components (for internal use)
pub use callback::{Http1Callback, HttpProxyMode};
