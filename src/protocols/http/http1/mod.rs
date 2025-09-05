// HTTP/1.1 handler and internal modules
mod callback;
mod handler;
mod io;

// Re-export main handler functions
pub use handler::{
    expects_100_continue, handle_connector, handle_listener, handle_listener_connection,
    prepare_client_response, prepare_server_request, read_request, read_response, send_request,
    send_response, should_keep_alive,
};

// Re-export HTTP/1.1 components (for internal use)
pub use callback::{Http1Callback, HttpProxyMode};
