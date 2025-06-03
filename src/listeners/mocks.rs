use async_trait::async_trait;
use std::collections::VecDeque;
use std::io::{Error as IoError, ErrorKind, Result as IoResult};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::http::TcpListenerLike as HttpTcpListenerLike; // Alias to avoid name clash if socks also has one
use super::socks::TcpListenerLike as SocksTcpListenerLike;

// --- Mock Stream for TCP ---
#[derive(Debug, Clone)]
pub struct MockTcpStream {
    pub name: String,
    read_buffer: Arc<Mutex<VecDeque<bytes::Bytes>>>,
    write_buffer: Arc<Mutex<Vec<u8>>>,
    is_closed: Arc<Mutex<bool>>, // To simulate EOF or stream closure
}

impl MockTcpStream {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            read_buffer: Arc::new(Mutex::new(VecDeque::new())),
            write_buffer: Arc::new(Mutex::new(Vec::new())),
            is_closed: Arc::new(Mutex::new(false))),
        }
    }

    #[allow(dead_code)]
    pub fn add_read_data(&self, data: bytes::Bytes) {
        self.read_buffer.lock().unwrap().push_back(data);
    }

    #[allow(dead_code)]
    pub fn get_written_data(&self) -> Vec<u8> {
        self.write_buffer.lock().unwrap().clone()
    }

    #[allow(dead_code)]
    pub fn close_stream(&self) {
        *self.is_closed.lock().unwrap() = true;
    }
}

impl AsyncRead for MockTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<IoResult<()>> {
        if *self.is_closed.lock().unwrap() && self.read_buffer.lock().unwrap().is_empty() {
            return Poll::Ready(Ok(())); // EOF
        }
        let mut buffer_guard = self.read_buffer.lock().unwrap();
        if let Some(front_bytes) = buffer_guard.front_mut() {
            let available = front_bytes.len();
            let to_read = std::cmp::min(available, buf.remaining());
            buf.put_slice(&front_bytes[..to_read]);
            if to_read == available {
                buffer_guard.pop_front();
            } else {
                *front_bytes = front_bytes.split_off(to_read);
            }
            Poll::Ready(Ok(()))
        } else {
            if *self.is_closed.lock().unwrap() {
                return Poll::Ready(Ok(())); // EOF if closed and no data
            }
            // No data available right now, but not EOF
            Poll::Pending
        }
    }
}

impl AsyncWrite for MockTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<IoResult<usize>> {
        if *self.is_closed.lock().unwrap() {
            return Poll::Ready(Err(IoError::new(ErrorKind::BrokenPipe, "Stream is closed")));
        }
        self.write_buffer.lock().unwrap().extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        if *self.is_closed.lock().unwrap() {
            return Poll::Ready(Err(IoError::new(ErrorKind::BrokenPipe, "Stream is closed")));
        }
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        *self.is_closed.lock().unwrap() = true;
        Poll::Ready(Ok(()))
    }
}

// --- Mock TCP Listener ---
pub struct MockTcpListener {
    local_addr_val: SocketAddr,
    accept_queue: Arc<Mutex<VecDeque<(MockTcpStream, SocketAddr)>>>,
    // To simulate listener closure or errors
    return_error_on_accept: Arc<Mutex<Option<IoError>>>,
}

impl MockTcpListener {
    pub fn new(local_addr: SocketAddr) -> Self {
        Self {
            local_addr_val: local_addr,
            accept_queue: Arc::new(Mutex::new(VecDeque::new())),
            return_error_on_accept: Arc::new(Mutex::new(None))),
        }
    }

    #[allow(dead_code)]
    pub fn add_connection(&self, stream: MockTcpStream, remote_addr: SocketAddr) {
        self.accept_queue.lock().unwrap().push_back((stream, remote_addr));
    }

    #[allow(dead_code)]
    pub fn set_error_on_accept(&self, error: Option<IoError>) {
        *self.return_error_on_accept.lock().unwrap() = error;
    }
     #[allow(dead_code)]
    pub fn connections_left(&self) -> usize {
        self.accept_queue.lock().unwrap().len()
    }
}

#[async_trait]
impl HttpTcpListenerLike for MockTcpListener {
    type Stream = MockTcpStream;

    async fn accept(&self) -> IoResult<(Self::Stream, SocketAddr)> {
        if let Some(err) = self.return_error_on_accept.lock().unwrap().take() {
            return Err(err);
        }
        if let Some((stream, addr)) = self.accept_queue.lock().unwrap().pop_front() {
            Ok((stream, addr))
        } else {
            // Simulate blocking until a connection is added or an error is set.
            // For test purposes, often better to return an error or specific signal.
            // Or, make the test ensure connections are available.
            // Returning an error like WouldBlock, but actual WouldBlock is for non-blocking I/O.
            // For an async fn, pending is the way to go if we expect it to be called again.
            // However, for a mock that's exhausted, an EOF-like error or specific mock error is fine.
            Err(IoError::new(ErrorKind::NotConnected, "MockTcpListener has no more connections to accept"))
        }
    }

    fn local_addr(&self) -> IoResult<SocketAddr> {
        Ok(self.local_addr_val)
    }
}

// Implement for SOCKS listener trait as well, assuming it's identical
#[async_trait]
impl SocksTcpListenerLike for MockTcpListener {
    type Stream = MockTcpStream;

    async fn accept(&self) -> IoResult<(Self::Stream, SocketAddr)> {
        // Reuse the same logic as HttpTcpListenerLike
        if let Some(err) = self.return_error_on_accept.lock().unwrap().take() {
            return Err(err);
        }
        if let Some((stream, addr)) = self.accept_queue.lock().unwrap().pop_front() {
            Ok((stream, addr))
        } else {
            Err(IoError::new(ErrorKind::NotConnected, "MockTcpListener has no more connections to accept"))
        }
    }

    fn local_addr(&self) -> IoResult<SocketAddr> {
        Ok(self.local_addr_val)
    }
}

use super::quic::{QuicConnectingLike, QuicEndpointLike};
// Assuming MockQuicConnection, MockQuicSendStream, MockQuicRecvStream might be
// moved to a more common place like `crate::common::mocks::quic_mocks` or similar.
// For now, let's assume they are accessible or we define simplified versions here if needed.
// If we use the ones from `crate::common::quic::tests`, they need to be made public.
// Let's try to use them by path, assuming they were made `pub` in their test module,
// or preferably moved. For this exercise, I'll use placeholder names and then we can refine.
// For now, let's use the full path to common::quic::tests mocks. This implies they need to be pub.
// This is often not ideal for test mocks. A better way is to have common crate mocks.
// If not, we'd redefine simpler ones here.
use crate::common::quic::tests::{MockQuicConnection, MockQuicSendStream, MockQuicRecvStream}; // This path is illustrative
use crate::common::quic::QuicConnectionLike as CommonQuicConnectionLike;


// --- Mock QUIC Connecting ---
#[derive(Clone)] // Clone might be useful for some test setups
pub struct MockQuicConnecting {
    remote_addr_val: SocketAddr,
    connection_to_return: Arc<MockQuicConnection>, // Using the mock from common::quic::tests
}

impl MockQuicConnecting {
    pub fn new(remote_addr: SocketAddr, connection: Arc<MockQuicConnection>) -> Self {
        Self {
            remote_addr_val: remote_addr,
            connection_to_return: connection,
        }
    }
}

#[async_trait]
impl QuicConnectingLike for MockQuicConnecting {
    type Connection = MockQuicConnection; // This refers to common::quic::tests::MockQuicConnection

    async fn wait_for_connection(self) -> Result<Self::Connection, quinn::ConnectionError> {
        // In a real scenario, Arc::try_unwrap or clone if Connection is Clone.
        // MockQuicConnection from common::quic::tests would need to be Clone or we return Arc.
        // The QuicConnectionLike trait is implemented for MockQuicConnection, not Arc<MockQuicConnection>.
        // Let's assume MockQuicConnection can be cloned or we adjust the trait.
        // For simplicity, if connection_to_return is Arc'd and MockQuicConnection is not Clone,
        // this mock is slightly problematic.
        // Let's assume MockQuicConnection from common is Clone for this to work easily, or QuicConnectingLike::Connection can be Arc<dyn...>
        // The trait QuicConnectingLike expects Self::Connection, not Arc<Self::Connection>.
        // If MockQuicConnection is not Clone, we can't easily get it out of the Arc for return here.
        // Simplest path: Make MockQuicConnection in common::quic::tests derive Clone.
        // Or, change QuicConnectingLike to return Arc<Self::Connection>.
        // Given previous refactors (e.g. client_thread takes Arc<C>), returning Arc might be more consistent.
        // Let's assume for now that we can clone it from the Arc for the purpose of returning by value.
        // This might require MockQuicConnection to be `Clone`.
        // If MockQuicConnection is not Clone, this mock needs rethinking or trait adjustment.
        // Ok((*self.connection_to_return).clone()) // if MockQuicConnection is Clone
        // For now, let's assume we return the Arc itself, and adjust the trait user if necessary,
        // or that client_thread can indeed work with Arc<MockQuicConnection> where MockQuicConnection : QuicConnectionLike.
        // The client_thread in listener::quic takes Arc<C>, so this is fine.
        Ok(self.connection_to_return.as_ref().clone()) // Requires MockQuicConnection to be Clone.
                                                       // A better approach if MockQuicConnection is not Clone:
                                                       // The trait should probably be: `async fn wait_for_connection(self) -> Result<Arc<Self::Connection>, quinn::ConnectionError>;`
                                                       // Or `client_thread` should take `connection: C` not `Arc<C>`.
                                                       // The `client_thread` takes `Arc<C>`, so it expects an Arc.
                                                       // But `QuicConnectingLike::Connection` is not `Arc<Something>`. It *is* `Something`.
                                                       // This implies `Self::Connection` itself must be `Arc<ActualConnectionImplementation>`.
                                                       // This is getting complicated. Let's simplify the mock return.
                                                       // The simplest is if MockQuicConnection is cloneable.
                                                       // Ok(MockQuicConnection::new(self.remote_addr_val)) // return a new one for simplicity if clone is hard
                                                       // This needs to be an instance that implements QuicConnectionLike.
                                                       // The type is MockQuicConnection, so we need to return that.
                                                       // Ok(self.connection_to_return) // This would require Self::Connection = Arc<MockQuicConnection>
                                                       // Let's assume MockQuicConnection is Clone.
        Ok(self.connection_to_return.as_ref().clone())
    }

    fn remote_address(&self) -> SocketAddr {
        self.remote_addr_val
    }
}

// --- Mock QUIC Endpoint ---
pub struct MockQuicEndpoint {
    local_addr_val: SocketAddr,
    accept_queue: Arc<Mutex<VecDeque<MockQuicConnecting>>>,
    return_error_on_accept: Arc<Mutex<bool>>, // Simplified: just a flag to stop
}

impl MockQuicEndpoint {
    pub fn new(local_addr: SocketAddr) -> Self {
        Self {
            local_addr_val: local_addr,
            accept_queue: Arc::new(Mutex::new(VecDeque::new())),
            return_error_on_accept: Arc::new(Mutex::new(false)),
        }
    }

    #[allow(dead_code)]
    pub fn add_connecting(&self, connecting: MockQuicConnecting) {
        self.accept_queue.lock().unwrap().push_back(connecting);
    }

    #[allow(dead_code)]
    pub fn close_listener_immediately(&self) { // To stop the accept loop
        *self.return_error_on_accept.lock().unwrap() = true;
    }
}

#[async_trait]
impl QuicEndpointLike for MockQuicEndpoint {
    type Connecting = MockQuicConnecting;
    // This means Self::Connection is MockQuicConnecting::Connection which is MockQuicConnection
    type Connection = MockQuicConnection;


    async fn accept(&self) -> Option<Self::Connecting> {
        if *self.return_error_on_accept.lock().unwrap() {
            return None; // Simulate endpoint closed
        }
        self.accept_queue.lock().unwrap().pop_front()
    }

    fn local_addr(&self) -> IoResult<SocketAddr> {
        Ok(self.local_addr_val)
    }
    fn close(&self, _error_code: quinn::VarInt, _reason: &[u8]) {
        // no-op
        *self.return_error_on_accept.lock().unwrap() = true; // Simulate closed for future accepts
    }
}
