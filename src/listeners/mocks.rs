use async_trait::async_trait;
use std::collections::VecDeque;
use std::io::{Error as IoError, ErrorKind, Result as IoResult};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::http::TcpListenerLike as HttpTcpListenerLike;
use super::socks::TcpListenerLike as SocksTcpListenerLike;

use super::quic::{QuicConnectingLike, QuicEndpointLike};
use quinn::ConnectError as QuinnConnectError;
// Assuming MockQuicConnection is accessible from common::quic::tests or a common mocks module.
// It needs to be pub and Clone.
use crate::common::quic::tests::MockQuicConnection;


// --- Mock Stream for TCP ---
#[derive(Debug, Clone)]
pub struct MockTcpStream {
    pub name: String,
    read_buffer: Arc<Mutex<VecDeque<bytes::Bytes>>>,
    write_buffer: Arc<Mutex<Vec<u8>>>,
    is_closed: Arc<Mutex<bool>>,
}

impl MockTcpStream {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            read_buffer: Arc::new(Mutex::new(VecDeque::new())),
            write_buffer: Arc::new(Mutex::new(Vec::new())),
            is_closed: Arc::new(Mutex::new(false)), // Corrected: removed extra parenthesis
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
            return Poll::Ready(Ok(()));
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
                return Poll::Ready(Ok(()));
            }
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
    return_error_on_accept: Arc<Mutex<Option<IoError>>>,
}

impl MockTcpListener {
    pub fn new(local_addr: SocketAddr) -> Self {
        Self {
            local_addr_val: local_addr,
            accept_queue: Arc::new(Mutex::new(VecDeque::new())),
            return_error_on_accept: Arc::new(Mutex::new(None)), // Corrected
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
            Err(IoError::new(ErrorKind::NotConnected, "MockTcpListener has no more connections to accept"))
        }
    }

    fn local_addr(&self) -> IoResult<SocketAddr> {
        Ok(self.local_addr_val)
    }
}

#[async_trait]
impl SocksTcpListenerLike for MockTcpListener {
    type Stream = MockTcpStream;

    async fn accept(&self) -> IoResult<(Self::Stream, SocketAddr)> {
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

#[derive(Clone)]
pub struct MockQuicConnecting {
    remote_addr_val: SocketAddr,
    connection_to_return: Arc<MockQuicConnection>,
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
    type Connection = MockQuicConnection;

    async fn wait_for_connection(self) -> Result<Self::Connection, QuinnConnectError> {
        Ok(self.connection_to_return.as_ref().clone())
    }

    fn remote_address(&self) -> SocketAddr {
        self.remote_addr_val
    }
}

pub struct MockQuicEndpoint {
    local_addr_val: SocketAddr,
    accept_queue: Arc<Mutex<VecDeque<MockQuicConnecting>>>,
    return_error_on_accept: Arc<Mutex<bool>>,
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
    pub fn close_listener_immediately(&self) {
        *self.return_error_on_accept.lock().unwrap() = true;
    }
}

#[async_trait]
impl QuicEndpointLike for MockQuicEndpoint {
    type Connecting = MockQuicConnecting;
    type Connection = MockQuicConnection;

    async fn accept(&self) -> Option<Self::Connecting> {
        if *self.return_error_on_accept.lock().unwrap() {
            return None;
        }
        self.accept_queue.lock().unwrap().pop_front()
    }

    fn local_addr(&self) -> IoResult<SocketAddr> {
        Ok(self.local_addr_val)
    }
    fn close(&self, _error_code: quinn::VarInt, _reason: &[u8]) {
        *self.return_error_on_accept.lock().unwrap() = true;
    }
}
