// --- Mock Implementations for Connector Dependencies ---
// These mocks are intended for use in testing individual connectors.

use async_trait::async_trait;
use easy_error::{Error, ResultExt, err_msg};
use std::collections::VecDeque;
use std::io::{Result as IoResult, ErrorKind};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf}; // For MockIoStream
use bytes::Bytes; // For MockIoStream read buffer

use crate::common::dialers::{
    TcpDialer, TcpConnectionInfo, TlsStreamConnector,
    SimpleDnsResolver, RawUdpSocketLike, UdpSocketFactory // These are now in common::dialers
};
use crate::common::IoStream;
use rustls::pki_types::ServerName<'static>;


// --- Mock IoStream (basic version for testing dialers) ---
#[derive(Debug, Clone)] // Added Clone
pub struct MockIoStream {
    pub name: String,
    read_buffer: Arc<Mutex<VecDeque<Bytes>>>, // Changed to Arc<Mutex<>>
    write_buffer: Arc<Mutex<Vec<u8>>>,      // Changed to Arc<Mutex<>>
    is_closed: Arc<Mutex<bool>>,            // Changed to Arc<Mutex<>>
}

impl MockIoStream {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            read_buffer: Arc::new(Mutex::new(VecDeque::new())),
            write_buffer: Arc::new(Mutex::new(Vec::new())),
            is_closed: Arc::new(Mutex::new(false)),
        }
    }
    pub fn add_read_data(&self, data: Bytes) {
        self.read_buffer.lock().unwrap().push_back(data);
    }
    pub fn get_written_data(&self) -> Vec<u8> {
        self.write_buffer.lock().unwrap().clone()
    }
    // Added to allow test to signal stream closure if needed, e.g. for read EOF
    #[allow(dead_code)]
    pub fn close_stream(&self) {
        *self.is_closed.lock().unwrap() = true;
    }
}

impl AsyncRead for MockIoStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<IoResult<()>> {
        if *self.is_closed.lock().unwrap() && self.read_buffer.lock().unwrap().is_empty() {
            return std::task::Poll::Ready(Ok(())); // EOF
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
            std::task::Poll::Ready(Ok(()))
        } else {
            if *self.is_closed.lock().unwrap() {
                return std::task::Poll::Ready(Ok(())); // EOF if closed
            }
            std::task::Poll::Pending // No data, not closed
        }
    }
}
impl AsyncWrite for MockIoStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<IoResult<usize>> {
        if *self.is_closed.lock().unwrap() {
            return std::task::Poll::Ready(Err(IoError::new(ErrorKind::BrokenPipe, "Stream is closed")));
        }
        self.write_buffer.lock().unwrap().extend_from_slice(buf);
        std::task::Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: std::pin::Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> std::task::Poll<IoResult<()>> {
        if *self.is_closed.lock().unwrap() {
             return std::task::Poll::Ready(Err(IoError::new(ErrorKind::BrokenPipe, "Stream is closed")));
        }
        std::task::Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: std::pin::Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> std::task::Poll<IoResult<()>> {
        *self.is_closed.lock().unwrap() = true;
        std::task::Poll::Ready(Ok(()))
    }
}
impl IoStream for MockIoStream {}


// --- MockTcpDialer ---
#[derive(Default)]
pub struct MockTcpDialer {
    // Function to call on connect, allows custom mock behavior per test
    connect_fn: Option<Box<dyn Fn(SocketAddr, Option<std::net::IpAddr>, bool, Option<u32>) -> Result<TcpConnectionInfo, Error> + Send + Sync>>,
    // Or, a queue of responses
    responses: Mutex<VecDeque<Result<TcpConnectionInfo, Error>>>,
}

impl MockTcpDialer {
    pub fn new() -> Self { Self::default() }
    #[allow(dead_code)]
    pub fn set_connect_fn(&mut self, f: Box<dyn Fn(SocketAddr, Option<std::net::IpAddr>, bool, Option<u32>) -> Result<TcpConnectionInfo, Error> + Send + Sync>) {
        self.connect_fn = Some(f);
    }
    #[allow(dead_code)]
    pub fn add_response(&self, response: Result<TcpConnectionInfo, Error>) {
        self.responses.lock().unwrap().push_back(response);
    }
}

#[async_trait]
impl TcpDialer for MockTcpDialer {
    async fn connect(&self, remote: SocketAddr, local_bind: Option<std::net::IpAddr>, keepalive: bool, fwmark: Option<u32>) -> Result<TcpConnectionInfo, Error> {
        if let Some(f) = &self.connect_fn {
            return f(remote, local_bind, keepalive, fwmark);
        }
        if let Some(response) = self.responses.lock().unwrap().pop_front() {
            return response;
        }
        Err(err_msg("MockTcpDialer: No connect_fn or queued response"))
    }
}

// --- MockTlsStreamConnector ---
#[derive(Default)]
pub struct MockTlsStreamConnector {
    connect_tls_fn: Option<Box<dyn Fn(ServerName<'static>, Box<dyn IoStream>) -> Result<Box<dyn IoStream>, Error> + Send + Sync>>,
    responses: Mutex<VecDeque<Result<Box<dyn IoStream>, Error>>>,
}

impl MockTlsStreamConnector {
    pub fn new() -> Self { Self::default() }
    #[allow(dead_code)]
    pub fn set_connect_tls_fn(&mut self, f: Box<dyn Fn(ServerName<'static>, Box<dyn IoStream>) -> Result<Box<dyn IoStream>, Error> + Send + Sync>) {
        self.connect_tls_fn = Some(f);
    }
     #[allow(dead_code)]
    pub fn add_response(&self, response: Result<Box<dyn IoStream>, Error>) {
        self.responses.lock().unwrap().push_back(response);
    }
}

#[async_trait]
impl TlsStreamConnector for MockTlsStreamConnector {
    async fn connect_tls(&self, domain: ServerName<'static>, stream: Box<dyn IoStream>) -> Result<Box<dyn IoStream>, Error> {
        if let Some(f) = &self.connect_tls_fn {
            return f(domain, stream);
        }
        if let Some(response) = self.responses.lock().unwrap().pop_front() {
            return response;
        }
        Err(err_msg("MockTlsStreamConnector: No connect_tls_fn or queued response"))
    }
}

// --- MockSimpleDnsResolver ---
#[derive(Default)]
pub struct MockSimpleDnsResolver {
    lookup_fn: Option<Box<dyn Fn(&str, u16) -> Result<SocketAddr, Error> + Send + Sync>>,
    responses: Mutex<VecDeque<Result<SocketAddr, Error>>>,
}

impl MockSimpleDnsResolver {
    pub fn new() -> Self { Self::default() }
    #[allow(dead_code)]
    pub fn set_lookup_fn(&mut self, f: Box<dyn Fn(&str, u16) -> Result<SocketAddr, Error> + Send + Sync>) {
        self.lookup_fn = Some(f);
    }
    #[allow(dead_code)]
    pub fn add_response(&self, response: Result<SocketAddr, Error>) {
        self.responses.lock().unwrap().push_back(response);
    }
}

#[async_trait]
impl SimpleDnsResolver for MockSimpleDnsResolver {
    async fn lookup_host(&self, domain: &str, port: u16) -> Result<SocketAddr, Error> {
        if let Some(f) = &self.lookup_fn {
            return f(domain, port);
        }
         if let Some(response) = self.responses.lock().unwrap().pop_front() {
            return response;
        }
        Err(err_msg("MockSimpleDnsResolver: No lookup_fn or queued response"))
    }
}

// --- MockRawUdpSocket (implements RawUdpSocketLike) ---
#[derive(Clone, Debug)] // Clone needed if Arc<MockRawUdpSocket> is used and cloned.
pub struct MockRawUdpSocket {
    local_addr_val: SocketAddr,
    recv_buffer: Arc<Mutex<VecDeque<(Bytes, SocketAddr)>>>, // Data to be received, and from where
    sent_data: Arc<Mutex<Vec<(Bytes, SocketAddr)>>>,     // Data sent, and to where
}

impl MockRawUdpSocket {
    pub fn new(local_addr: SocketAddr) -> Self {
        Self {
            local_addr_val: local_addr,
            recv_buffer: Arc::new(Mutex::new(VecDeque::new())),
            sent_data: Arc::new(Mutex::new(Vec::new())),
        }
    }
    #[allow(dead_code)]
    pub fn add_recv_data(&self, data: Bytes, from: SocketAddr) {
        self.recv_buffer.lock().unwrap().push_back((data, from));
    }
    #[allow(dead_code)]
    pub fn get_sent_data(&self) -> Vec<(Bytes, SocketAddr)> {
        self.sent_data.lock().unwrap().clone()
    }
}

#[async_trait]
impl RawUdpSocketLike for MockRawUdpSocket {
    async fn recv_from_raw(&self, buf: &mut [u8]) -> IoResult<(usize, SocketAddr)> {
        if let Some((data, from_addr)) = self.recv_buffer.lock().unwrap().pop_front() {
            let len = std::cmp::min(buf.len(), data.len());
            buf[..len].copy_from_slice(&data[..len]);
            Ok((len, from_addr))
        } else {
            Err(IoError::new(ErrorKind::WouldBlock, "MockRawUdpSocket: No data in recv_buffer"))
        }
    }
    async fn send_to_raw(&self, buf: &[u8], target: SocketAddr) -> IoResult<usize> {
        self.sent_data.lock().unwrap().push((Bytes::copy_from_slice(buf), target));
        Ok(buf.len())
    }
    fn local_addr_raw(&self) -> IoResult<SocketAddr> {
        Ok(self.local_addr_val)
    }
}

// --- MockUdpSocketFactory ---
#[derive(Default)]
pub struct MockUdpSocketFactory {
    create_fn: Option<Box<dyn Fn(SocketAddr, Option<SocketAddr>, Option<u32>) -> Result<Arc<dyn RawUdpSocketLike>, Error> + Send + Sync>>,
    responses: Mutex<VecDeque<Result<Arc<dyn RawUdpSocketLike>, Error>>>,
}

impl MockUdpSocketFactory {
    pub fn new() -> Self { Self::default() }
    #[allow(dead_code)]
    pub fn set_create_fn(&mut self, f: Box<dyn Fn(SocketAddr, Option<SocketAddr>, Option<u32>) -> Result<Arc<dyn RawUdpSocketLike>, Error> + Send + Sync>) {
        self.create_fn = Some(f);
    }
    #[allow(dead_code)]
    pub fn add_response(&self, response: Result<Arc<dyn RawUdpSocketLike>, Error>) {
        self.responses.lock().unwrap().push_back(response);
    }
}

#[async_trait]
impl UdpSocketFactory for MockUdpSocketFactory {
    async fn create_raw_udp_socket(
        &self,
        local_bind_addr: SocketAddr,
        connect_to_remote: Option<SocketAddr>,
        fwmark: Option<u32>,
    ) -> Result<Arc<dyn RawUdpSocketLike>, Error> {
        if let Some(f) = &self.create_fn {
            return f(local_bind_addr, connect_to_remote, fwmark);
        }
        if let Some(response) = self.responses.lock().unwrap().pop_front() {
            return response;
        }
        Err(err_msg("MockUdpSocketFactory: No create_fn or queued response"))
    }
}
