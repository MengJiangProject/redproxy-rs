use async_trait::async_trait;
use easy_error::{Error, err_msg}; // Removed ResultExt
use quinn::ConnectError as QuinnConnectError; // For MockQuicEndpointConnector
use quinn::ConnectionError as QuinnConnectionError; // For MockQuicConnecting's trait (if this was the error, it's actually QuinnConnectError for connect)
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::io::{Result as IoResult, ErrorKind, Error as StdIoError};


use crate::common::dialers::{
    TcpDialer, TcpConnectionInfo, TlsStreamConnector,
    SimpleDnsResolver, RawUdpSocketLike, UdpSocketFactory
};
use crate::context::{IOStream, IOBufStream};
use rustls::pki_types::ServerName;

// Assuming QuicEndpointConnector trait is in super (connectors/quic.rs)
// For MockQuicEndpointConnector, we need WrappedQuinnConnection
use crate::connectors::quic::QuicEndpointConnector;
use crate::common::quic::QuinnConnection as WrappedQuinnConnection; // This is QuinnConnection(quinn::Connection)


// --- Mock IoStream ---
#[derive(Debug, Clone)]
pub struct MockIoStream {
    pub name: String,
    read_buffer: Arc<Mutex<VecDeque<bytes::Bytes>>>,
    write_buffer: Arc<Mutex<Vec<u8>>>,
    is_closed: Arc<Mutex<bool>>,
}
// ... (impl MockIoStream, AsyncRead, AsyncWrite, IOStream - as previously corrected)
impl MockIoStream {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            read_buffer: Arc::new(Mutex::new(VecDeque::new())),
            write_buffer: Arc::new(Mutex::new(Vec::new())),
            is_closed: Arc::new(Mutex::new(false)),
        }
    }
    pub fn add_read_data(&self, data: bytes::Bytes) {
        self.read_buffer.lock().unwrap().push_back(data);
    }
    pub fn get_written_data(&self) -> Vec<u8> {
        self.write_buffer.lock().unwrap().clone()
    }
    #[allow(dead_code)]
    pub fn close_stream(&self) {
        *self.is_closed.lock().unwrap() = true;
    }
}
impl AsyncRead for MockIoStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<IoResult<()>> {
        if *self.is_closed.lock().unwrap() && self.read_buffer.lock().unwrap().is_empty() {
            return std::task::Poll::Ready(Ok(()));
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
                return std::task::Poll::Ready(Ok(()));
            }
            std::task::Poll::Pending
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
            return std::task::Poll::Ready(Err(StdIoError::new(ErrorKind::BrokenPipe, "Stream is closed")));
        }
        self.write_buffer.lock().unwrap().extend_from_slice(buf);
        std::task::Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: std::pin::Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> std::task::Poll<IoResult<()>> {
        if *self.is_closed.lock().unwrap() {
             return std::task::Poll::Ready(Err(StdIoError::new(ErrorKind::BrokenPipe, "Stream is closed")));
        }
        std::task::Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: std::pin::Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> std::task::Poll<IoResult<()>> {
        *self.is_closed.lock().unwrap() = true;
        std::task::Poll::Ready(Ok(()))
    }
}
impl IOStream for MockIoStream {}


// --- MockTcpDialer ---
#[derive(Default)]
pub struct MockTcpDialer {
    connect_fn: Option<Box<dyn Fn(SocketAddr, Option<std::net::IpAddr>, bool, Option<u32>) -> Result<TcpConnectionInfo, Error> + Send + Sync>>,
    responses: Mutex<VecDeque<Result<TcpConnectionInfo, Error>>>,
}
// ... (impl MockTcpDialer, TcpDialer - as previously corrected)
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
    connect_tls_fn: Option<Box<dyn Fn(ServerName<'static>, IOBufStream) -> Result<IOBufStream, Error> + Send + Sync>>,
    responses: Mutex<VecDeque<Result<IOBufStream, Error>>>,
}
// ... (impl MockTlsStreamConnector, TlsStreamConnector - as previously corrected)
impl MockTlsStreamConnector {
    pub fn new() -> Self { Self::default() }
    #[allow(dead_code)]
    pub fn set_connect_tls_fn(&mut self, f: Box<dyn Fn(ServerName<'static>, IOBufStream) -> Result<IOBufStream, Error> + Send + Sync>) {
        self.connect_tls_fn = Some(f);
    }
     #[allow(dead_code)]
    pub fn add_response(&self, response: Result<IOBufStream, Error>) {
        self.responses.lock().unwrap().push_back(response);
    }
}
#[async_trait]
impl TlsStreamConnector for MockTlsStreamConnector {
    async fn connect_tls(&self, domain: ServerName<'static>, stream: IOBufStream) -> Result<IOBufStream, Error> {
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
// ... (impl MockSimpleDnsResolver, SimpleDnsResolver - as previously corrected)
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
#[derive(Clone, Debug)]
pub struct MockRawUdpSocket {
    local_addr_val: SocketAddr,
    recv_buffer: Arc<Mutex<VecDeque<(Bytes, SocketAddr)>>>,
    sent_data: Arc<Mutex<Vec<(Bytes, SocketAddr)>>>,
}
// ... (impl MockRawUdpSocket, RawUdpSocketLike - as previously corrected)
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
            Err(StdIoError::new(ErrorKind::WouldBlock, "MockRawUdpSocket: No data in recv_buffer"))
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
// ... (impl MockUdpSocketFactory, UdpSocketFactory - as previously corrected)
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

// --- MockQuicEndpointConnector (from connectors/mocks.rs) ---
// This needs to be defined here or connectors/mocks.rs made part of common::mocks
// For now, copied here and adapted.
use crate::connectors::quic::QuicEndpointConnector as ActualQuicEndpointConnector; // Trait
use crate::common::quic::QuinnConnection as ActualWrappedQuinnConnection; // Concrete wrapped type

#[derive(Default)]
pub struct MockQuicEndpointConnector {
    connect_responses: Mutex<VecDeque<Result<ActualWrappedQuinnConnection, QuinnConnectError>>>,
    local_addr_val: Mutex<SocketAddr>,
}

impl MockQuicEndpointConnector {
    pub fn new(local_addr: SocketAddr) -> Self {
        Self {
            connect_responses: Mutex::new(VecDeque::new()),
            local_addr_val: Mutex::new(local_addr),
        }
    }

    #[allow(dead_code)]
    pub fn add_connect_response(&self, response: Result<ActualWrappedQuinnConnection, QuinnConnectError>) {
        self.connect_responses.lock().unwrap().push_back(response);
    }
}

#[async_trait]
impl ActualQuicEndpointConnector for MockQuicEndpointConnector {
    type Connection = ActualWrappedQuinnConnection; // Must be this type

    async fn connect(&self, _remote: SocketAddr, _server_name: &str) -> Result<Self::Connection, QuinnConnectError> {
        if let Some(response) = self.connect_responses.lock().unwrap().pop_front() {
            response
        } else {
            Err(QuinnConnectError::Timeout) // Default error
        }
    }

    fn local_addr(&self) -> IoResult<SocketAddr> {
        Ok(*self.local_addr_val.lock().unwrap())
    }
}
