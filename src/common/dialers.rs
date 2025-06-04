use async_trait::async_trait;
use std::io::Result as IoResult;
use std::net::{IpAddr, SocketAddr};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use easy_error::{Error, ResultExt};

use crate::context::{make_buffered_stream, IOStream, IOBufStream};
use crate::common::set_keepalive;
#[cfg(target_os = "linux")]
use crate::common::network_utils::fwmark_direct_socket;
#[cfg(not(target_os = "linux"))]
use crate::common::network_utils::fwmark_direct_socket_stub as fwmark_direct_socket;

use crate::common::dns::DnsConfig;
use crate::common::udp::udp_socket;


// --- TCP Connection Info ---
pub struct TcpConnectionInfo {
    pub stream: IOBufStream,
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
}

#[async_trait]
pub trait TcpDialer: Send + Sync + 'static {
    async fn connect(&self, remote: SocketAddr, local_bind: Option<IpAddr>, keepalive: bool, fwmark: Option<u32>) -> Result<TcpConnectionInfo, Error>;
}

pub struct TokioTcpDialer;

#[async_trait]
impl TcpDialer for TokioTcpDialer {
    async fn connect(&self, remote: SocketAddr, local_bind: Option<IpAddr>, keepalive_opt: bool, fwmark: Option<u32>) -> Result<TcpConnectionInfo, Error> {
        let socket = if remote.is_ipv4() {
            TcpSocket::new_v4().context("socket v4")?
        } else {
            TcpSocket::new_v6().context("socket v6")?
        };

        if let Some(bind_ip) = local_bind {
            socket.bind(SocketAddr::new(bind_ip, 0)).context("bind")?;
        }

        let stream = socket.connect(remote).await.context("connect")?;
        let local_addr = stream.local_addr().context("get local_addr")?;
        let peer_addr = stream.peer_addr().context("get peer_addr")?;

        if keepalive_opt {
            set_keepalive(&stream)?;
        }

        fwmark_direct_socket(&stream, fwmark)?;

        Ok(TcpConnectionInfo {
            stream: make_buffered_stream(stream),
            local_addr,
            remote_addr: peer_addr,
        })
    }
}

// --- TLS Stream Connector ---
use crate::common::tls::TlsClientConfig;
use rustls::pki_types::ServerName; // Corrected
use std::sync::Arc;

#[async_trait]
pub trait TlsStreamConnector: Send + Sync + 'static {
    async fn connect_tls(&self, domain: ServerName<'static>, stream: IOBufStream) -> Result<IOBufStream, Error>;
}

pub struct TokioTlsConnectorWrapper {
    tls_config: Arc<TlsClientConfig>,
}

impl TokioTlsConnectorWrapper {
    pub fn new(tls_config: Arc<TlsClientConfig>) -> Self {
        Self { tls_config }
    }
}

#[async_trait]
impl TlsStreamConnector for TokioTlsConnectorWrapper {
    async fn connect_tls(&self, domain: ServerName<'static>, stream: IOBufStream) -> Result<IOBufStream, Error> {
        let tls_connector = self.tls_config.connector();
        let unbuffered_inner_stream = stream.into_inner().into_inner();

        let rustls_stream = tls_connector.connect(domain, unbuffered_inner_stream).await
            .context("TokioTlsConnectorWrapper: TLS connect error")?;
        Ok(make_buffered_stream(rustls_stream))
    }
}

// --- DNS Resolver ---
use crate::common::dns::AddressFamily;

#[async_trait]
pub trait SimpleDnsResolver: Send + Sync + 'static {
    async fn lookup_host(&self, domain: &str, port: u16) -> Result<SocketAddr, Error>;
}

#[derive(Clone)]
pub struct ArcDnsConfigResolver(pub Arc<DnsConfig>);

#[async_trait]
impl SimpleDnsResolver for ArcDnsConfigResolver {
    async fn lookup_host(&self, domain: &str, port: u16) -> Result<SocketAddr, Error> {
        self.0.lookup_host(domain, port).await
    }
}

// --- UDP Socket Abstractions ---
#[async_trait]
pub trait RawUdpSocketLike: Send + Sync + 'static {
    async fn recv_from_raw(&self, buf: &mut [u8]) -> IoResult<(usize, SocketAddr)>;
    async fn send_to_raw(&self, buf: &[u8], target: SocketAddr) -> IoResult<usize>;
    fn local_addr_raw(&self) -> IoResult<SocketAddr>;
}

#[async_trait]
impl RawUdpSocketLike for UdpSocket {
    async fn recv_from_raw(&self, buf: &mut [u8]) -> IoResult<(usize, SocketAddr)> {
        self.recv_from(buf).await
    }
    async fn send_to_raw(&self, buf: &[u8], target: SocketAddr) -> IoResult<usize> {
        self.send_to(buf, target).await
    }
    fn local_addr_raw(&self) -> IoResult<SocketAddr> {
        self.local_addr()
    }
}

#[async_trait]
pub trait UdpSocketFactory: Send + Sync + 'static {
    async fn create_raw_udp_socket(
        &self,
        local_bind_addr: SocketAddr,
        connect_to_remote: Option<SocketAddr>,
        fwmark: Option<u32>,
    ) -> Result<Arc<dyn RawUdpSocketLike>, Error>;
}

pub struct TokioUdpSocketFactory;

#[async_trait]
impl UdpSocketFactory for TokioUdpSocketFactory {
    async fn create_raw_udp_socket(
        &self,
        local_bind_addr: SocketAddr,
        connect_to_remote: Option<SocketAddr>,
        fwmark: Option<u32>,
    ) -> Result<Arc<dyn RawUdpSocketLike>, Error> {
        let real_udp_socket = udp_socket(local_bind_addr, connect_to_remote, false)
            .context("TokioUdpSocketFactory: failed to create udp_socket")?;
        fwmark_direct_socket(&real_udp_socket, fwmark)
             .context("TokioUdpSocketFactory: failed to set fwmark")?;
        Ok(Arc::new(real_udp_socket))
    }
}
