use async_trait::async_trait;
use std::io::Result as IoResult;
use std::net::{IpAddr, SocketAddr};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpSocket, TcpStream};
use easy_error::{Error, ResultExt};

use crate::common::{make_buffered_stream, set_keepalive, IoStream};
#[cfg(target_os = "linux")]
use crate::common::fwmark_direct_socket; // Assuming this is the new name from direct.rs
#[cfg(not(target_os = "linux"))]
use crate::common::fwmark_direct_socket_stub as fwmark_direct_socket; // Need a stub for non-Linux

// --- TCP Connection Info ---
// (This struct was part of direct.rs, moving it here)
pub struct TcpConnectionInfo {
    pub stream: Box<dyn IoStream>,
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
}

// --- Testability Trait for TCP Connection ---
// (This trait was part of direct.rs, moving it here)
#[async_trait]
pub trait TcpDialer: Send + Sync + 'static {
    async fn connect(&self, remote: SocketAddr, local_bind: Option<IpAddr>, keepalive: bool, fwmark: Option<u32>) -> Result<TcpConnectionInfo, Error>;
}

// --- Wrapper for real TCP dialing ---
// (This struct was part of direct.rs, moving it here)
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

        // Use the potentially renamed fwmark_direct_socket or a common fwmark utility
        // Assuming fwmark_direct_socket is the correct function to use now.
        fwmark_direct_socket(&stream, fwmark)?;

        Ok(TcpConnectionInfo {
            stream: make_buffered_stream(stream),
            local_addr,
            remote_addr: peer_addr,
        })
    }
}

// Stub for fwmark_direct_socket on non-Linux platforms
#[cfg(not(target_os = "linux"))]
pub fn fwmark_direct_socket_stub<T>(_sk: &T, _mark: Option<u32>) -> Result<(), Error> {
    tracing::warn!("fwmark not supported on this platform, using stub");
    Ok(())
}

// TODO: Consider adding UdpSocketFactory and RawUdpSocketLike here if they are common enough.
// TODO: Consider adding SimpleDnsResolver and ArcDnsConfigResolver here.

use crate::common::tls::TlsClientConfig;
use rustls::pki_types::ServerName<'static>;
use std::sync::Arc;


// --- Testability Trait for TLS Connection (after TCP is established) ---
#[async_trait]
pub trait TlsStreamConnector: Send + Sync + 'static {
    async fn connect_tls(&self, domain: ServerName<'static>, stream: Box<dyn IoStream>) -> Result<Box<dyn IoStream>, Error>;
}

// --- Wrapper for real tokio_rustls::TlsConnector ---
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
    async fn connect_tls(&self, domain: ServerName<'static>, stream: Box<dyn IoStream>) -> Result<Box<dyn IoStream>, Error> {
        let tls_connector = self.tls_config.connector();
        let rustls_stream = tls_connector.connect(domain, stream).await
            .context("TokioTlsConnectorWrapper: TLS connect error")?;
        Ok(make_buffered_stream(rustls_stream))
    }
}
