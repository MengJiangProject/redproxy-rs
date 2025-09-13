use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use std::io;
use std::net::{IpAddr, SocketAddr};
use tokio::net::{TcpListener as TokioTcpListener, TcpSocket, UdpSocket, lookup_host};
use tokio::time::Duration;
use tracing::{error, warn};

use crate::common::tls::{TlsClientConfig, TlsServerConfig};
use crate::common::udp::udp_socket;
use crate::context::IOStream;

#[cfg(not(windows))]
pub fn set_keepalive(stream: &tokio::net::TcpStream) -> anyhow::Result<()> {
    use anyhow::Context;
    use nix::sys::socket::{setsockopt, sockopt::KeepAlive};
    setsockopt(stream, KeepAlive, &true).context("setsockopt")
}

#[cfg(windows)]
pub fn set_keepalive(stream: &tokio::net::TcpStream) -> anyhow::Result<()> {
    use anyhow::Context;
    use std::os::windows::prelude::AsRawSocket;
    crate::common::windows::set_keepalive(stream.as_raw_socket() as _, true).context("setsockopt")
}

#[async_trait]
pub trait TcpListener: Send + Sync {
    async fn accept(&self) -> Result<(Box<dyn IOStream>, SocketAddr)>;
    async fn local_addr(&self) -> Result<SocketAddr>;
}

// Clean, low-level socket abstraction equivalent to Tokio socket library
#[async_trait]
pub trait SocketOps: Send + Sync {
    // DNS
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>>;

    // TCP
    async fn tcp_listen(&self, local: SocketAddr) -> Result<Box<dyn TcpListener>>;
    async fn tcp_connect(
        &self,
        remote: SocketAddr,
        bind: Option<IpAddr>,
    ) -> Result<(Box<dyn IOStream>, SocketAddr, SocketAddr)>;

    // UDP
    async fn udp_bind(&self, local: SocketAddr) -> Result<(UdpSocket, SocketAddr)>;

    // TLS
    async fn tls_handshake_client(
        &self,
        stream: Box<dyn IOStream>,
        server_name: &str,
        tls_config: &TlsClientConfig,
    ) -> Result<Box<dyn IOStream>>;
    async fn tls_handshake_server(
        &self,
        stream: Box<dyn IOStream>,
        tls_config: &TlsServerConfig,
    ) -> Result<(Box<dyn IOStream>, Option<String>)>;

    // Socket Options
    async fn set_keepalive(&self, stream: &dyn IOStream, enable: bool) -> Result<()>;
    async fn set_fwmark(&self, stream: &dyn IOStream, mark: Option<u32>) -> Result<()>;
}

// Real implementation using actual Tokio sockets
pub struct RealSocketOps;

pub struct RealTcpListener {
    listener: TokioTcpListener,
}

#[async_trait]
impl TcpListener for RealTcpListener {
    async fn accept(&self) -> Result<(Box<dyn IOStream>, SocketAddr)> {
        loop {
            match self.listener.accept().await {
                Ok((stream, addr)) => {
                    return Ok((Box::new(stream), addr));
                }
                Err(e) => {
                    match e.kind() {
                        // Transient errors - retry with minimal backoff
                        io::ErrorKind::WouldBlock
                        | io::ErrorKind::ConnectionAborted
                        | io::ErrorKind::Interrupted => {
                            warn!("Transient accept error: {}, retrying", e);
                            tokio::time::sleep(Duration::from_millis(10)).await;
                            continue;
                        }

                        // Resource exhaustion - longer backoff before retry
                        io::ErrorKind::OutOfMemory => {
                            error!("Resource exhaustion during accept: {}, backing off", e);
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            continue;
                        }

                        // Fatal errors - bubble up to application
                        io::ErrorKind::PermissionDenied
                        | io::ErrorKind::InvalidInput
                        | io::ErrorKind::AddrNotAvailable
                        | io::ErrorKind::AddrInUse => {
                            return Err(e.into());
                        }

                        // Unknown errors - be conservative, retry with backoff
                        _ => {
                            warn!("Unknown accept error: {}, retrying after backoff", e);
                            tokio::time::sleep(Duration::from_millis(50)).await;
                            continue;
                        }
                    }
                }
            }
        }
    }

    async fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }
}

#[async_trait]
impl SocketOps for RealSocketOps {
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>> {
        let addrs = lookup_host((host, 0))
            .await?
            .map(|addr| addr.ip())
            .collect();
        Ok(addrs)
    }

    async fn tcp_listen(&self, local: SocketAddr) -> Result<Box<dyn TcpListener>> {
        let listener = TokioTcpListener::bind(local).await?;
        Ok(Box::new(RealTcpListener { listener }))
    }

    async fn tcp_connect(
        &self,
        remote: SocketAddr,
        bind: Option<IpAddr>,
    ) -> Result<(Box<dyn IOStream>, SocketAddr, SocketAddr)> {
        let server = if remote.is_ipv4() {
            TcpSocket::new_v4().context("socket")?
        } else {
            TcpSocket::new_v6().context("socket")?
        };

        if let Some(bind_ip) = bind {
            server.bind(SocketAddr::new(bind_ip, 0)).context("bind")?;
        }

        let stream = server.connect(remote).await.context("connect")?;
        let local = stream.local_addr().context("local_addr")?;
        let peer = stream.peer_addr().context("peer_addr")?;

        Ok((Box::new(stream), local, peer))
    }

    async fn udp_bind(&self, local: SocketAddr) -> Result<(UdpSocket, SocketAddr)> {
        let socket = udp_socket(local, None, false).context("setup socket")?;
        let local_addr = socket.local_addr().context("local_addr")?;
        Ok((socket, local_addr))
    }

    async fn tls_handshake_client(
        &self,
        stream: Box<dyn IOStream>,
        server_name: &str,
        tls_config: &TlsClientConfig,
    ) -> Result<Box<dyn IOStream>> {
        use rustls::pki_types::ServerName;

        let tls_connector = tls_config.connector()?;
        let domain = ServerName::try_from(server_name.to_string())
            .or_else(|e| {
                if tls_config.insecure {
                    ServerName::try_from("example.com")
                } else {
                    Err(e)
                }
            })
            .map_err(|_e| anyhow!("invalid server name: {}", server_name))?;

        let tls_stream = tls_connector
            .connect(domain, stream)
            .await
            .context("TLS handshake failed")?;
        Ok(Box::new(tls_stream))
    }

    async fn tls_handshake_server(
        &self,
        stream: Box<dyn IOStream>,
        tls_config: &TlsServerConfig,
    ) -> Result<(Box<dyn IOStream>, Option<String>)> {
        let tls_acceptor = tls_config.acceptor()?;
        let tls_stream = tls_acceptor
            .accept(stream)
            .await
            .context("TLS handshake failed")?;

        // Extract ALPN protocol before boxing
        let alpn_protocol = tls_stream
            .get_ref()
            .1
            .alpn_protocol()
            .map(|bytes| String::from_utf8_lossy(bytes).to_string());

        Ok((Box::new(tls_stream), alpn_protocol))
    }

    async fn set_keepalive(&self, stream: &dyn IOStream, enable: bool) -> Result<()> {
        if let Some(tcp_stream) = stream.as_any().downcast_ref::<tokio::net::TcpStream>()
            && enable
        {
            set_keepalive(tcp_stream)?;
        }
        Ok(())
    }

    async fn set_fwmark(&self, stream: &dyn IOStream, mark: Option<u32>) -> Result<()> {
        if let Some(tcp_stream) = stream.as_any().downcast_ref::<tokio::net::TcpStream>() {
            set_fwmark(tcp_stream, mark)?;
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub fn set_fwmark<T: std::os::unix::prelude::AsFd>(sk: &T, mark: Option<u32>) -> Result<()> {
    use nix::sys::socket::setsockopt;
    use nix::sys::socket::sockopt::Mark;
    if mark.is_none() {
        return Ok(());
    }
    let mark = mark.unwrap();
    setsockopt(sk, Mark, &mark).context("setsockopt")
}

#[cfg(not(target_os = "linux"))]
pub fn set_fwmark<T>(_sk: &T, _mark: Option<u32>) -> Result<()> {
    tracing::warn!("fwmark not supported on this platform");
    Ok(())
}

#[cfg(test)]
pub mod test_utils {
    use super::*;
    use tokio_test::io::Builder;
    use tokio_test::io::Mock;

    // Flexible stream interaction builder for different protocols
    #[derive(Clone, Debug)]
    pub enum StreamInteraction {
        Write(Vec<u8>),
        Read(Vec<u8>),
    }

    #[derive(Clone, Debug, Default)]
    pub struct StreamScript {
        pub interactions: Vec<StreamInteraction>,
    }

    impl StreamScript {
        pub fn new() -> Self {
            Self {
                interactions: Vec::new(),
            }
        }

        pub fn write(mut self, data: &[u8]) -> Self {
            self.interactions
                .push(StreamInteraction::Write(data.to_vec()));
            self
        }

        pub fn read(mut self, data: &[u8]) -> Self {
            self.interactions
                .push(StreamInteraction::Read(data.to_vec()));
            self
        }

        pub fn build(self) -> Mock {
            let mut builder = Builder::new();
            for interaction in self.interactions {
                match interaction {
                    StreamInteraction::Write(data) => {
                        builder.write(&data);
                    }
                    StreamInteraction::Read(data) => {
                        builder.read(&data);
                    }
                }
            }
            builder.build()
        }
    }

    // Default stream builder for plain TCP connections (no protocol interactions)
    fn default_tcp_stream() -> Mock {
        StreamScript::new().build()
    }

    pub struct MockTcpListener;

    #[async_trait]
    impl TcpListener for MockTcpListener {
        async fn accept(&self) -> Result<(Box<dyn IOStream>, SocketAddr)> {
            let stream = default_tcp_stream();
            let addr = "127.0.0.1:12345".parse().unwrap();
            Ok((Box::new(stream), addr))
        }

        async fn local_addr(&self) -> Result<SocketAddr> {
            Ok("127.0.0.1:8080".parse().unwrap())
        }
    }

    // Mock SocketOps that accepts higher-level logic for creating protocol-specific mock streams
    pub struct MockSocketOps<F = fn() -> Mock>
    where
        F: Fn() -> Mock + Send + Sync + Clone,
    {
        pub tcp_result: std::result::Result<(SocketAddr, SocketAddr), String>,
        pub udp_result: std::result::Result<SocketAddr, String>,
        pub stream_builder: F,
    }

    impl<F> Clone for MockSocketOps<F>
    where
        F: Fn() -> Mock + Send + Sync + Clone,
    {
        fn clone(&self) -> Self {
            Self {
                tcp_result: self.tcp_result.clone(),
                udp_result: self.udp_result.clone(),
                stream_builder: self.stream_builder.clone(),
            }
        }
    }

    impl MockSocketOps {
        // Default constructor uses plain TCP streams (backward compatibility)
        pub fn new() -> Self {
            Self::new_with_builder(default_tcp_stream)
        }
    }

    impl Default for MockSocketOps {
        fn default() -> Self {
            Self::new()
        }
    }

    impl<F> MockSocketOps<F>
    where
        F: Fn() -> Mock + Send + Sync + Clone,
    {
        // Constructor that accepts custom stream builder
        pub fn new_with_builder(stream_builder: F) -> Self {
            Self {
                tcp_result: Ok((
                    "127.0.0.1:12345".parse().unwrap(),
                    "192.0.2.1:80".parse().unwrap(),
                )),
                udp_result: Ok("127.0.0.1:12346".parse().unwrap()),
                stream_builder,
            }
        }

        pub fn with_tcp_error(mut self, error: String) -> Self {
            self.tcp_result = Err(error);
            self
        }
    }

    #[async_trait]
    impl<F> SocketOps for MockSocketOps<F>
    where
        F: Fn() -> Mock + Send + Sync + Clone,
    {
        async fn resolve(&self, _host: &str) -> Result<Vec<IpAddr>> {
            Ok(vec!["192.0.2.1".parse().unwrap()])
        }

        async fn tcp_listen(&self, _local: SocketAddr) -> Result<Box<dyn TcpListener>> {
            Ok(Box::new(MockTcpListener))
        }

        async fn tcp_connect(
            &self,
            _remote: SocketAddr,
            _bind: Option<IpAddr>,
        ) -> Result<(Box<dyn IOStream>, SocketAddr, SocketAddr)> {
            match &self.tcp_result {
                Ok((local, peer)) => {
                    let mock_stream = (self.stream_builder)();
                    Ok((Box::new(mock_stream), *local, *peer))
                }
                Err(e) => Err(anyhow::anyhow!(e.clone())),
            }
        }

        async fn udp_bind(&self, _local: SocketAddr) -> Result<(UdpSocket, SocketAddr)> {
            match &self.udp_result {
                Ok(local_addr) => {
                    // Create a mock UDP socket bound to unspecified address
                    let socket = UdpSocket::bind("127.0.0.1:0")
                        .await
                        .map_err(|e| anyhow!("Mock UDP bind failed: {}", e))?;
                    Ok((socket, *local_addr))
                }
                Err(e) => Err(anyhow::anyhow!(e.clone())),
            }
        }

        async fn tls_handshake_client(
            &self,
            stream: Box<dyn IOStream>,
            _server_name: &str,
            _tls_config: &TlsClientConfig,
        ) -> Result<Box<dyn IOStream>> {
            Ok(stream)
        }

        async fn tls_handshake_server(
            &self,
            stream: Box<dyn IOStream>,
            _tls_config: &TlsServerConfig,
        ) -> Result<(Box<dyn IOStream>, Option<String>)> {
            // For mock, return stream with no ALPN (simulates cleartext)
            Ok((stream, None))
        }

        async fn set_keepalive(&self, _stream: &dyn IOStream, _enable: bool) -> Result<()> {
            // Mock implementation - just succeed
            Ok(())
        }

        async fn set_fwmark(&self, _stream: &dyn IOStream, _mark: Option<u32>) -> Result<()> {
            // Mock implementation - just succeed
            Ok(())
        }
    }
}
