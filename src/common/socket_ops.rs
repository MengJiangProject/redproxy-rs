use std::net::{IpAddr, SocketAddr};

use anyhow::{Context, Result};
use async_trait::async_trait;
use tokio::net::{TcpSocket, UdpSocket};

use crate::common::udp::udp_socket;

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

// Stream trait that works with both real and mock streams
pub trait Stream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync {
    fn as_any(&self) -> &dyn std::any::Any;
}

impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync + 'static> Stream for T {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

// Clean, low-level socket abstraction equivalent to Tokio socket library
#[async_trait]
pub trait SocketOps: Send + Sync {
    async fn tcp_connect(&self, remote: SocketAddr, bind: Option<IpAddr>) -> Result<(Box<dyn Stream>, SocketAddr, SocketAddr)>;
    async fn udp_bind(&self, local: SocketAddr) -> Result<(UdpSocket, SocketAddr)>;
    
    // Orthogonal methods for specific socket options
    async fn set_keepalive(&self, stream: &dyn Stream, enable: bool) -> Result<()>;
    async fn set_fwmark(&self, stream: &dyn Stream, mark: Option<u32>) -> Result<()>;
}

// Real implementation using actual Tokio sockets
pub struct RealSocketOps;

#[async_trait]
impl SocketOps for RealSocketOps {
    async fn tcp_connect(&self, remote: SocketAddr, bind: Option<IpAddr>) -> Result<(Box<dyn Stream>, SocketAddr, SocketAddr)> {
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
    
    async fn set_keepalive(&self, stream: &dyn Stream, enable: bool) -> Result<()> {
        if let Some(tcp_stream) = stream.as_any().downcast_ref::<tokio::net::TcpStream>() {
            if enable {
                set_keepalive(tcp_stream)?;
            }
        }
        Ok(())
    }
    
    async fn set_fwmark(&self, stream: &dyn Stream, mark: Option<u32>) -> Result<()> {
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

    // Mock SocketOps that behaves identically to RealSocketOps from connector's perspective
    pub struct MockSocketOps {
        pub tcp_result: Result<(SocketAddr, SocketAddr)>,
        pub udp_result: Result<SocketAddr>,
    }

    impl MockSocketOps {
        pub fn new() -> Self {
            Self {
                tcp_result: Ok((
                    "127.0.0.1:12345".parse().unwrap(),
                    "192.0.2.1:80".parse().unwrap(),
                )),
                udp_result: Ok("127.0.0.1:12346".parse().unwrap()),
            }
        }

        pub fn with_tcp_error(mut self, error: String) -> Self {
            self.tcp_result = Err(anyhow::anyhow!(error));
            self
        }
    }

    #[async_trait]
    impl SocketOps for MockSocketOps {
        async fn tcp_connect(&self, _remote: SocketAddr, _bind: Option<IpAddr>) -> Result<(Box<dyn Stream>, SocketAddr, SocketAddr)> {
            match &self.tcp_result {
                Ok((local, peer)) => {
                    // Create a mock stream using tokio-test - this is clean and safe
                    let mock_stream = Builder::new().build();
                    Ok((Box::new(mock_stream), *local, *peer))
                }
                Err(e) => Err(anyhow::anyhow!(e.to_string())),
            }
        }
        
        async fn udp_bind(&self, _local: SocketAddr) -> Result<(UdpSocket, SocketAddr)> {
            match &self.udp_result {
                Ok(local_addr) => {
                    // Create a mock UDP socket bound to unspecified address
                    let socket = UdpSocket::bind("127.0.0.1:0").await
                        .map_err(|e| anyhow::anyhow!("Mock UDP bind failed: {}", e))?;
                    Ok((socket, *local_addr))
                }
                Err(e) => Err(anyhow::anyhow!(e.to_string())),
            }
        }
        
        async fn set_keepalive(&self, _stream: &dyn Stream, _enable: bool) -> Result<()> {
            // Mock implementation - just succeed
            Ok(())
        }
        
        async fn set_fwmark(&self, _stream: &dyn Stream, _mark: Option<u32>) -> Result<()> {
            // Mock implementation - just succeed
            Ok(())
        }
    }

}