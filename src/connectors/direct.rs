use std::{
    net::{IpAddr, SocketAddr},
    ops::{Deref, DerefMut},
    sync::Arc,
};

use anyhow::{Context, Error, Result};
use async_trait::async_trait;
use chashmap_async::CHashMap;
use serde::{Deserialize, Serialize};
use tracing::{debug, trace};

use super::ConnectorRef;
use crate::{
    common::{
        dns::{AddressFamily, DnsConfig},
        frames::{Frame, FrameIO, FrameReader, FrameWriter},
        into_unspecified,
        socket_ops::{RealSocketOps, SocketOps},
    },
    context::{ContextRef, ContextRefOps, ContextState, Feature, TargetAddress, make_buffered_stream},
};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DirectConnectorConfig {
    name: String,
    bind: Option<IpAddr>,
    #[serde(default)]
    dns: Arc<DnsConfig>,
    fwmark: Option<u32>,
    #[serde(default = "default_keepalive")]
    keepalive: bool,
    #[serde(default)]
    override_bind_address: Option<IpAddr>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DirectConnector<S = RealSocketOps>
where
    S: SocketOps,
{
    #[serde(flatten)]
    config: DirectConnectorConfig,
    #[serde(skip)]
    udp_binds: Arc<CHashMap<String, SocketAddr>>,
    #[serde(skip)]
    socket_ops: Arc<S>,
}

impl<S: SocketOps> Deref for DirectConnector<S> {
    type Target = DirectConnectorConfig;
    fn deref(&self) -> &Self::Target {
        &self.config
    }
}

impl<S: SocketOps> DerefMut for DirectConnector<S> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.config
    }
}

fn default_keepalive() -> bool {
    true
}

// Production constructor (zero-cost)
impl DirectConnector<RealSocketOps> {
    pub fn new(config: DirectConnectorConfig) -> Self {
        Self {
            config,
            udp_binds: Arc::new(CHashMap::new()),
            socket_ops: Arc::new(RealSocketOps),
        }
    }
}

// Generic constructor for testing
#[cfg(test)]
impl<S: SocketOps> DirectConnector<S> {
    pub fn with_socket_ops(config: DirectConnectorConfig, socket_ops: Arc<S>) -> Self {
        Self {
            config,
            udp_binds: Arc::new(CHashMap::new()),
            socket_ops,
        }
    }
}

pub fn from_value(value: &serde_yaml_ng::Value) -> Result<ConnectorRef> {
    let config: DirectConnectorConfig =
        serde_yaml_ng::from_value(value.clone()).context("parse direct connector config")?;
    let ret = DirectConnector::new(config);
    Ok(Box::new(ret))
}

#[async_trait]
impl<S: SocketOps + Send + Sync + 'static> super::Connector for DirectConnector<S> {
    async fn init(&mut self) -> Result<()> {
        let bind = self.bind;
        let dns = Arc::get_mut(&mut self.dns).unwrap();
        dns.init()?;
        if let Some(addr) = bind {
            debug!("bind address set, overriding dns family");
            if addr.is_ipv4() {
                dns.family = AddressFamily::V4Only;
            } else {
                dns.family = AddressFamily::V6Only;
            }
        }
        Ok(())
    }

    fn name(&self) -> &str {
        self.name.as_str()
    }

    async fn shutdown(&self) -> Result<()> {
        tracing::debug!("{}: shutting down connector", self.name);
        self.udp_binds.clear().await;
        Ok(())
    }

    fn features(&self) -> &[Feature] {
        &[Feature::TcpForward, Feature::UdpForward, Feature::UdpBind, Feature::TcpBind]
    }

    async fn connect(self: Arc<Self>, ctx: ContextRef) -> Result<(), Error> {
        let target = ctx.read().await.target();
        trace!("connecting to {}", target);
        let remote = match &target {
            TargetAddress::SocketAddr(addr) => *addr,
            TargetAddress::DomainPort(domain, port) => {
                self.dns.lookup_host(domain.as_str(), *port).await?
            }
            _ => unreachable!(),
        };

        trace!("target resolved to {}", remote);

        let feature = ctx.read().await.feature();
        match feature {
            Feature::TcpForward => {
                let (server, local, remote_addr) =
                    self.socket_ops.tcp_connect(remote, self.bind).await?;

                self.socket_ops
                    .set_keepalive(server.as_ref(), self.keepalive)
                    .await?;
                self.socket_ops
                    .set_fwmark(server.as_ref(), self.fwmark)
                    .await?;

                ctx.write()
                    .await
                    .set_server_stream(make_buffered_stream(server))
                    .set_local_addr(local)
                    .set_server_addr(remote_addr);
                trace!("connected to {:?}", target);
            }
            Feature::UdpForward | Feature::UdpBind => {
                let local = if let Some(bind) = self.bind {
                    SocketAddr::new(bind, 0)
                } else {
                    into_unspecified(remote)
                };
                let source = ctx
                    .read()
                    .await
                    .extra("udp-bind-source")
                    .unwrap_or("")
                    .to_owned();
                let local = if source.is_empty() {
                    local
                } else {
                    self.udp_binds
                        .get(&source)
                        .await
                        .map(|x| x.to_owned())
                        .unwrap_or(local)
                };

                let (socket, local_addr) = self.socket_ops.udp_bind(local).await?;
                let frames = setup_session(socket, remote, self.dns.clone());
                let remote_addr = remote;

                ctx.write()
                    .await
                    .set_server_frames(frames)
                    .set_local_addr(local_addr)
                    .set_server_addr(remote_addr)
                    .set_extra("udp-bind-address", local_addr.to_string());

                if !source.is_empty() {
                    self.udp_binds.insert(source, local_addr).await;
                }
                trace!("connected to {:?}", target);
            }
            Feature::TcpBind => {
                // Create TCP listener on the requested address
                let listener = self.socket_ops.tcp_listen(remote).await?;
                let local_addr = listener.local_addr().await?;
                
                // Apply NAT address override if configured
                let response_addr = if let Some(override_ip) = self.override_bind_address {
                    SocketAddr::new(override_ip, local_addr.port())
                } else {
                    local_addr
                };
                
                // Create oneshot channel for the bind operation
                let (sender, receiver) = tokio::sync::oneshot::channel::<()>();
                
                // Set up the BIND receiver in context and mark as waiting for bind
                ctx.write().await
                    .set_bind_receiver(receiver)
                    .set_state(ContextState::BindWaiting);
                
                // Trigger the bind_listen callback
                ctx.on_bind_listen(response_addr).await;
                
                // Spawn task to wait for connection
                let ctx_clone = ctx.clone();
                let connector_name = self.name.clone();
                tokio::spawn(async move {
                    match listener.accept().await {
                        Ok((stream, peer_addr)) => {
                            debug!("{}: BIND accepted connection from {}", connector_name, peer_addr);
                            // Set the server stream in context
                            ctx_clone.write().await.set_server_stream(make_buffered_stream(stream));
                            // Trigger the bind_accept callback
                            ctx_clone.on_bind_accept(peer_addr).await;
                            // Signal that BIND is complete
                            let _ = sender.send(());
                        }
                        Err(e) => {
                            debug!("{}: BIND accept failed: {}", connector_name, e);
                        }
                    }
                });
                
                trace!("BIND listening on {:?}", response_addr);
            }
            //x => bail!("not supported feature {:?}", x),
        }
        Ok(())
    }
}

use std::io::Result as IoResult;
use tokio::net::UdpSocket;

fn setup_session(socket: UdpSocket, target: SocketAddr, dns: Arc<DnsConfig>) -> FrameIO {
    let socket = Arc::new(socket);
    let frames = DirectFrames {
        socket,
        target,
        dns,
    };
    (Box::new(frames.clone()), Box::new(frames))
}

#[derive(Clone)]
struct DirectFrames {
    socket: Arc<UdpSocket>,
    target: SocketAddr,
    dns: Arc<DnsConfig>,
}

#[async_trait]
impl FrameReader for DirectFrames {
    async fn read(&mut self) -> IoResult<Option<Frame>> {
        let mut frame = Frame::new();
        let (_, _source) = frame.recv_from(&self.socket).await?;
        tracing::trace!("read udp frame: {:?}", frame);
        return Ok(Some(frame));
    }
}

#[async_trait]
impl FrameWriter for DirectFrames {
    async fn write(&mut self, frame: Frame) -> IoResult<usize> {
        let target = if self.target.ip().is_unspecified() {
            match frame.addr.as_ref() {
                Some(TargetAddress::SocketAddr(addr)) => *addr,
                Some(TargetAddress::DomainPort(domain, port)) => self
                    .dns
                    .lookup_host(domain.as_str(), *port)
                    .await
                    .map_err(|x| {
                        tracing::warn!("dns error: {}", x);
                        std::io::Error::new(std::io::ErrorKind::InvalidInput, "dns error")
                    })?,
                _ => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "bad target",
                    ));
                }
            }
        } else {
            self.target
        };
        tracing::trace!("send udp frame: {:?}", frame);
        self.socket.send_to(frame.body(), target).await?;
        Ok(frame.len())
    }
    async fn shutdown(&mut self) -> IoResult<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        common::socket_ops::{SocketOps, test_utils::MockSocketOps},
        connectors::Connector,
        context::{ContextManager, Feature, TargetAddress},
    };
    use std::net::{Ipv4Addr, SocketAddr};

    fn create_test_connector<S: SocketOps>(socket_ops: Arc<S>) -> DirectConnector<S> {
        DirectConnector::with_socket_ops(
            DirectConnectorConfig {
                name: "test".to_string(),
                bind: None,
                dns: Arc::new(DnsConfig::default()),
                fwmark: None,
                keepalive: true,
                override_bind_address: None,
            },
            socket_ops,
        )
    }

    async fn create_test_context(target: TargetAddress, feature: Feature) -> ContextRef {
        let manager = Arc::new(ContextManager::default());
        let source = "127.0.0.1:1234".parse::<SocketAddr>().unwrap();
        let ctx = manager
            .create_context("test-listener".to_string(), source)
            .await;

        ctx.write().await.set_target(target).set_feature(feature);
        ctx
    }

    #[tokio::test]
    async fn test_tcp_connect_success() {
        let mock_ops = Arc::new(MockSocketOps::new());
        let mut connector = create_test_connector(mock_ops);
        connector.init().await.unwrap();

        let connector = Arc::new(connector);
        let target = TargetAddress::SocketAddr("192.0.2.1:80".parse().unwrap());
        let ctx = create_test_context(target, Feature::TcpForward).await;

        // This should succeed and properly set context
        let result = connector.connect(ctx.clone()).await;
        assert!(result.is_ok());

        // Verify context was updated correctly
        let context_read = ctx.read().await;
        // Check that server stream was set by verifying we can't take it twice
        assert!(context_read.props().server_addr != ([0, 0, 0, 0], 0).into());
        assert_eq!(context_read.local_addr().to_string(), "127.0.0.1:12345");
        assert_eq!(context_read.server_addr().to_string(), "192.0.2.1:80");
    }

    #[tokio::test]
    async fn test_tcp_connect_failure() {
        let mock_ops =
            Arc::new(MockSocketOps::new().with_tcp_error("Connection refused".to_string()));
        let mut connector = create_test_connector(mock_ops);
        connector.init().await.unwrap();

        let connector = Arc::new(connector);
        let target = TargetAddress::SocketAddr("192.0.2.1:80".parse().unwrap());
        let ctx = create_test_context(target, Feature::TcpForward).await;

        // This should fail with our mocked error
        let result = connector.connect(ctx).await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Connection refused")
        );
    }

    #[tokio::test]
    async fn test_bind_address_handling() {
        let mock_ops = Arc::new(MockSocketOps::new());
        let mut connector = DirectConnector::with_socket_ops(
            DirectConnectorConfig {
                name: "test".to_string(),
                bind: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))),
                dns: Arc::new(DnsConfig::default()),
                fwmark: None,
                keepalive: true,
                override_bind_address: None,
            },
            mock_ops,
        );

        connector.init().await.unwrap();

        let connector = Arc::new(connector);
        let target = TargetAddress::SocketAddr("192.0.2.1:80".parse().unwrap());
        let ctx = create_test_context(target, Feature::TcpForward).await;

        // Should successfully use the bind address (passed to mock)
        let result = connector.connect(ctx).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_basic_connector_interface() {
        let mock_ops = Arc::new(MockSocketOps::new());
        let connector = create_test_connector(mock_ops);

        // Test basic connector interface
        assert_eq!(connector.name(), "test");
        assert_eq!(connector.features().len(), 3);
        assert!(connector.has_feature(Feature::TcpForward));
        assert!(connector.has_feature(Feature::UdpForward));
        assert!(connector.has_feature(Feature::UdpBind));
    }
}
