use std::{
    io::{ErrorKind, Result as IoResult},
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use async_trait::async_trait;
use chashmap_async::CHashMap;
use easy_error::{bail, Error, ResultExt, err_msg};
use serde::{Deserialize, Serialize};
use tracing::{debug, trace};

use super::ConnectorRef;
use crate::{
    common::{
        dns::{AddressFamily, DnsConfig},
        frames::{Frame, FrameIO, FrameReader, FrameWriter},
        into_unspecified,
    },
    context::{ContextRef, Feature, TargetAddress, IOStream},
    GlobalState,
};

use crate::common::dialers::{
    TcpDialer, TokioTcpDialer, TcpConnectionInfo,
    SimpleDnsResolver, ArcDnsConfigResolver,
    RawUdpSocketLike, UdpSocketFactory, TokioUdpSocketFactory,
};


#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectConnector {
    name: String,
    bind: Option<IpAddr>,
    #[serde(default)]
    dns_config: Arc<DnsConfig>,
    fwmark: Option<u32>,
    #[serde(default = "default_keepalive")]
    keepalive: bool,
    #[serde(skip)]
    udp_binds: Arc<CHashMap<String, SocketAddr>>,
    #[serde(skip)]
    tcp_dialer: Arc<dyn TcpDialer>,
    #[serde(skip)]
    dns_resolver: Arc<dyn SimpleDnsResolver>,
    #[serde(skip)]
    udp_socket_factory: Arc<dyn UdpSocketFactory>,
}


fn default_keepalive() -> bool {
    true
}

impl DirectConnector {
    #[cfg(test)]
    pub fn new_with_mocks(
        name: String,
        bind: Option<IpAddr>,
        dns_config: Arc<DnsConfig>,
        fwmark: Option<u32>,
        keepalive: bool,
        tcp_dialer: Arc<dyn TcpDialer>,
        dns_resolver: Arc<dyn SimpleDnsResolver>,
        udp_socket_factory: Arc<dyn UdpSocketFactory>,
    ) -> Self {
        Self {
            name,
            bind,
            dns_config,
            fwmark,
            keepalive,
            udp_binds: Arc::new(CHashMap::new()),
            tcp_dialer,
            dns_resolver,
            udp_socket_factory,
        }
    }
}

pub fn from_value(value: &serde_yaml_ng::Value) -> Result<ConnectorRef, Error> {
    let mut temp_connector: DirectConnector = serde_yaml_ng::from_value(value.clone())
        .map_err(|e| err_msg(format!("Failed to parse DirectConnector config: {}, cause: {:?}", e, e.cause())))?;

    temp_connector.tcp_dialer = Arc::new(TokioTcpDialer);
    temp_connector.dns_resolver = Arc::new(ArcDnsConfigResolver(temp_connector.dns_config.clone()));
    temp_connector.udp_socket_factory = Arc::new(TokioUdpSocketFactory);

    Ok(Box::new(temp_connector))
}

#[async_trait]
impl super::Connector for DirectConnector {
    async fn init(&mut self) -> Result<(), Error> {
        let dns_cfg_mut = Arc::get_mut(&mut self.dns_config)
            .ok_or_else(|| err_msg("Failed to get mutable DnsConfig for init. It might be shared elsewhere."))?;

        dns_cfg_mut.init()?;
        if let Some(addr) = self.bind {
            debug!("bind address set, overriding dns family for DirectConnector {}", self.name);
            if addr.is_ipv4() {
                dns_cfg_mut.family = AddressFamily::V4Only;
            } else {
                dns_cfg_mut.family = AddressFamily::V6Only;
            }
        }
        Ok(())
    }

    fn name(&self) -> &str {
        self.name.as_str()
    }

    fn features(&self) -> &[Feature] {
        &[Feature::TcpForward, Feature::UdpForward, Feature::UdpBind]
    }

    async fn connect(
        self: Arc<Self>,
        _state: Arc<GlobalState>,
        ctx: ContextRef,
    ) -> Result<(), Error> {
        let target = ctx.read().await.props().target.clone(); // Use props()
        trace!("connecting to {}", target);
        let remote_addr = match &target {
            TargetAddress::SocketAddr(addr) => *addr,
            TargetAddress::DomainPort(domain, port) => {
                self.dns_resolver.lookup_host(domain.as_str(), *port).await?
            }
            _ => unreachable!(),
        };

        trace!("target resolved to {}", remote_addr);

        let feature = ctx.read().await.props().request_feature; // Use props()
        match feature {
            Feature::TcpForward => {
                let conn_info = self.tcp_dialer.connect(remote_addr, self.bind, self.keepalive, self.fwmark).await?;
                let mut ctx_write = ctx.write().await;
                ctx_write.set_server_stream(conn_info.stream);
                ctx_write.set_local_addr(conn_info.local_addr);
                ctx_write.set_server_addr(conn_info.remote_addr);
                trace!("connected to {:?} via TCP", target);
            }
            Feature::UdpForward | Feature::UdpBind => {
                let local_udp_bind = if let Some(bind_ip) = self.bind {
                    SocketAddr::new(bind_ip, 0)
                } else {
                    into_unspecified(remote_addr)
                };
                let source_key_for_udp_bind = ctx
                    .read()
                    .await
                    .props() // Use props()
                    .extra.get("udp-bind-source").cloned().unwrap_or_default();

                let actual_udp_bind_addr = if source_key_for_udp_bind.is_empty() {
                    local_udp_bind
                } else {
                    self.udp_binds
                        .get(&source_key_for_udp_bind)
                        .await
                        .map(|x| x.to_owned())
                        .unwrap_or(local_udp_bind)
                };

                let raw_udp_socket = self.udp_socket_factory.create_raw_udp_socket(
                    actual_udp_bind_addr,
                    Some(remote_addr),
                    self.fwmark,
                ).await.context("create raw udp socket")?;

                let actual_local_addr = raw_udp_socket.local_addr_raw().context("local_addr_raw udp")?;

                let mut ctx_write = ctx.write().await;
                ctx_write.set_server_frames(setup_session(raw_udp_socket, remote_addr, self.dns_config.clone()));
                ctx_write.set_local_addr(actual_local_addr);
                ctx_write.set_server_addr(remote_addr);
                ctx_write.set_extra("udp-bind-address", actual_local_addr.to_string());

                if !source_key_for_udp_bind.is_empty() {
                    self.udp_binds.insert(source_key_for_udp_bind, actual_local_addr).await;
                }
                trace!("connected to {:?} via UDP", target);
            }
            x => bail!("not supported feature {:?}", x),
        }
        Ok(())
    }
}

// DirectFrames is no longer generic over S. It takes Arc<dyn RawUdpSocketLike>.
fn setup_session(
    socket: Arc<dyn RawUdpSocketLike>, // Changed to Arc<dyn RawUdpSocketLike>
    target: SocketAddr,
    dns: Arc<DnsConfig>
) -> FrameIO {
    let frames = DirectFrames {
        socket,
        target,
        dns,
    };
    (Box::new(frames.clone()), Box::new(frames))
}

#[derive(Clone)]
struct DirectFrames { // Removed generic S
    socket: Arc<dyn RawUdpSocketLike>, // Changed to Arc<dyn RawUdpSocketLike>
    target: SocketAddr,
    dns: Arc<DnsConfig>,
}

#[async_trait]
impl FrameReader for DirectFrames { // Removed generic S
    async fn read(&mut self) -> IoResult<Option<Frame>> {
        let mut frame_body_buffer = vec![0u8; 65535];
        let (len, source_addr) = self.socket.recv_from_raw(&mut frame_body_buffer).await?;

        let mut frame = Frame::new();
        frame.body.extend_from_slice(&frame_body_buffer[..len]); // Use extend_from_slice for BytesMut
        frame.addr = Some(TargetAddress::SocketAddr(source_addr));
        tracing::trace!("read udp frame: {:?} from {}", frame, source_addr);
        Ok(Some(frame))
    }
}

#[async_trait]
impl FrameWriter for DirectFrames { // Removed generic S
    async fn write(&mut self, frame: Frame) -> IoResult<usize> {
        let actual_target = if self.target.ip().is_unspecified() {
            match frame.addr.as_ref() {
                Some(TargetAddress::SocketAddr(addr)) => *addr,
                Some(TargetAddress::DomainPort(domain, port)) => {
                    self.dns.lookup_host(domain.as_str(), *port).await
                        .map_err(|x| {
                            tracing::warn!("dns error: {}", x);
                            std::io::Error::new(ErrorKind::InvalidInput, "dns error")
                        })?
                }
                _ => return Err(std::io::Error::new(ErrorKind::InvalidInput, "bad target for DirectFrames write")),
            }
        } else {
            self.target
        };
        tracing::trace!("send udp frame: {:?} to {}", frame, actual_target);
        self.socket.send_to_raw(frame.body(), actual_target).await?;
        Ok(frame.len())
    }
    async fn shutdown(&mut self) -> IoResult<()> {
        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    // UdpSocketFactory is already imported by main code block via common::dialers
    // use crate::common::dialers::{UdpSocketFactory};
    use crate::common::mocks::connector_mocks::{
        MockTcpDialer, MockSimpleDnsResolver, MockUdpSocketFactory, MockRawUdpSocket, MockIoStream
    };
    use crate::config::context::Contexts as AppContexts;
    use std::sync::atomic::AtomicU32;
    use std::net::Ipv4Addr;
    use crate::connectors::Connector; // Import Connector trait for tests

    fn create_mock_global_state_for_connectors() -> Arc<GlobalState> {
        Arc::new(GlobalState {
            contexts: Arc::new(AppContexts::new(1024, Arc::new(AtomicU32::new(0)))),
            rules: Default::default(),
            dns_resolver: Arc::new(crate::common::dns::create_resolver(None, false).unwrap()),
            // The following fields are based on the *actual* GlobalState struct, not the outdated one.
            // Assuming GlobalState has these fields or similar.
            // If not, these will also cause errors.
            // Based on previous errors, GlobalState has: connectors, metrics, io_params
            // This mock GlobalState might need adjustment based on current definition if tests fail here.
            // For now, let's assume it's minimal and only `contexts` is crucial for these tests.
            connectors: Default::default(), // Added
            metrics: Default::default(),    // Added
            io_params: Default::default(),  // Added
        })
    }

    #[tokio::test]
    async fn test_direct_connector_connect_tcp_domain() {
        let mock_tcp_dialer = Arc::new(MockTcpDialer::new());
        let mock_dns_resolver = Arc::new(MockSimpleDnsResolver::new());
        let mock_udp_factory = Arc::new(MockUdpSocketFactory::new());

        let domain = "example.com";
        let port = 80u16;
        let resolved_addr: SocketAddr = "93.184.216.34:80".parse().unwrap();
        let local_addr: SocketAddr = "192.168.1.100:12345".parse().unwrap();

        mock_dns_resolver.add_response(Ok(resolved_addr));

        let mock_server_raw_stream = MockIoStream::new("server_stream_tcp_domain_raw");
        mock_tcp_dialer.add_response(Ok(TcpConnectionInfo {
            stream: crate::context::make_buffered_stream(Box::new(mock_server_raw_stream)),
            local_addr,
            remote_addr: resolved_addr,
        }));

        let connector = DirectConnector::new_with_mocks(
            "test_direct_tcp".to_string(),
            None,
            Arc::new(DnsConfig::default()),
            None,
            true,
            mock_tcp_dialer.clone(),
            mock_dns_resolver.clone(),
            mock_udp_factory.clone(),
        );
        let connector_arc: Arc<dyn Connector> = Arc::new(connector); // Use Arc<dyn Connector>

        let mock_state = create_mock_global_state_for_connectors();
        let ctx = mock_state.contexts.create_context("test_listener".to_string(), "1.2.3.4:5555".parse().unwrap()).await;
        ctx.write().await.set_target(TargetAddress::DomainPort(domain.to_string(), port));
        ctx.write().await.set_feature(Feature::TcpForward);


        let result = connector_arc.connect(mock_state.clone(), ctx.clone()).await;
        assert!(result.is_ok(), "DirectConnector connect failed: {:?}", result.err());

        let ctx_read = ctx.read().await;
        assert!(ctx_read.server_stream_is_some(), "Server stream not set"); // Use helper
        assert_eq!(ctx_read.props().local_addr, local_addr, "Local address mismatch");
        assert_eq!(ctx_read.props().server_addr, resolved_addr, "Server address mismatch");
    }

    #[tokio::test]
    async fn test_direct_connector_connect_udp_domain() {
        let mock_tcp_dialer = Arc::new(MockTcpDialer::new());
        let mock_dns_resolver = Arc::new(MockSimpleDnsResolver::new());
        let mock_udp_factory = Arc::new(MockUdpSocketFactory::new());

        let domain = "udpserver.example.com";
        let port = 1234u16;
        let resolved_addr: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let mock_udp_local_addr: SocketAddr = "192.168.1.101:54321".parse().unwrap();

        mock_dns_resolver.add_response(Ok(resolved_addr));

        let mock_raw_udp_socket = Arc::new(MockRawUdpSocket::new(mock_udp_local_addr));
        mock_udp_factory.add_response(Ok(mock_raw_udp_socket.clone()));

        let connector_config = DirectConnector::new_with_mocks(
            "test_direct_udp".to_string(),
            None,
            Arc::new(DnsConfig::default()),
            Some(123),
            true,
            mock_tcp_dialer.clone(),
            mock_dns_resolver.clone(),
            mock_udp_factory.clone(),
        );
        let connector_arc: Arc<dyn Connector> = Arc::new(connector_config); // Use Arc<dyn Connector>

        let mock_state = create_mock_global_state_for_connectors();
        let ctx = mock_state.contexts.create_context("test_listener_udp".to_string(), "1.2.3.4:1111".parse().unwrap()).await;
        ctx.write().await.set_target(TargetAddress::DomainPort(domain.to_string(), port));
        ctx.write().await.set_feature(Feature::UdpForward);

        let result = connector_arc.connect(mock_state.clone(), ctx.clone()).await;
        assert!(result.is_ok(), "DirectConnector connect for UDP failed: {:?}", result.err());

        let ctx_read = ctx.read().await;
        assert!(ctx_read.server_frames_is_some(), "Server frames not set for UDP"); // Use helper
        assert_eq!(ctx_read.props().local_addr, mock_udp_local_addr, "Local UDP address mismatch");
        assert_eq!(ctx_read.props().server_addr, resolved_addr, "Server UDP address mismatch");
    }
}
