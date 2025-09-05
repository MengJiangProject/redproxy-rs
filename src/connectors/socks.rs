use std::{
    ops::{Deref, DerefMut},
    sync::Arc,
};

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tracing::{trace, warn};

use crate::{
    common::{
        into_unspecified,
        socket_ops::{RealSocketOps, SocketOps},
        socks::{
            PasswordAuth, SOCKS_CMD_BIND, SOCKS_CMD_CONNECT, SOCKS_CMD_UDP_ASSOCIATE, SOCKS_REPLY_OK, SocksRequest,
            SocksResponse, frames::setup_udp_session,
        },
        tls::TlsClientConfig,
    },
    context::{ContextRef, ContextRefOps, ContextState, Feature, make_buffered_stream},
};

use super::ConnectorRef;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SocksConnectorConfig {
    name: String,
    server: String,
    port: u16,
    #[serde(default = "default_socks_version")]
    version: u8,
    auth: Option<SocksAuthData>,
    tls: Option<TlsClientConfig>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SocksConnector<S = RealSocketOps>
where
    S: SocketOps,
{
    #[serde(flatten)]
    config: SocksConnectorConfig,
    #[serde(skip)]
    socket_ops: Arc<S>,
}

impl<S: SocketOps> Deref for SocksConnector<S> {
    type Target = SocksConnectorConfig;
    fn deref(&self) -> &Self::Target {
        &self.config
    }
}

impl<S: SocketOps> DerefMut for SocksConnector<S> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.config
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SocksAuthData {
    username: String,
    password: String,
}

fn default_socks_version() -> u8 {
    5
}

// Production constructor (zero-cost)
impl SocksConnector<RealSocketOps> {
    pub fn new(config: SocksConnectorConfig) -> Self {
        Self {
            config,
            socket_ops: Arc::new(RealSocketOps),
        }
    }
}

// Generic constructor for testing
#[cfg(test)]
impl<S: SocketOps> SocksConnector<S> {
    pub fn with_socket_ops(config: SocksConnectorConfig, socket_ops: Arc<S>) -> Self {
        Self { config, socket_ops }
    }
}

pub fn from_value(value: &serde_yaml_ng::Value) -> Result<ConnectorRef> {
    let config: SocksConnectorConfig =
        serde_yaml_ng::from_value(value.clone()).context("parse socks connector config")?;
    let ret = SocksConnector::new(config);
    Ok(Box::new(ret))
}

#[async_trait]
impl<S: SocketOps + Send + Sync + 'static> super::Connector for SocksConnector<S> {
    fn name(&self) -> &str {
        self.name.as_str()
    }

    fn features(&self) -> &[Feature] {
        if self.version == 5 {
            &[Feature::TcpForward, Feature::UdpForward, Feature::UdpBind, Feature::TcpBind]
        } else {
            // SOCKS4 supports CONNECT and BIND, but not UDP
            &[Feature::TcpForward, Feature::TcpBind]
        }
    }

    async fn init(&mut self) -> Result<()> {
        if let Some(Err(e)) = self.tls.as_mut().map(TlsClientConfig::init) {
            return Err(e);
        }
        if self.version != 4 && self.version != 5 {
            bail!("illegal socks version {}", self.version);
        }
        Ok(())
    }

    async fn connect(self: Arc<Self>, ctx: ContextRef) -> Result<()> {
        trace!(
            "{} connecting to server {}:{}",
            self.name, self.server, self.port
        );

        let addrs = self.socket_ops.resolve(&self.server).await?;
        let server_addr = addrs
            .first()
            .ok_or_else(|| anyhow::anyhow!("no address found for {}", self.server))?;
        let server_addr = std::net::SocketAddr::new(*server_addr, self.port);

        let (mut server_stream, local, remote) = self
            .socket_ops
            .tcp_connect(server_addr, None)
            .await
            .context("TCP connection failed")?;

        if let Some(tls_config) = &self.tls {
            server_stream = self
                .socket_ops
                .tls_handshake_client(server_stream, &self.server, tls_config)
                .await
                .context("TLS handshake failed")?;
        }

        self.socket_ops
            .set_keepalive(server_stream.as_ref(), true)
            .await?;
        let mut server = make_buffered_stream(server_stream);
        let feature = ctx.read().await.feature();
        let cmd = match feature {
            Feature::UdpBind | Feature::UdpForward => SOCKS_CMD_UDP_ASSOCIATE,
            Feature::TcpForward => SOCKS_CMD_CONNECT,
            Feature::TcpBind => SOCKS_CMD_BIND,
            //_ => bail!("unknown supported feature: {:?}", feature),
        };
        let auth = self
            .auth
            .to_owned()
            .map(|auth| (auth.username, auth.password));
        let req = SocksRequest {
            version: self.version,
            cmd,
            target: ctx.read().await.target(),
            auth,
        };
        req.write_to(&mut server, PasswordAuth::optional()).await?;
        let resp = SocksResponse::read_from(&mut server).await?;
        if resp.cmd != SOCKS_REPLY_OK {
            bail!("upstream server failure: {:?}", resp.cmd);
        }
        ctx.write()
            .await
            .set_server_stream(server)
            .set_local_addr(local)
            .set_server_addr(remote);
        if feature == Feature::UdpBind || feature == Feature::UdpForward {
            let mut udp_remote = resp
                .target
                .as_socket_addr()
                .ok_or_else(|| anyhow::anyhow!("bad bind address"))?;
            if udp_remote.ip().is_unspecified() {
                udp_remote = std::net::SocketAddr::new(remote.ip(), udp_remote.port());
            }
            let udp_local = into_unspecified(remote);
            let (_, frames) = setup_udp_session(udp_local, Some(udp_remote))
                .await
                .context("setup_udp_session")?;
            ctx.write().await.set_server_frames(frames);
        } else if feature == Feature::TcpBind {
            let mut bind_addr = resp
                .target
                .as_socket_addr()
                .ok_or_else(|| anyhow::anyhow!("bad bind address from SOCKS server"))?;
            if bind_addr.ip().is_unspecified() {
                bind_addr = std::net::SocketAddr::new(remote.ip(), bind_addr.port());
            }
            // Set state to BindWaiting - SOCKS BIND needs to wait for second response
            ctx.write().await.set_state(ContextState::BindWaiting);
            // Notify that BIND is ready - the server stream is already set for SOCKS protocol
            ctx.on_bind_listen(bind_addr).await;
            
            // Set up receiver to wait for second SOCKS response  
            let (sender, receiver) = tokio::sync::oneshot::channel::<()>();
            ctx.write().await.set_bind_receiver(receiver);
            
            // Spawn task to read second SOCKS response
            tokio::spawn(async move {
                // Take the server stream temporarily to read the second response
                let mut server_stream = ctx.write().await.take_server_stream().expect("server stream should be set");
                
                match SocksResponse::read_from(&mut server_stream).await {
                    Ok(resp2) => {
                        if resp2.cmd == SOCKS_REPLY_OK {
                            // Extract peer address from second response
                            if let Some(peer_addr) = resp2.target.as_socket_addr() {
                                trace!("SOCKS BIND accepted connection from {}", peer_addr);
                                // Set the server stream back in context
                                ctx.write().await.set_server_stream(server_stream);
                                // Trigger the bind_accept callback
                                ctx.on_bind_accept(peer_addr).await;
                                // Signal that BIND is complete
                                let _ = sender.send(());
                            }
                        } else {
                            warn!("SOCKS BIND second response failed: {:?}", resp2.cmd);
                        }
                    }
                    Err(e) => {
                        warn!("Failed to read second SOCKS BIND response: {}", e);
                    }
                }
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        common::socket_ops::{
            SocketOps,
            test_utils::{MockSocketOps, StreamScript},
        },
        connectors::Connector,
        context::{ContextManager, Feature, TargetAddress},
    };
    use std::net::SocketAddr;
    use tokio_test::io::Mock;

    // SOCKS5 protocol stream builder for SocksConnector tests
    fn socks5_connect_stream(
        target_host: &str,
        target_port: u16,
        auth: Option<(&str, &str)>,
    ) -> Mock {
        let mut script = StreamScript::new();

        if let Some((username, password)) = auth {
            // SOCKS5 with username/password auth
            script = script
                .write(&[0x05, 0x02, 0x00, 0x02]) // Version 5, 2 methods, no-auth + username/password
                .read(&[0x05, 0x02]) // Version 5, username/password selected
                .write(&[0x01, username.len() as u8]) // Auth version, username length
                .write(username.as_bytes())
                .write(&[password.len() as u8])
                .write(password.as_bytes())
                .read(&[0x01, 0x00]); // Auth success
        } else {
            // SOCKS5 without auth
            script = script
                .write(&[0x05, 0x01, 0x00]) // Version 5, 1 method, no auth
                .read(&[0x05, 0x00]); // Version 5, no auth selected
        }

        // SOCKS5 CONNECT request and response
        script = script
            .write(&[0x05, 0x01, 0x00, 0x03, target_host.len() as u8]) // Version, CONNECT, reserved, domain name type, hostname length
            .write(target_host.as_bytes())
            .write(&[(target_port >> 8) as u8, (target_port & 0xFF) as u8]) // Port in network byte order
            .read(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50]); // Success response with dummy IP/port

        script.build()
    }

    // SOCKS4 protocol stream builder for SocksConnector tests
    fn socks4_connect_stream(target_ip: [u8; 4], target_port: u16) -> Mock {
        StreamScript::new()
            .write(&[0x04, 0x01]) // Version 4, CONNECT
            .write(&[(target_port >> 8) as u8, (target_port & 0xFF) as u8]) // Port
            .write(&target_ip) // IP address
            .write(&[0x00]) // Empty user ID
            .read(&[0x00, 0x5a, 0x00, 0x50, 127, 0, 0, 1]) // Success response (VN=0, CD=90 for success)
            .build()
    }

    fn create_test_connector<S: SocketOps>(
        server: String,
        port: u16,
        version: u8,
        auth: Option<SocksAuthData>,
        tls: Option<TlsClientConfig>,
        socket_ops: Arc<S>,
    ) -> SocksConnector<S> {
        SocksConnector::with_socket_ops(
            SocksConnectorConfig {
                name: "test_socks".to_string(),
                server,
                port,
                version,
                auth,
                tls,
            },
            socket_ops,
        )
    }

    async fn create_test_context(target: TargetAddress, feature: Feature) -> ContextRef {
        let manager = Arc::new(ContextManager::default());
        let source = "127.0.0.1:1234".parse::<SocketAddr>().unwrap();
        let ctx = manager.create_context("test".to_string(), source).await;

        ctx.write().await.set_target(target).set_feature(feature);
        ctx
    }

    #[tokio::test]
    async fn test_socks_connector_basic_interface() {
        let mock_ops = Arc::new(MockSocketOps::new_with_builder(|| {
            socks5_connect_stream("httpbin.org", 80, None)
        }));
        let connector =
            create_test_connector("192.0.2.10".to_string(), 1080, 5, None, None, mock_ops);

        // Test basic interface
        assert_eq!(connector.name(), "test_socks");
        assert_eq!(
            connector.features(),
            &[Feature::TcpForward, Feature::UdpForward, Feature::UdpBind]
        );
        assert_eq!(connector.version, 5);

        // Test init
        let mut connector_copy = connector.clone();
        let result = connector_copy.init().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_socks5_connector_connection_success() {
        let mock_ops = Arc::new(MockSocketOps::new_with_builder(|| {
            socks5_connect_stream("httpbin.org", 80, None)
        }));
        let connector = Arc::new(create_test_connector(
            "192.0.2.10".to_string(),
            1080,
            5,
            None,
            None,
            mock_ops,
        ));

        let target = TargetAddress::DomainPort("httpbin.org".to_string(), 80);
        let ctx = create_test_context(target, Feature::TcpForward).await;

        // This should succeed with mock socket ops
        let result = connector.connect(ctx.clone()).await;
        assert!(result.is_ok());

        // Verify context was updated correctly with mock addresses
        let context_read = ctx.read().await;
        assert_eq!(context_read.local_addr().to_string(), "127.0.0.1:12345");
        assert_eq!(context_read.server_addr().to_string(), "192.0.2.1:80");
    }

    #[tokio::test]
    async fn test_socks4_connector_connection_success() {
        let mock_ops = Arc::new(MockSocketOps::new_with_builder(|| {
            socks4_connect_stream([127, 0, 0, 1], 80)
        }));
        let connector = Arc::new(create_test_connector(
            "192.0.2.11".to_string(),
            1080,
            4,
            None,
            None,
            mock_ops,
        ));

        // SOCKS4 only supports IP addresses, not domain names
        let target = TargetAddress::SocketAddr("127.0.0.1:80".parse().unwrap());
        let ctx = create_test_context(target, Feature::TcpForward).await;

        // This should succeed with mock socket ops
        let result = connector.connect(ctx.clone()).await;
        if let Err(e) = &result {
            println!("SOCKS4 connection error: {:?}", e);
        }
        assert!(result.is_ok());

        // Verify context was updated correctly with mock addresses
        let context_read = ctx.read().await;
        assert_eq!(context_read.local_addr().to_string(), "127.0.0.1:12345");
        assert_eq!(context_read.server_addr().to_string(), "192.0.2.1:80");
    }

    #[tokio::test]
    async fn test_socks_connector_connection_failure() {
        let mock_ops = Arc::new(
            MockSocketOps::new_with_builder(|| socks5_connect_stream("example.com", 80, None))
                .with_tcp_error("Connection refused".to_string()),
        );
        let connector = Arc::new(create_test_connector(
            "192.0.2.12".to_string(),
            1080,
            5,
            None,
            None,
            mock_ops,
        ));

        let target = TargetAddress::DomainPort("example.com".to_string(), 80);
        let ctx = create_test_context(target, Feature::TcpForward).await;

        // This should fail with mock error
        let result = connector.connect(ctx).await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("TCP connection failed")
        );
    }

    #[tokio::test]
    async fn test_socks5_connector_with_auth() {
        let auth = SocksAuthData {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        };

        let mock_ops = Arc::new(MockSocketOps::new_with_builder(|| {
            socks5_connect_stream("httpbin.org", 80, Some(("testuser", "testpass")))
        }));
        let connector = Arc::new(create_test_connector(
            "192.0.2.13".to_string(),
            1080,
            5,
            Some(auth.clone()),
            None,
            mock_ops,
        ));

        // Test that auth configuration is preserved
        assert!(connector.auth.is_some());
        assert_eq!(connector.auth.as_ref().unwrap().username, "testuser");
        assert_eq!(connector.auth.as_ref().unwrap().password, "testpass");

        // Test connection with auth
        let target = TargetAddress::DomainPort("httpbin.org".to_string(), 80);
        let ctx = create_test_context(target, Feature::TcpForward).await;

        let result = connector.connect(ctx.clone()).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_socks_connector_features() {
        let mock_ops = Arc::new(MockSocketOps::new_with_builder(|| {
            socks5_connect_stream("httpbin.org", 80, None)
        }));
        let connector =
            create_test_connector("192.0.2.14".to_string(), 1080, 5, None, None, mock_ops);

        // Test supported features
        let features = connector.features();
        assert!(features.contains(&Feature::TcpForward));
        assert!(features.contains(&Feature::UdpForward));
        assert!(features.contains(&Feature::UdpBind));
    }

    #[tokio::test]
    async fn test_default_socks_version() {
        assert_eq!(default_socks_version(), 5);
    }
}
