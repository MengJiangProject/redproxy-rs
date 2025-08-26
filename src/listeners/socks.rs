use anyhow::{Context as AnyhowContext, Error, Result, anyhow};
use async_trait::async_trait;
use futures::TryFutureExt;
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tokio::sync::mpsc::Sender;
use tracing::{debug, error, info, warn};

use crate::{
    common::{
        auth::AuthData,
        into_unspecified,
        socket_ops::{TcpListener, RealSocketOps, SocketOps},
        socks::{
            PasswordAuth, SOCKS_CMD_BIND, SOCKS_CMD_CONNECT, SOCKS_CMD_UDP_ASSOCIATE,
            SOCKS_REPLY_GENERAL_FAILURE, SOCKS_REPLY_OK, SocksRequest, SocksResponse,
            frames::setup_udp_session,
        },
        tls::TlsServerConfig,
    },
    config::Timeouts,
    context::{
        Context, ContextCallback, ContextManager, ContextRef, ContextRefOps, Feature, IOStream,
        TargetAddress, make_buffered_stream,
    },
    listeners::Listener,
};
use std::ops::{Deref, DerefMut};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SocksListenerConfig {
    name: String,
    bind: SocketAddr,
    tls: Option<TlsServerConfig>,
    #[serde(default)]
    auth: AuthData,
    #[serde(default = "default_allow_udp")]
    allow_udp: bool,
    #[serde(default)]
    enforce_udp_client: bool,
    #[serde(default)]
    override_udp_address: Option<IpAddr>,
    // BIND command support
    #[serde(default)]
    allow_bind: bool,
    #[serde(default = "default_enforce_bind_address")]
    enforce_bind_address: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SocksListener<S = RealSocketOps>
where
    S: SocketOps,
{
    #[serde(flatten)]
    config: SocksListenerConfig,
    #[serde(skip)]
    socket_ops: Arc<S>,
}

impl<S: SocketOps> Deref for SocksListener<S> {
    type Target = SocksListenerConfig;
    fn deref(&self) -> &Self::Target {
        &self.config
    }
}

impl<S: SocketOps> DerefMut for SocksListener<S> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.config
    }
}

impl<S: SocketOps> SocksListener<S> {
    pub fn new(config: SocksListenerConfig, socket_ops: Arc<S>) -> Self {
        Self { config, socket_ops }
    }
}

fn default_allow_udp() -> bool {
    true
}

fn default_enforce_bind_address() -> bool {
    true
}

pub fn from_value(value: &serde_yaml_ng::Value) -> Result<Box<dyn Listener>> {
    let config: SocksListenerConfig =
        serde_yaml_ng::from_value(value.clone()).with_context(|| "parse socks listener config")?;
    let ret = SocksListener::new(config, Arc::new(RealSocketOps));
    Ok(Box::new(ret))
}

#[async_trait]
impl<S: SocketOps + Send + Sync + 'static> Listener for SocksListener<S> {
    async fn init(&mut self) -> Result<()> {
        if let Some(Err(e)) = self.tls.as_mut().map(TlsServerConfig::init) {
            return Err(e);
        }
        self.auth.init().await?;
        Ok(())
    }
    async fn listen(
        self: Arc<Self>,
        contexts: Arc<ContextManager>,
        timeouts: Timeouts,
        queue: Sender<ContextRef>,
    ) -> Result<()> {
        info!("{} listening on {}", self.name, self.bind);
        let listener = self.socket_ops.tcp_listen(self.bind).await?;
        let this = self.clone();
        tokio::spawn(this.accept(listener, contexts, timeouts, queue));
        Ok(())
    }

    fn name(&self) -> &str {
        &self.name
    }
}

impl<S: SocketOps + Send + Sync + 'static> SocksListener<S> {
    async fn accept(
        self: Arc<Self>,
        listener: Box<dyn TcpListener>,
        contexts: Arc<ContextManager>,
        timeouts: Timeouts,
        queue: Sender<ContextRef>,
    ) {
        loop {
            match listener.accept().await.with_context(|| "accept") {
                Ok((socket, source)) => {
                    let source = crate::common::try_map_v4_addr(source);
                    let this = self.clone();
                    let queue = queue.clone();
                    let contexts = contexts.clone();
                    let timeouts = timeouts.clone();
                    debug!("{}: connected from {:?}", self.name, source);
                    // we spawn a new thread here to avoid handshake to block accept thread
                    tokio::spawn(
                        this.clone()
                            .handshake(socket, source, contexts, timeouts, queue)
                            .unwrap_or_else(move |e| {
                                warn!(
                                    "{}: handshake error: {}: cause: {:?}",
                                    this.name,
                                    e,
                                    e.source()
                                );
                            }),
                    );
                }
                Err(e) => {
                    error!(
                        "{}, Accept error: {}: cause: {:?}",
                        self.name,
                        e,
                        e.source()
                    );
                    return;
                }
            }
        }
    }

    async fn handshake(
        self: Arc<Self>,
        socket: Box<dyn IOStream>,
        source: SocketAddr,
        contexts: Arc<ContextManager>,
        timeouts: Timeouts,
        queue: Sender<ContextRef>,
    ) -> Result<()> {
        let local_addr =
            if let Some(tcp_stream) = socket.as_any().downcast_ref::<tokio::net::TcpStream>() {
                tcp_stream.local_addr().with_context(|| "local_addr")?
            } else {
                // For mock streams, we don't have a local address.
                "0.0.0.0:0".parse().unwrap()
            };

        self.socket_ops
            .set_keepalive(socket.as_ref(), true)
            .await
            .unwrap_or_else(|e| warn!("set_keepalive failed: {}", e));

        let mut socket = if let Some(tls_config) = &self.tls {
            let (stream, _alpn) = self
                .socket_ops
                .tls_handshake_server(socket, tls_config)
                .await?;
            make_buffered_stream(stream)
        } else {
            make_buffered_stream(socket)
        };

        let ctx = contexts.create_context(self.name.to_owned(), source).await;

        let auth_server = PasswordAuth {
            required: self.auth.required,
        };
        let request = SocksRequest::read_from(&mut socket, auth_server).await?;
        debug!("request {:?}", request);

        ctx.write()
            .await
            .set_extra(
                "user",
                request.auth.as_ref().map(|a| a.0.as_str()).unwrap_or(""),
            )
            .set_callback(Callback {
                version: request.version,
                listen_addr: None,
            })
            .set_client_stream(socket);

        if !self.auth.check(&request.auth).await {
            ctx.on_error(anyhow!("not authencated")).await;
            debug!("client not authencated: {:?}", request.auth);
            return Ok(());
        }
        match request.cmd {
            SOCKS_CMD_CONNECT => {
                ctx.write().await.set_target(request.target);
                ctx.enqueue(&queue).await?;
            }
            SOCKS_CMD_BIND => {
                if !self.allow_bind {
                    ctx.on_error(anyhow!("BIND command not allowed")).await;
                    debug!("bind not allowed");
                    return Ok(());
                }

                // Process target address based on listener policy
                // BIND operations must use SocketAddr, resolve domains first if needed
                let bind_addr = match request.target {
                    TargetAddress::SocketAddr(addr) => addr,
                    TargetAddress::DomainPort(domain, port) => {
                        // For BIND, we can't use domains, must resolve or reject
                        ctx.on_error(anyhow!(
                            "BIND does not support domain addresses: {}:{}",
                            domain,
                            port
                        ))
                        .await;
                        debug!("BIND rejected domain address: {}:{}", domain, port);
                        return Ok(());
                    }
                    _ => {
                        ctx.on_error(anyhow!("Invalid BIND target address")).await;
                        debug!("BIND rejected invalid address type");
                        return Ok(());
                    }
                };

                let final_target = if self.enforce_bind_address {
                    // Enforce mode: force system-assigned address and port, ignore client request
                    // Use appropriate unspecified address based on client's requested address family
                    let unspecified_addr = if bind_addr.is_ipv6() {
                        SocketAddr::new("::".parse::<std::net::Ipv6Addr>().unwrap().into(), 0)
                    } else {
                        SocketAddr::new("0.0.0.0".parse::<std::net::Ipv4Addr>().unwrap().into(), 0)
                    };
                    unspecified_addr.into()
                } else {
                    // Normal mode: honor client's requested address
                    bind_addr.into()
                };

                ctx.write()
                    .await
                    .set_target(final_target)
                    .set_feature(Feature::TcpBind);

                ctx.enqueue(&queue).await?;
            }
            SOCKS_CMD_UDP_ASSOCIATE => {
                if !self.allow_udp {
                    ctx.on_error(anyhow!("not supported")).await;
                    debug!("udp not allowed");
                    return Ok(());
                }
                let local = into_unspecified(source);
                let remote = if self.enforce_udp_client {
                    request
                        .target
                        .as_socket_addr()
                        .filter(|x| !x.ip().is_unspecified())
                } else {
                    None
                };
                let target = into_unspecified(local).into();
                let (mut listen_addr, frames) = setup_udp_session(local, remote)
                    .await
                    .with_context(|| "setup_udp_session")?;

                if let Some(override_addr) = self.override_udp_address {
                    listen_addr = SocketAddr::new(override_addr, listen_addr.port());
                } else if listen_addr.ip().is_unspecified() {
                    listen_addr = SocketAddr::new(local_addr.ip(), listen_addr.port());
                }

                ctx.write()
                    .await
                    .set_target(target)
                    .set_feature(Feature::UdpForward)
                    .set_client_frames(frames)
                    .set_callback(Callback {
                        version: request.version,
                        listen_addr: Some(listen_addr),
                    })
                    .set_idle_timeout(timeouts.udp);
                ctx.enqueue(&queue).await?;
            }
            _ => {
                ctx.on_error(anyhow!("unknown cmd")).await;
                debug!("unknown cmd: {:?}", request.cmd);
            }
        }
        Ok(())
    }
}

struct Callback {
    version: u8,
    listen_addr: Option<SocketAddr>,
}

#[async_trait]
impl ContextCallback for Callback {
    async fn on_connect(&self, ctx: &mut Context) {
        let version = self.version;
        let cmd = SOCKS_REPLY_OK;
        let target = self.listen_addr.map_or_else(|| ctx.target(), |x| x.into());
        let socket = ctx.borrow_client_stream();
        let resp = SocksResponse {
            version,
            cmd,
            target,
        };
        if let Some(e) = resp.write_to(socket.unwrap()).await.err() {
            warn!("failed to send response: {}", e)
        }
    }
    async fn on_error(&self, ctx: &mut Context, _error: Error) {
        let version = self.version;
        let cmd = SOCKS_REPLY_GENERAL_FAILURE;
        let target = "0.0.0.0:0".parse().unwrap();
        let socket = ctx.borrow_client_stream();
        if socket.is_none() {
            return;
        }
        let resp = SocksResponse {
            version,
            cmd,
            target,
        };
        if let Some(e) = resp.write_to(socket.unwrap()).await.err() {
            warn!("failed to send response: {}", e)
        }
    }

    async fn on_bind_listen(&self, ctx: &mut Context, bind_addr: SocketAddr) {
        let version = self.version;
        let cmd = SOCKS_REPLY_OK;
        let target = bind_addr.into();
        let socket = ctx.borrow_client_stream();
        let resp = SocksResponse {
            version,
            cmd,
            target,
        };
        if let Some(e) = resp.write_to(socket.unwrap()).await.err() {
            warn!("failed to send BIND listen response: {}", e)
        }
    }

    async fn on_bind_accept(&self, ctx: &mut Context, peer_addr: SocketAddr) {
        let version = self.version;
        let cmd = SOCKS_REPLY_OK;
        let target = peer_addr.into();
        let socket = ctx.borrow_client_stream();
        let resp = SocksResponse {
            version,
            cmd,
            target,
        };
        if let Some(e) = resp.write_to(socket.unwrap()).await.err() {
            warn!("failed to send BIND accept response: {}", e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::socket_ops::{SocketOps, test_utils::MockSocketOps};
    use crate::config::Timeouts;
    use crate::context::{ContextManager, Feature, TargetAddress};
    use std::sync::Arc;
    use tokio::sync::mpsc;

    fn create_test_listener<S: SocketOps>(
        socket_ops: Arc<S>,
        allow_bind: bool,
        enforce_bind_address: bool,
    ) -> SocksListener<S> {
        SocksListener::new(
            SocksListenerConfig {
                name: "test_socks".to_string(),
                bind: "127.0.0.1:1080".parse().unwrap(),
                tls: None,
                auth: AuthData::default(),
                allow_udp: true,
                enforce_udp_client: false,
                override_udp_address: None,
                allow_bind,
                enforce_bind_address,
            },
            socket_ops,
        )
    }

    #[tokio::test]
    async fn test_socks5_bind_request_allowed() {
        use crate::common::socket_ops::test_utils::StreamScript;

        // Create mock stream that sends SOCKS5 BIND request
        // Note: We don't expect specific response writes because they're handled by callbacks
        let mock_ops = Arc::new(MockSocketOps::new_with_builder(|| {
            StreamScript::new()
                // SOCKS5 handshake
                .read(&[0x05, 0x01, 0x00]) // Version 5, 1 method, no auth
                .write(&[0x05, 0x00]) // Version 5, accept no auth
                // BIND request: VER CMD RSV ATYP DST.ADDR DST.PORT
                .read(&[
                    0x05, // Version 5
                    0x02, // BIND command
                    0x00, // Reserved
                    0x01, // IPv4
                    192, 168, 1, 100, // 192.168.1.100
                    0x1F, 0x90, // Port 8080 (0x1F90)
                ])
                .build()
        }));

        let listener = Arc::new(create_test_listener(mock_ops.clone(), true, false));
        let (tx, mut rx) = mpsc::channel(10);
        let ctx_manager = Arc::new(ContextManager::default());
        let timeouts = Timeouts::default();

        // Simulate handshake with BIND request
        let client_addr: std::net::SocketAddr = "127.0.0.1:54321".parse().unwrap();
        let socket = Box::new((mock_ops.stream_builder)());

        let result = listener
            .handshake(socket, client_addr, ctx_manager, timeouts, tx.clone())
            .await;
        assert!(
            result.is_ok(),
            "SOCKS5 BIND handshake should succeed when allowed"
        );

        // Verify context was created with TcpBind feature
        let ctx_ref = rx.recv().await.expect("Should receive context");
        let ctx = ctx_ref.read().await;
        assert_eq!(
            ctx.feature(),
            Feature::TcpBind,
            "Context should have TcpBind feature"
        );

        // Verify target address matches BIND request
        let target = ctx.target();
        if let TargetAddress::SocketAddr(addr) = target {
            assert_eq!(
                addr.ip(),
                "192.168.1.100".parse::<std::net::IpAddr>().unwrap()
            );
            assert_eq!(addr.port(), 8080);
        } else {
            panic!("Expected SocketAddr target");
        }
    }

    #[tokio::test]
    async fn test_socks5_bind_request_denied() {
        use crate::common::socket_ops::test_utils::StreamScript;

        // Create mock stream for BIND rejection - expect error response from callback
        let mock_ops = Arc::new(MockSocketOps::new_with_builder(|| {
            StreamScript::new()
                // SOCKS5 handshake
                .read(&[0x05, 0x01, 0x00])
                .write(&[0x05, 0x00])
                // BIND request
                .read(&[
                    0x05, // Version 5
                    0x02, // BIND command
                    0x00, // Reserved
                    0x01, // IPv4
                    192, 168, 1, 100, // 192.168.1.100
                    0x1F, 0x90, // Port 8080
                ])
                // Expect error response from callback (general failure)
                .write(&[
                    0x05, // Version 5
                    0x01, // General failure (not command not supported)
                    0x00, // Reserved
                    0x01, // IPv4
                    0, 0, 0, 0, // 0.0.0.0
                    0x00, 0x00, // Port 0
                ])
                .build()
        }));

        let listener = Arc::new(create_test_listener(mock_ops.clone(), false, false)); // BIND disabled
        let (tx, mut rx) = mpsc::channel(10);
        let ctx_manager = Arc::new(ContextManager::default());
        let timeouts = Timeouts::default();

        let client_addr: std::net::SocketAddr = "127.0.0.1:54321".parse().unwrap();
        let socket = Box::new((mock_ops.stream_builder)());

        let result = listener
            .handshake(socket, client_addr, ctx_manager, timeouts, tx)
            .await;
        // Should complete the handshake but reject BIND (no context enqueued)
        assert!(result.is_ok(), "Should handle BIND rejection gracefully");

        // Verify no context was enqueued since BIND was rejected
        match tokio::time::timeout(std::time::Duration::from_millis(100), rx.recv()).await {
            Err(_) => {
                // Timeout occurred - this is what we expect (no context sent)
            }
            Ok(None) => {
                // Channel closed without sending anything - also acceptable
            }
            Ok(Some(ctx)) => {
                panic!(
                    "Context was unexpectedly enqueued when BIND should be denied: {:?}",
                    ctx
                );
            }
        }
    }

    #[tokio::test]
    async fn test_socks5_bind_with_enforce_address() {
        use crate::common::socket_ops::test_utils::StreamScript;

        // Test that enforce_bind_address forces system allocation
        let mock_ops = Arc::new(MockSocketOps::new_with_builder(|| {
            StreamScript::new()
                .read(&[0x05, 0x01, 0x00])
                .write(&[0x05, 0x00])
                // Client requests specific address
                .read(&[
                    0x05, 0x02, 0x00, 0x01, // SOCKS5 BIND IPv4
                    192, 168, 1, 100, // Requested: 192.168.1.100
                    0x1F, 0x90, // Port 8080
                ])
                .build()
        }));

        let listener = Arc::new(create_test_listener(mock_ops.clone(), true, true)); // enforce_bind_address = true
        let (tx, mut rx) = mpsc::channel(10);
        let ctx_manager = Arc::new(ContextManager::default());
        let timeouts = Timeouts::default();

        let client_addr: std::net::SocketAddr = "127.0.0.1:54321".parse().unwrap();
        let socket = Box::new((mock_ops.stream_builder)());

        let result = listener
            .handshake(socket, client_addr, ctx_manager, timeouts, tx)
            .await;
        assert!(result.is_ok());

        let ctx_ref = rx.recv().await.expect("Should receive context");
        let ctx = ctx_ref.read().await;
        assert_eq!(ctx.feature(), Feature::TcpBind);

        // Target should be system-allocated address (0.0.0.0:0), not client request
        if let TargetAddress::SocketAddr(addr) = ctx.target() {
            assert_eq!(addr.ip(), "0.0.0.0".parse::<std::net::IpAddr>().unwrap());
            assert_eq!(addr.port(), 0);
        }
    }

    #[tokio::test]
    async fn test_socks4_bind_request() {
        use crate::common::socket_ops::test_utils::StreamScript;

        // Test SOCKS4 BIND support
        let mock_ops = Arc::new(MockSocketOps::new_with_builder(|| {
            StreamScript::new()
                // SOCKS4 BIND request: VER CMD DSTPORT DSTIP USERID
                .read(&[
                    0x04, // Version 4
                    0x02, // BIND command
                    0x1F, 0x90, // Port 8080
                    192, 168, 1, 100,  // IP 192.168.1.100
                    0x00, // Empty userid (null terminated)
                ])
                .build()
        }));

        let listener = Arc::new(create_test_listener(mock_ops.clone(), true, false));
        let (tx, mut rx) = mpsc::channel(10);
        let ctx_manager = Arc::new(ContextManager::default());
        let timeouts = Timeouts::default();

        let client_addr: std::net::SocketAddr = "127.0.0.1:54321".parse().unwrap();
        let socket = Box::new((mock_ops.stream_builder)());

        let result = listener
            .handshake(socket, client_addr, ctx_manager, timeouts, tx)
            .await;
        assert!(result.is_ok(), "SOCKS4 BIND should succeed");

        let ctx_ref = rx.recv().await.expect("Should receive context");
        let ctx = ctx_ref.read().await;
        assert_eq!(
            ctx.feature(),
            Feature::TcpBind,
            "SOCKS4 should support BIND"
        );

        if let TargetAddress::SocketAddr(addr) = ctx.target() {
            assert_eq!(
                addr.ip(),
                "192.168.1.100".parse::<std::net::IpAddr>().unwrap()
            );
            assert_eq!(addr.port(), 8080);
        }
    }

    #[tokio::test]
    async fn test_socks5_bind_ipv6() {
        use crate::common::socket_ops::test_utils::StreamScript;

        // Test SOCKS5 BIND with IPv6 address
        let mock_ops = Arc::new(MockSocketOps::new_with_builder(|| {
            StreamScript::new()
                .read(&[0x05, 0x01, 0x00])
                .write(&[0x05, 0x00])
                // BIND request with IPv6
                .read(&[
                    0x05, 0x02, 0x00, 0x04, // SOCKS5 BIND IPv6
                    0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x01, // 2001:db8::1
                    0x1F, 0x90, // Port 8080
                ])
                .build()
        }));

        let listener = Arc::new(create_test_listener(mock_ops.clone(), true, false));
        let (tx, mut rx) = mpsc::channel(10);
        let ctx_manager = Arc::new(ContextManager::default());
        let timeouts = Timeouts::default();

        let client_addr: std::net::SocketAddr = "127.0.0.1:54321".parse().unwrap();
        let socket = Box::new((mock_ops.stream_builder)());

        let result = listener
            .handshake(socket, client_addr, ctx_manager, timeouts, tx)
            .await;
        assert!(result.is_ok(), "SOCKS5 BIND with IPv6 should succeed");

        let ctx_ref = rx.recv().await.expect("Should receive context");
        let ctx = ctx_ref.read().await;

        if let TargetAddress::SocketAddr(addr) = ctx.target() {
            assert_eq!(
                addr.ip(),
                "2001:db8::1".parse::<std::net::IpAddr>().unwrap()
            );
            assert_eq!(addr.port(), 8080);
        }
    }
}
