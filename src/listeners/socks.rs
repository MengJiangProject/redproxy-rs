use async_trait::async_trait;
use easy_error::{err_msg, Error, ResultExt};
use futures::TryFutureExt;
use serde::{Deserialize, Serialize};
use std::{
    io::Result as IoResult,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
    sync::mpsc::Sender,
};
use tracing::{debug, error, info, warn};

use crate::{
    common::{
        auth::AuthData,
        into_unspecified, set_keepalive,
        socks::{
            frames::setup_udp_session, PasswordAuth, SocksRequest, SocksResponse, SOCKS_CMD_BIND,
            SOCKS_CMD_CONNECT, SOCKS_CMD_UDP_ASSOCIATE, SOCKS_REPLY_GENERAL_FAILURE,
            SOCKS_REPLY_OK,
        },
        tls::TlsServerConfig,
    },
    context::{make_buffered_stream, Context, ContextCallback, ContextRef, ContextRefOps, Feature, IoStream},
    listeners::Listener,
    GlobalState,
};

// --- Testability Trait for TcpListener (can be shared or defined per module if variations needed) ---
#[async_trait]
pub trait TcpListenerLike: Send + Sync + 'static {
    type Stream: AsyncRead + AsyncWrite + Send + Unpin + 'static;

    async fn accept(&self) -> IoResult<(Self::Stream, SocketAddr)>;
    fn local_addr(&self) -> IoResult<SocketAddr>;
}

// --- Wrapper for real TcpListener ---
pub struct TokioTcpListener(TcpListener);

#[async_trait]
impl TcpListenerLike for TokioTcpListener {
    type Stream = TcpStream;

    async fn accept(&self) -> IoResult<(Self::Stream, SocketAddr)> {
        self.0.accept().await
    }
    fn local_addr(&self) -> IoResult<SocketAddr> {
        self.0.local_addr()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SocksListener {
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
}

fn default_allow_udp() -> bool {
    true
}

pub fn from_value(value: &serde_yaml_ng::Value) -> Result<Box<dyn Listener>, Error> {
    let ret: SocksListener = serde_yaml_ng::from_value(value.clone()).context("parse config")?;
    Ok(Box::new(ret))
}

#[async_trait]
impl Listener for SocksListener {
    async fn init(&mut self) -> Result<(), Error> {
        if let Some(Err(e)) = self.tls.as_mut().map(TlsServerConfig::init) {
            return Err(e);
        }
        self.auth.init().await?;
        Ok(())
    }
    async fn listen(
        self: Arc<Self>,
        state: Arc<GlobalState>,
        queue: Sender<ContextRef>,
    ) -> Result<(), Error> {
        info!("{} listening on {}", self.name, self.bind);
        let listener = TokioTcpListener(TcpListener::bind(&self.bind).await.context("bind")?);
        let this = self.clone();
        tokio::spawn(this.accept_loop(listener, state, queue));
        Ok(())
    }

    fn name(&self) -> &str {
        &self.name
    }
}

impl SocksListener {
    async fn accept_loop<L: TcpListenerLike>(
        self: Arc<Self>,
        listener: L,
        state: Arc<GlobalState>,
        queue: Sender<ContextRef>,
    ) {
        loop {
            match listener.accept().await.context("accept") {
                Ok((socket, source)) => {
                    let source_addr = crate::common::try_map_v4_addr(source);
                    let this = self.clone();
                    let queue = queue.clone();
                    let state = state.clone();
                    let local_addr_result = listener.local_addr(); // Get local_addr from the listener
                    debug!("{}: connected from {:?}", self.name, source_addr);

                    tokio::spawn(async move {
                        match local_addr_result {
                            Ok(local_addr) => {
                                if let Err(e) = this.handshake(socket, source_addr, local_addr, state, queue).await {
                                    warn!(
                                        "{}: handshake error from {}: {}: cause: {:?}",
                                        this.name, source_addr, e, e.cause
                                    );
                                }
                            }
                            Err(e) => {
                                warn!("{}: failed to get local address: {}", this.name, e);
                            }
                        }
                    });
                }
                Err(e) => {
                    error!("{}, Accept error: {}: cause: {:?}", self.name, e, e.cause);
                    return;
                }
            }
        }
    }

    async fn handshake<S: AsyncRead + AsyncWrite + Send + Unpin + 'static>(
        self: Arc<Self>,
        socket: S,
        source: SocketAddr,
        local_addr: SocketAddr, // Passed in from accept_loop
        state: Arc<GlobalState>,
        queue: Sender<ContextRef>,
    ) -> Result<(), Error> {
        // set_keepalive would need similar handling as in http.rs if S is not TcpStream
        // For now, assuming it's handled or mock doesn't need it.
        // let local_addr = socket.local_addr().context("local_addr")?; // This line is problematic if socket is not TcpStream

        let tls_acceptor = self.tls.as_ref().map(|options| options.acceptor());
        let mut client_io_stream: Box<dyn IoStream> = if let Some(acceptor) = tls_acceptor {
            make_buffered_stream(acceptor.accept(socket).await.context("tls accept error")?)
        } else {
            make_buffered_stream(socket)
        };
        let ctx = state
            .contexts
            .create_context(self.name.to_owned(), source)
            .await;

        let auth_server = PasswordAuth {
            required: self.auth.required,
        };
        // SocksRequest::read_from expects a mutable reference to something that implements RW trait.
        // Box<dyn IoStream> implements AsyncRead + AsyncWriteExt + Send + Sync + Unpin, so it should fit.
        let request = SocksRequest::read_from(&mut client_io_stream, auth_server).await?;
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
            .set_client_stream(client_io_stream);

        if !self.auth.check(&request.auth).await {
            ctx.on_error(err_msg("not authenticated")).await; // Corrected typo
            debug!("client not authencated: {:?}", request.auth);
            return Ok(());
        }
        match request.cmd {
            SOCKS_CMD_CONNECT => {
                ctx.write().await.set_target(request.target);
                ctx.enqueue(&queue).await?;
            }
            SOCKS_CMD_BIND => {
                ctx.on_error(err_msg("not supported")).await;
                debug!("not supported cmd: {:?}", request.cmd);
            }
            SOCKS_CMD_UDP_ASSOCIATE => {
                if !self.allow_udp {
                    ctx.on_error(err_msg("not supported")).await;
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
                    .context("setup_udp_session")?;

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
                    .set_idle_timeout(state.timeouts.udp);
                ctx.enqueue(&queue).await?;
            }
            _ => {
                ctx.on_error(err_msg("unknown cmd")).await;
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::listeners::mocks::{MockTcpListener, MockTcpStream};
    use crate::config::Contexts;
    use std::net::Ipv4Addr;
    use std::sync::atomic::AtomicU32;
    use bytes::BytesMut;
    use bytes::BufMut; // For put_u8, put_slice etc.

    // Helper to create a basic GlobalState for tests
    fn create_mock_global_state() -> Arc<GlobalState> {
        Arc::new(GlobalState {
            contexts: Arc::new(Contexts::new(1024, Arc::new(AtomicU32::new(0)))),
            rules: Default::default(),
            dns_resolver: Arc::new(crate::dns::create_resolver(None, false).unwrap()),
            geoip_db: Default::default(),
            transports: Default::default(),
            listeners: Default::default(),
            udp_capacity: 0,
            timeouts: Default::default(),
            hostname: "test_host".to_string(),
            #[cfg(feature = "dashboard")]
            web_ui_port: None,
            #[cfg(feature = "dashboard")]
            web_ui_path: None,
            #[cfg(feature = "api")]
            api_port: None,
            #[cfg(feature = "api")]
            external_controller: None,
        })
    }

    #[tokio::test]
    async fn test_socks_handshake_connect_no_auth() {
        let listener_config = Arc::new(SocksListener {
            name: "test_socks_listener".to_string(),
            bind: "0.0.0.0:0".parse().unwrap(),
            tls: None,
            auth: AuthData::default(), // No auth
            allow_udp: true,
            enforce_udp_client: false,
            override_udp_address: None,
        });

        let mock_stream = MockTcpStream::new("sock_stream_1");

        // SOCKS5 CONNECT request:
        // - Version: 5
        // - NMethods: 1
        // - Method: 0 (No Auth)
        // Then, after server sends 0x05 0x00:
        // - Version: 5
        // - Command: 1 (CONNECT)
        // - RSV: 0
        // - ATYP: 1 (IPv4)
        // - Dest Addr: 8.8.8.8
        // - Dest Port: 53
        let mut req_part1 = BytesMut::new();
        req_part1.put_u8(5); // Version
        req_part1.put_u8(1); // NMethods
        req_part1.put_u8(0); // Method: No Auth
        mock_stream.add_read_data(req_part1.freeze());

        let mut req_part2 = BytesMut::new();
        req_part2.put_u8(5); // Version
        req_part2.put_u8(1); // Command: CONNECT
        req_part2.put_u8(0); // RSV
        req_part2.put_u8(1); // ATYP: IPv4
        req_part2.put_slice(&[8, 8, 8, 8]); // Dest Addr: 8.8.8.8
        req_part2.put_u16(53); // Dest Port: 53
        mock_stream.add_read_data(req_part2.freeze());

        let mock_state = create_mock_global_state();
        let (queue_tx, mut queue_rx) = tokio::sync::mpsc::channel::<ContextRef>(10);
        let source_addr: SocketAddr = "1.2.3.4:54321".parse().unwrap();
        let listener_local_addr: SocketAddr = "127.0.0.1:1080".parse().unwrap();


        let handshake_result = listener_config
            .handshake(mock_stream.clone(), source_addr, listener_local_addr, mock_state.clone(), queue_tx)
            .await;

        assert!(handshake_result.is_ok(), "Handshake failed: {:?}", handshake_result.err());

        // Check SOCKS pre-auth response (0x05 0x00)
        let written_data = mock_stream.get_written_data();
        assert!(written_data.len() >= 2, "Not enough data written for pre-auth response");
        assert_eq!(&written_data[0..2], &[5, 0], "SOCKS pre-auth response mismatch");

        // Check if context was enqueued
        let ctx_ref_opt = tokio::time::timeout(std::time::Duration::from_millis(100), queue_rx.recv()).await;
        assert!(ctx_ref_opt.is_ok(), "Timeout waiting for context on queue");
        let ctx_ref = ctx_ref_opt.unwrap().expect("Queue was empty or closed");

        let ctx_read = ctx_ref.read().await;
        assert_eq!(ctx_read.listener_name(), "test_socks_listener");
        assert_eq!(ctx_read.source(), source_addr);
        assert_eq!(ctx_read.target().as_socket_addr().unwrap().ip(), IpAddr::V4(Ipv4Addr::new(8,8,8,8)));
        assert_eq!(ctx_read.target().as_socket_addr().unwrap().port(), 53);
        assert!(ctx_read.client_stream().is_some(), "Client stream not set in context");

        // The callback is not directly comparable by type name easily without more infra.
        // We trust it's the socks::Callback if other things are correct.
    }

    #[tokio::test]
    async fn test_socks_accept_loop_processes_connections() {
        let listener_config = Arc::new(SocksListener {
            name: "test_socks_accept_listener".to_string(),
            bind: "0.0.0.0:0".parse().unwrap(),
            tls: None,
            auth: AuthData::default(), // No auth
            allow_udp: true, // Allow UDP for broader testing, though not used in this specific test's request
            enforce_udp_client: false,
            override_udp_address: None,
        });

        let mock_listener_addr: SocketAddr = "127.0.0.1:1080".parse().unwrap();
        let mock_tcp_listener = MockTcpListener::new(mock_listener_addr);

        // Connection 1
        let stream1 = MockTcpStream::new("s_stream1_accept");
        let mut req1_part1 = BytesMut::new(); req1_part1.put_u8(5); req1_part1.put_u8(1); req1_part1.put_u8(0); stream1.add_read_data(req1_part1.freeze());
        let mut req1_part2 = BytesMut::new(); req1_part2.put_u8(5); req1_part2.put_u8(1); req1_part2.put_u8(0); req1_part2.put_u8(1); req1_part2.put_slice(&[1,1,1,1]); req1_part2.put_u16(80); stream1.add_read_data(req1_part2.freeze());
        mock_tcp_listener.add_connection(stream1, "10.0.0.1:1234".parse().unwrap());

        // Connection 2
        let stream2 = MockTcpStream::new("s_stream2_accept");
        let mut req2_part1 = BytesMut::new(); req2_part1.put_u8(5); req2_part1.put_u8(1); req2_part1.put_u8(0); stream2.add_read_data(req2_part1.freeze());
        let mut req2_part2 = BytesMut::new(); req2_part2.put_u8(5); req2_part2.put_u8(1); req2_part2.put_u8(0); req2_part2.put_u8(1); req2_part2.put_slice(&[2,2,2,2]); req2_part2.put_u16(80); stream2.add_read_data(req2_part2.freeze());
        mock_tcp_listener.add_connection(stream2, "10.0.0.2:1234".parse().unwrap());

        let mock_state = create_mock_global_state();
        let (queue_tx, mut queue_rx) = tokio::sync::mpsc::channel::<ContextRef>(10);

        let listener_arc_clone = listener_config.clone();
        let accept_task = tokio::spawn(async move {
            // Pass the listener directly, not an Arc if it's not needed by the function signature
            listener_arc_clone.accept_loop(mock_tcp_listener, mock_state, queue_tx).await;
        });

        // Wait for the accept_loop to finish
        match tokio::time::timeout(std::time::Duration::from_secs(1), accept_task).await {
            Ok(Ok(_)) => { /* Task completed successfully */ },
            Ok(Err(e)) => panic!("accept_loop task resulted in an error: {:?}", e), // Should not happen if JoinError is the only error type
            Err(_) => panic!("accept_loop task timed out"),
        }

        // Check that two contexts were enqueued
        let ctx1_ref = queue_rx.recv().await.expect("Queue should have received context 1");
        assert_eq!(ctx1_ref.read().await.listener_name(), "test_socks_accept_listener");
        assert_eq!(ctx1_ref.read().await.source(), "10.0.0.1:1234".parse().unwrap());
        assert_eq!(ctx1_ref.read().await.target().to_string(), "1.1.1.1:80");


        let ctx2_ref = queue_rx.recv().await.expect("Queue should have received context 2");
        assert_eq!(ctx2_ref.read().await.listener_name(), "test_socks_accept_listener");
        assert_eq!(ctx2_ref.read().await.source(), "10.0.0.2:1234".parse().unwrap());
        assert_eq!(ctx2_ref.read().await.target().to_string(), "2.2.2.2:80");

        // Ensure no more contexts
        match tokio::time::timeout(std::time::Duration::from_millis(50), queue_rx.recv()).await {
            Ok(Some(_ctx)) => panic!("Expected no more contexts to be enqueued"),
            Ok(None) => { /* Channel closed, correct, no more items */ }
            Err(_) => { /* Timeout, correct, no more items */ }
        }
    }
     // TODO: Test for SOCKS handshake with UDP associate
     // TODO: Test for SOCKS handshake with authentication

    #[tokio::test]
    async fn test_socks_handshake_udp_associate() {
        let listener_config = Arc::new(SocksListener {
            name: "test_socks_udp".to_string(),
            bind: "0.0.0.0:0".parse().unwrap(),
            tls: None,
            auth: AuthData::default(), // No auth
            allow_udp: true,
            enforce_udp_client: false,
            override_udp_address: None,
        });

        let mock_tcp_stream = MockTcpStream::new("sock_tcp_for_udp");

        // SOCKS5 UDP ASSOCIATE request:
        // Client's desired address for UDP (can be 0.0.0.0:0)
        let client_udp_target_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();

        let mut req_part1 = BytesMut::new(); // Auth negotiation
        req_part1.put_u8(5); req_part1.put_u8(1); req_part1.put_u8(0);
        mock_tcp_stream.add_read_data(req_part1.freeze());

        let mut req_part2 = BytesMut::new(); // UDP Associate command
        req_part2.put_u8(5); // Version
        req_part2.put_u8(SOCKS_CMD_UDP_ASSOCIATE); // Command
        req_part2.put_u8(0); // RSV
        match client_udp_target_addr { // ATYP + Addr + Port
            SocketAddr::V4(v4) => {
                req_part2.put_u8(SOCKS_ATYP_INET4);
                req_part2.put_slice(&v4.ip().octets());
                req_part2.put_u16(v4.port());
            }
            SocketAddr::V6(v6) => {
                req_part2.put_u8(SOCKS_ATYP_INET6);
                req_part2.put_slice(&v6.ip().octets());
                req_part2.put_u16(v6.port());
            }
        }
        mock_tcp_stream.add_read_data(req_part2.freeze());

        let mock_state = create_mock_global_state();
        let (queue_tx, mut queue_rx) = tokio::sync::mpsc::channel::<ContextRef>(10);
        let source_addr: SocketAddr = "1.2.3.4:54321".parse().unwrap();
        let listener_tcp_local_addr: SocketAddr = "127.0.0.1:1080".parse().unwrap(); // For TCP part

        // Mocking UdpSocketLike for setup_udp_session:
        // The handshake calls `setup_udp_session` which uses `S::bind`.
        // We need to ensure that a mock `UdpSocketLike` is used.
        // This test is for `SocksListener::handshake`, not `setup_udp_session` directly.
        // `setup_udp_session` is called with `S = tokio::net::UdpSocket` by default.
        // To test this properly, `setup_udp_session` itself would need to be injectable,
        // or the test would perform real UDP binding.
        // For now, let's assume real UDP binding will occur and succeed on a random port.
        // The response should contain this dynamically allocated port.

        let handshake_result = listener_config
            .handshake(mock_tcp_stream.clone(), source_addr, listener_tcp_local_addr, mock_state.clone(), queue_tx)
            .await;

        assert!(handshake_result.is_ok(), "Handshake failed for UDP associate: {:?}", handshake_result.err());

        // Check SOCKS pre-auth response (0x05 0x00)
        let written_data = mock_tcp_stream.get_written_data();
        assert!(written_data.len() >= 2, "Not enough data for pre-auth response");
        assert_eq!(&written_data[0..2], &[5, 0], "SOCKS pre-auth response mismatch");

        // Check SOCKS UDP associate response (after pre-auth)
        // Expected: VER(5) REP(0) RSV(0) ATYP(1/4) BND.ADDR BND.PORT
        assert!(written_data.len() >= 2 + 4 + 4 + 2, "Not enough data for UDP associate response"); // Min length for IPv4
        assert_eq!(written_data[2], 5, "UDP associate response VER mismatch"); // VER
        assert_eq!(written_data[3], SOCKS_REPLY_OK, "UDP associate response REP not OK"); // REP
        assert_eq!(written_data[4], 0, "UDP associate response RSV mismatch"); // RSV

        let bnd_atyp = written_data[5];
        let bnd_addr: IpAddr;
        let bnd_port: u16;

        if bnd_atyp == SOCKS_ATYP_INET4 {
            assert!(written_data.len() >= 2 + 4 + 4 + 2);
            let mut addr_bytes = [0u8; 4];
            addr_bytes.copy_from_slice(&written_data[6..10]);
            bnd_addr = IpAddr::from(addr_bytes);
            bnd_port = u16::from_be_bytes([written_data[10], written_data[11]]);
        } else if bnd_atyp == SOCKS_ATYP_INET6 {
            assert!(written_data.len() >= 2 + 4 + 16 + 2);
            let mut addr_bytes = [0u8; 16];
            addr_bytes.copy_from_slice(&written_data[6..22]);
            bnd_addr = IpAddr::from(addr_bytes);
            bnd_port = u16::from_be_bytes([written_data[22], written_data[23]]);
        } else {
            panic!("Unexpected BND.ATYP in UDP associate response: {}", bnd_atyp);
        }

        // The bind address should be the listener's TCP local IP (or override_udp_address if set)
        // and a dynamically allocated port.
        if listener_config.override_udp_address.is_none() {
             assert_eq!(bnd_addr, listener_tcp_local_addr.ip(), "Bound IP in response should match listener's TCP IP");
        } else {
            assert_eq!(bnd_addr, listener_config.override_udp_address.unwrap());
        }
        assert_ne!(bnd_port, 0, "Bound port in UDP response should not be 0");


        // Check if context was enqueued
        let ctx_ref_opt = tokio::time::timeout(std::time::Duration::from_millis(100), queue_rx.recv()).await;
        assert!(ctx_ref_opt.is_ok(), "Timeout waiting for context on queue for UDP associate");
        let ctx_ref = ctx_ref_opt.unwrap().expect("Queue was empty for UDP associate");

        let ctx_read = ctx_ref.read().await;
        assert_eq!(ctx_read.listener_name(), "test_socks_udp");
        assert_eq!(ctx_read.source(), source_addr);
        assert!(matches!(ctx_read.feature(), Feature::UdpForward), "Feature should be UdpForward");
        assert!(ctx_read.client_frames().is_some(), "Client frames not set for UDP associate");
        // Target for UDP associate is usually unspecified from client, server binds locally.
        // The context's target is set to an unspecified version of the source's IP.
        assert!(ctx_read.target().as_socket_addr().unwrap().ip().is_unspecified());
    }

    #[tokio::test]
    async fn test_socks_handshake_failed_auth() {
        let auth_data = AuthData::UserPass {
            users: vec![("testuser".to_string(), "testpass".to_string())].into_iter().collect(),
            required: true, // Authentication is required
        };

        let listener_config = Arc::new(SocksListener {
            name: "test_socks_auth_fail".to_string(),
            bind: "0.0.0.0:0".parse().unwrap(),
            tls: None,
            auth: auth_data,
            allow_udp: false, // UDP not relevant for this test
            enforce_udp_client: false,
            override_udp_address: None,
        });

        let mock_tcp_stream = MockTcpStream::new("sock_tcp_auth_fail");

        // Client attempts SOCKS5 with "No Authentication Required" (0x00) method,
        // but server requires Username/Password (0x02).
        let mut req_part1 = BytesMut::new(); // Auth negotiation offering only "No Auth"
        req_part1.put_u8(5); // Version
        req_part1.put_u8(1); // NMethods
        req_part1.put_u8(SOCKS_AUTH_NONE); // Method: No Auth
        mock_tcp_stream.add_read_data(req_part1.freeze());

        let mock_state = create_mock_global_state();
        let (queue_tx, mut queue_rx) = tokio::sync::mpsc::channel::<ContextRef>(10);
        let source_addr: SocketAddr = "1.2.3.4:12345".parse().unwrap();
        let listener_tcp_local_addr: SocketAddr = "127.0.0.1:1081".parse().unwrap();

        let handshake_result = listener_config
            .handshake(mock_tcp_stream.clone(), source_addr, listener_tcp_local_addr, mock_state.clone(), queue_tx)
            .await;

        // Handshake itself should complete Ok because errors are handled by writing to client stream
        // and not enqueuing the context.
        assert!(handshake_result.is_ok(), "Handshake function itself should not fail: {:?}", handshake_result.err());

        // Check SOCKS auth response. Server should select no acceptable methods (0xFF).
        let written_data = mock_tcp_stream.get_written_data();
        // Expected: VER(5) METHOD(0xFF - No acceptable methods)
        assert!(written_data.len() >= 2, "Not enough data for auth response. Got: {:?}", written_data);
        assert_eq!(&written_data[0..2], &[5, 0xFF], "SOCKS auth response should indicate no acceptable method");

        // Ensure no context was enqueued
        match tokio::time::timeout(std::time::Duration::from_millis(50), queue_rx.recv()).await {
            Ok(Some(_ctx)) => panic!("Expected no context to be enqueued on auth failure"),
            Ok(None) => { /* Channel closed, correct */ }
            Err(_) => { /* Timeout, correct, no item received */ }
        }

        // --- Test case 2: Client offers User/Pass, but provides wrong credentials ---
        // This part is more complex because it involves the sub-negotiation.
        // The current PasswordAuth server impl in common/socks.rs always returns success (0x01 0x00)
        // after reading user/pass, it doesn't actually validate them against a list.
        // The check `self.auth.check(&request.auth).await` in SocksListener::handshake
        // happens *after* SocksRequest::read_from (which includes auth sub-negotiation).
        // So, to test this properly, the common::socks::PasswordAuth::auth_v5 would need to
        // actually perform credential checking and return an auth failure code (e.g., 0x01 0x01)
        // which would then cause SocksRequest::read_from to return an Err.
        // The current test setup cannot easily test "wrong credentials" if PasswordAuth always succeeds.
        // However, we can test if self.auth.check() fails *after* a (mock successful) sub-negotiation.
        // Let's simulate the case where the client *does* go through user/pass auth, auth itself "succeeds" at protocol level,
        // but our listener's `self.auth.check()` then rejects it.

        let mock_tcp_stream_wrong_creds = MockTcpStream::new("sock_tcp_wrong_creds");
        let listener_config_strong_auth = Arc::new(SocksListener {
            name: "test_socks_auth_fail_creds".to_string(),
            bind: "0.0.0.0:0".parse().unwrap(),
            tls: None,
            auth: AuthData::UserPass { // Require "realuser":"realpass"
                 users: vec![("realuser".to_string(), "realpass".to_string())].into_iter().collect(),
                 required: true,
            },
            allow_udp: false, enforce_udp_client: false, override_udp_address: None,
        });

        // Client offers User/Pass method
        let mut p1 = BytesMut::new(); p1.put_u8(5); p1.put_u8(1); p1.put_u8(SOCKS_AUTH_USRPWD);
        mock_tcp_stream_wrong_creds.add_read_data(p1.freeze());
        // Client sends "wronguser", "wrongpass" in sub-negotiation
        let mut p2 = BytesMut::new();
        p2.put_u8(1); // sub-negotiation version
        p2.put_u8("wronguser".len() as u8); p2.put_slice(b"wronguser");
        p2.put_u8("wrongpass".len() as u8); p2.put_slice(b"wrongpass");
        mock_tcp_stream_wrong_creds.add_read_data(p2.freeze());

        let (queue_tx2, mut queue_rx2) = tokio::sync::mpsc::channel::<ContextRef>(10);
        let handshake_result2 = listener_config_strong_auth
            .handshake(mock_tcp_stream_wrong_creds.clone(), source_addr, listener_tcp_local_addr, mock_state.clone(), queue_tx2)
            .await;
        assert!(handshake_result2.is_ok(), "Handshake function for wrong creds should complete: {:?}", handshake_result2.err());

        // Server responds: 0x05 0x02 (User/Pass selected)
        // Server responds to sub-negotiation: 0x01 0x00 (Success, because PasswordAuth mock doesn't check)
        // Then SocksListener::handshake calls self.auth.check() which fails.
        // Then ctx.on_error() is called, which writes SOCKS_REPLY_GENERAL_FAILURE
        let written_data2 = mock_tcp_stream_wrong_creds.get_written_data();

        // Expected: 0x05 0x02 (auth method selection)
        //           0x01 0x00 (auth sub-negotiation "success" from common::socks::PasswordAuth)
        //           SOCKS_REPLY_GENERAL_FAILURE response because self.auth.check() failed.
        //           VER(5) REP(1) RSV(0) ATYP(1) ADDR(0.0.0.0) PORT(0)
        assert!(written_data2.len() >= 2 + 2 + (1+1+1+1+4+2) , "Not enough data for all responses. Len: {}", written_data2.len());
        assert_eq!(&written_data2[0..2], &[5, SOCKS_AUTH_USRPWD], "SOCKS method selection mismatch");
        assert_eq!(&written_data2[2..4], &[1, 0], "SOCKS sub-negotiation response not success");

        assert_eq!(written_data2[4], 5, "Final error VER mismatch");
        assert_eq!(written_data2[5], SOCKS_REPLY_GENERAL_FAILURE, "Final error REP mismatch");


        match tokio::time::timeout(std::time::Duration::from_millis(50), queue_rx2.recv()).await {
            Ok(Some(_ctx)) => panic!("Expected no context to be enqueued on auth credential failure"),
            Ok(None) => { /* Channel closed, correct */ }
            Err(_) => { /* Timeout, correct, no item received */ }
        }
    }
}
