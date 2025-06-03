use async_trait::async_trait;
use chashmap_async::CHashMap;
use easy_error::{err_msg, Error, ResultExt};
use quinn::{Connection as QuinnConnection, ConnectError as QuinnConnectError, Endpoint as QuinnEndpoint}; // Specific Quinn types
use serde::{Deserialize, Serialize};
use std::{
    net::{SocketAddr, ToSocketAddrs},
    sync::Arc,
};
use tokio::sync::Mutex;
use tracing::debug;

use super::ConnectorRef;
use crate::{
    common::{
        h11c::h11c_connect,
        quic::{
            create_quic_client, create_quic_frames, quic_frames_thread, QuicFrameSessions,
            QuicStream, QuicConnectionLike, QuinnConnection as WrappedQuinnConnection, // Use the wrapper from common
        },
        tls::TlsClientConfig,
    },
    context::{make_buffered_stream, ContextRef, Feature},
    GlobalState,
};


// --- Testability Trait for QUIC Endpoint Connect Operation ---
#[async_trait]
pub trait QuicEndpointConnector: Send + Sync + 'static {
    // Use the QuicConnectionLike trait from common::quic for the connection type
    type Connection: QuicConnectionLike + Send + Sync + 'static;

    async fn connect(&self, remote: SocketAddr, server_name: &str) -> Result<Self::Connection, QuinnConnectError>;
    // We might also need a method to set default client config if that's part of the dynamic behavior.
    // fn set_default_client_config(&mut self, config: quinn::ClientConfig); // Quinn's Endpoint has this.
    fn local_addr(&self) -> std::io::Result<SocketAddr>; // Added for consistency
}

// --- Wrapper for real Quinn Endpoint ---
// This wrapper will hold the actual quinn::Endpoint.
pub struct TokioQuicEndpointConnector {
    endpoint: QuinnEndpoint,
}

impl TokioQuicEndpointConnector {
    pub fn new(bind_addr_str: &str, tls_client_config: &TlsClientConfig, enable_bbr: bool) -> Result<Self, Error> {
        let client_cfg = create_quic_client(tls_client_config, enable_bbr)
            .context("Failed to create QUIC client config for endpoint connector")?;
        let bind_addr = bind_addr_str.parse().context("Failed to parse bind address for QUIC endpoint connector")?;
        let mut endpoint = QuinnEndpoint::client(bind_addr)
            .context("Failed to bind QUIC client endpoint")?;
        endpoint.set_default_client_config(client_cfg);
        Ok(Self { endpoint })
    }
}

#[async_trait]
impl QuicEndpointConnector for TokioQuicEndpointConnector {
    type Connection = WrappedQuinnConnection; // Use the wrapper from common::quic

    async fn connect(&self, remote: SocketAddr, server_name: &str) -> Result<Self::Connection, QuinnConnectError> {
        self.endpoint.connect(remote, server_name)?.await.map(WrappedQuinnConnection)
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }
}

// Represents the established QUIC connection and its frame sessions
// Using Arc for Connection because QuicConnectionLike is implemented by QuinnConnection not Arc<QuinnConnection>
// and QuicFrameSessions is already Arc.
// However, quic_frames_thread takes Arc<C: QuicConnectionLike>.
// So, QuicConn should probably be Arc<WrappedQuinnConnection>
type QuicConn = (Arc<WrappedQuinnConnection>, QuicFrameSessions);

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuicConnector {
    name: String,
    server: String,
    port: u16,
    tls_config: TlsClientConfig, // Renamed from tls
    #[serde(default = "default_bind_addr")]
    bind_addr_str: String, // Renamed from bind
    #[serde(default = "default_bbr")]
    bbr: bool,
    #[serde(default = "default_inline_udp")]
    inline_udp: bool,

    #[serde(skip)]
    // endpoint_connector will hold Arc<TokioQuicEndpointConnector> or Arc<dyn QuicEndpointConnector>
    endpoint_connector: Option<Arc<dyn QuicEndpointConnector<Connection = WrappedQuinnConnection>>>,
    #[serde(skip)]
    connection_cache: Mutex<Option<QuicConn>>,
}

impl QuicConnector {
    #[cfg(test)]
    pub fn new_with_mocks(
        name: String,
        server: String,
        port: u16,
        tls_config: TlsClientConfig,
        bind_addr_str: String,
        bbr: bool,
        inline_udp: bool,
        endpoint_connector: Option<Arc<dyn QuicEndpointConnector<Connection = WrappedQuinnConnection>>>,
        // connection_cache can default to Mutex::new(None)
    ) -> Self {
        Self {
            name,
            server,
            port,
            tls_config,
            bind_addr_str,
            bbr,
            inline_udp,
            endpoint_connector,
            connection_cache: Mutex::new(None),
        }
    }
}

fn default_bind_addr() -> String {
    "[::]:0".to_owned()
}

fn default_bbr() -> bool {
    true
}

fn default_inline_udp() -> bool {
    false
}

pub fn from_value(value: &serde_yaml_ng::Value) -> Result<ConnectorRef, Error> {
    // Deserialize directly into QuicConnector, non-serde fields will be None/Default.
    // Then, in init, we'll create and store the endpoint_connector.
    let mut connector: QuicConnector = serde_yaml_ng::from_value(value.clone())
        .map_err(|e| Error::new(format!("Failed to parse QuicConnector config: {}", e)))?;

    // Initialize non-serde fields that are not set up in init
    // connector.endpoint_connector is set in init.
    // connector.connection_cache is initialized with Mutex::new(None) by default if not specified by serde.
    // Ensure connection_cache is properly initialized if serde doesn't do it for Mutex<Option<>>.
    // It's fine, Mutex::new(None) is the correct default for a skipped field.
    Ok(Box::new(connector))
}

#[async_trait]
impl super::Connector for QuicConnector {
    fn name(&self) -> &str {
        self.name.as_str()
    }

    fn features(&self) -> &[Feature] {
        &[Feature::TcpForward, Feature::UdpForward, Feature::UdpBind]
    }

    async fn init(&mut self) -> Result<(), Error> {
        self.tls_config.init().context("Failed to initialize TlsClientConfig for QuicConnector")?;

        // Create and store the endpoint_connector
        let connector_impl = TokioQuicEndpointConnector::new(
            &self.bind_addr_str,
            &self.tls_config,
            self.bbr
        ).context("Failed to create TokioQuicEndpointConnector")?;

        self.endpoint_connector = Some(Arc::new(connector_impl));
        Ok(())
    }

    async fn connect(
        self: Arc<Self>,
        _state: Arc<GlobalState>,
        ctx: ContextRef,
    ) -> Result<(), Error> {
        let (connection_arc, sessions_arc) = self.get_connection().await?;
        // remote_address and local_addr now need to come from the QuicConnectionLike and QuicEndpointConnector traits
        let remote_addr = connection_arc.remote_address();

        // local_addr from endpoint_connector is not directly available here in the same way.
        // The endpoint_connector itself doesn't store the local_addr of the *connection*.
        // The quinn::Endpoint has local_addr(), but not individual connections.
        // The underlying IoStream might eventually provide it, but not the QuicConnectionLike directly.
        // For now, let's use a placeholder or determine if it's strictly needed for h11c_connect.
        // h11c_connect uses local/remote for context.
        // The previous code used endpoint.as_ref().unwrap().local_addr().
        // If TokioQuicEndpointConnector stores its underlying QuinnEndpoint, it can expose local_addr().
        // Let's assume TokioQuicEndpointConnector can provide its bind address as local_addr for the connection context.
        // This isn't strictly the connection's local ephemeral port but the endpoint's bind.
        let local_addr_for_context = self.endpoint_connector.as_ref().unwrap().local_addr()
             .context("Failed to get local address from QUIC endpoint connector")?;


        let handshake_result = self.clone().perform_handshake(
            connection_arc.clone(), // Pass Arc here
            sessions_arc.clone(),
            ctx.clone(),
            remote_addr,
            local_addr_for_context
        ).await;

        match handshake_result {
            Ok(()) => Ok(()),
            Err(e) => {
                // Assuming error context "quic:" implies a connection-level issue.
                // The error from perform_handshake might need to be inspected more carefully.
                if e.to_string().contains("quic:") || e.to_string().contains("Connection error") { // Heuristic
                    self.clear_connection_cache().await;
                }
                Err(e)
            }
        }
    }
}

impl QuicConnector {
    async fn perform_handshake( // Renamed from handshake to avoid conflict with a field if any
        self: Arc<Self>,
        connection: Arc<WrappedQuinnConnection>, // Explicitly Arc<WrappedQuinnConnection>
        sessions: QuicFrameSessions,
        ctx: ContextRef,
        remote: SocketAddr,
        local: SocketAddr, // This is endpoint's local, not specific stream's
    ) -> Result<(), Error> {
        // open_bi is on QuicConnectionLike, which WrappedQuinnConnection implements
        let (send_stream_like, recv_stream_like) = connection.open_bi().await
            .map_err(|e| Error::new(format!("quic: failed to open bi-stream: {}", e)))?;

        // QuicStream::new expects types that implement QuicSendStreamLike and QuicRecvStreamLike
        // Our WrappedQuinnConnection::SendStream (QuinnSendStream) and ::RecvStream (QuinnRecvStream) do.
        let quic_stream_typed = QuicStream::new(send_stream_like, recv_stream_like);
        let server_io_stream = make_buffered_stream(quic_stream_typed);

        let channel_type = if self.inline_udp {
            "inline"
        } else {
            "quic-datagrams"
        };

        // create_quic_frames expects Arc<C: QuicConnectionLike>
        // We have Arc<WrappedQuinnConnection> which fits.
        let conn_for_frames = connection.clone();
        let sessions_for_frames = sessions.clone();
        let frame_io_factory = |id| create_quic_frames(conn_for_frames.clone(), id, sessions_for_frames.clone());

        h11c_connect(server_io_stream, ctx, local, remote, channel_type, frame_io_factory).await?;
        Ok(())
    }

    async fn get_connection(self: &Arc<Self>) -> Result<QuicConn, Error> {
        let mut cached_conn_opt = self.connection_cache.lock().await;
        if cached_conn_opt.is_none() {
            let new_conn_tuple = self.create_new_connection().await
                .context("Failed to create new QUIC connection")?;
            *cached_conn_opt = Some(new_conn_tuple);
        }
        // Clone the Arc<WrappedQuinnConnection> and Arc<CHashMap> (QuicFrameSessions)
        Ok(cached_conn_opt.as_ref().map(|(conn_arc, sessions_arc)| (conn_arc.clone(), sessions_arc.clone())).unwrap())
    }

    async fn clear_connection_cache(&self) { // Renamed from clear_connection
        let mut cached_conn_opt = self.connection_cache.lock().await;
        *cached_conn_opt = None;
        debug!("{}: QUIC connection cache cleared", self.name);
    }

    async fn create_new_connection(self: &Arc<Self>) -> Result<QuicConn, Error> { // Renamed from create_connection
        let remote_addr_resolved = (self.server.as_str(), self.port)
            .to_socket_addrs()
            .context("Failed to resolve QUIC server address")?
            .next()
            .ok_or_else(|| err_msg(format!("No IP addresses found for QUIC server: {}", self.server)))?;

        let server_name_for_tls = if self.tls_config.insecure {
            "example.com" // Use a valid dummy for insecure connections if server is IP
        } else {
            self.server.as_str()
        };

        let endpoint_conn = self.endpoint_connector.as_ref()
            .ok_or_else(|| err_msg("QUIC endpoint connector not initialized"))?
            .connect(remote_addr_resolved, server_name_for_tls)
            .await
            .map_err(|e| Error::new(format!("quic: connection error: {}", e)))?;

        let connection_arc = Arc::new(endpoint_conn); // endpoint_conn is WrappedQuinnConnection

        debug!("{}: new QUIC connection established to {:?}", self.name, remote_addr_resolved);
        let sessions_arc = Arc::new(CHashMap::new());

        // Spawn quic_frames_thread. It needs Arc<C: QuicConnectionLike>.
        // connection_arc is Arc<WrappedQuinnConnection> and WrappedQuinnConnection implements QuicConnectionLike.
        tokio::spawn(quic_frames_thread(
            self.name.to_owned(),
            sessions_arc.clone(),
            connection_arc.clone(),
        ));
        Ok((connection_arc, sessions_arc))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connectors::mocks::MockQuicEndpointConnector;
    use crate::common::quic::tests::{MockQuicConnection, MockQuicSendStream, MockQuicRecvStream};
    use crate::config::Contexts as AppContexts;
    use crate::context::TargetAddress;
    use std::sync::atomic::AtomicU32;
    use std::time::Duration;
    use bytes::Bytes;


    fn create_mock_global_state_for_quic_connector() -> Arc<GlobalState> {
        Arc::new(GlobalState {
            contexts: Arc::new(AppContexts::new(1024, Arc::new(AtomicU32::new(0)))),
            rules: Default::default(),
            dns_resolver: Arc::new(crate::dns::create_resolver(None, false).unwrap()),
            geoip_db: Default::default(),
            transports: Default::default(),
            listeners: Default::default(),
            udp_capacity: 0,
            timeouts: Default::default(),
            hostname: "test_quic_connector_host".to_string(),
            #[cfg(feature = "dashboard")] web_ui_port: None,
            #[cfg(feature = "dashboard")] web_ui_path: None,
            #[cfg(feature = "api")] api_port: None,
            #[cfg(feature = "api")] external_controller: None,
        })
    }

    #[tokio::test]
    async fn test_quic_connector_connect_and_handshake() {
        let server_name = "quicproxy.example.com".to_string();
        let server_port = 4433u16;
        let proxy_addr_resolved: SocketAddr = format!("{}:{}", server_name, server_port).parse().unwrap();

        let mock_endpoint_connector = Arc::new(MockQuicEndpointConnector::new(proxy_addr_resolved));

        let tls_config = TlsClientConfig { // Basic TlsClientConfig
            sni: server_name.clone(),
            insecure: true, // Simplify test
            ..Default::default()
        };

        // This Arc<MockQuicConnection> is what the endpoint connector's `connect` will return.
        let mock_quic_connection = Arc::new(MockQuicConnection::new(proxy_addr_resolved));

        // Pre-configure the mock bi-stream that perform_handshake will open
        let mock_send_stream = MockQuicSendStream::new("h11c_send");
        let mock_send_stream_clone = mock_send_stream.clone(); // To get written data later
        let mock_recv_stream = MockQuicRecvStream::new("h11c_recv");
        mock_quic_connection.add_mock_bi_streams(mock_send_stream, mock_recv_stream);

        // Configure the endpoint connector to return the above mock connection
        mock_endpoint_connector.add_connect_response(Ok(mock_quic_connection.as_ref().clone()));


        let quic_connector = QuicConnector::new_with_mocks(
            "test_quic_connector".to_string(),
            server_name.clone(),
            server_port,
            tls_config,
            "[::]:0".to_string(), // bind_addr_str
            false, // bbr
            false, // inline_udp
            Some(mock_endpoint_connector.clone()),
        );
        let connector_arc = Arc::new(quic_connector);

        let mock_state = create_mock_global_state_for_quic_connector();
        let ctx = mock_state.contexts.create_context("test_listener_quic".to_string(), "1.2.3.4:5555".parse().unwrap()).await;

        let final_dest_domain = "target.service.com";
        let final_dest_port = 443;
        ctx.write().await.set_target(TargetAddress::DomainPort(final_dest_domain.to_string(), final_dest_port));
        ctx.write().await.set_feature(Feature::TcpForward);

        // --- Call connect ---
        let result = connector_arc.connect(mock_state.clone(), ctx.clone()).await;
        assert!(result.is_ok(), "QuicConnector connect failed: {:?}", result.err());

        // --- Assertions ---
        // 1. Check if endpoint_connector.connect was called (implicitly done if no error and below checks pass)
        // 2. Check if mock_quic_connection.open_bi was called (streams consumed)
        assert_eq!(mock_quic_connection.mock_send_streams.lock().unwrap().len(), 0, "Send stream not consumed by open_bi");
        assert_eq!(mock_quic_connection.mock_recv_streams.lock().unwrap().len(), 0, "Recv stream not consumed by open_bi");

        // 3. Check if h11c_connect wrote the HTTP CONNECT request to the mock_send_stream
        let written_data = mock_send_stream_clone.get_written_data();
        let written_str = String::from_utf8(written_data).unwrap_or_default();

        assert!(written_str.starts_with(&format!("CONNECT {}:{} HTTP/1.1\r\n", final_dest_domain, final_dest_port)), "HTTP CONNECT request line mismatch. Got: {}", written_str);
        assert!(written_str.contains(&format!("\r\nhost: {}:{}\r\n", final_dest_domain, final_dest_port)), "HTTP CONNECT host header mismatch. Got: {}", written_str);

        // 4. Check context state (server_stream should be set by h11c_connect)
        let ctx_read = ctx.read().await;
        assert!(ctx_read.server_stream().is_some(), "Server stream not set in context by h11c_connect");
    }
}
