use async_trait::async_trait;
use chashmap_async::CHashMap;
use easy_error::{err_msg, Error, ResultExt};
use quinn::{Endpoint as QuinnEndpoint, ConnectionError as QuinnConnectionError, VarInt, Connection as QuinnRsConnection}; // Renamed Connection to QuinnRsConnection
use serde::{Deserialize, Serialize};
use std::{
    net::{SocketAddr, ToSocketAddrs},
    sync::Arc,
    io::Result as IoResult,
};
use tokio::sync::Mutex;
use tracing::debug;

use super::ConnectorRef;
use crate::{
    common::{
        h11c::h11c_connect,
        quic::{
            create_quic_client, create_quic_frames, quic_frames_thread, QuicFrameSessions,
            QuicStream, QuicConnectionLike, QuinnConnection as WrappedQuinnConnection,
            QuicSendStreamLike, QuicRecvStreamLike
        },
        tls::TlsClientConfig,
    },
    context::{make_buffered_stream, ContextRef, Feature, IOBufStream},
    GlobalState,
};


#[async_trait]
pub trait QuicEndpointConnector: Send + Sync + 'static {
    type Connection: QuicConnectionLike + Send + Sync + 'static;
    async fn connect(&self, remote: SocketAddr, server_name: &str) -> Result<Self::Connection, QuinnConnectionError>;
    fn local_addr(&self) -> IoResult<SocketAddr>;
}

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
    type Connection = WrappedQuinnConnection;

    async fn connect(&self, remote: SocketAddr, server_name: &str) -> Result<Self::Connection, QuinnConnectionError> {
        self.endpoint.connect(remote, server_name)?.await.map(WrappedQuinnConnection)
    }

    fn local_addr(&self) -> IoResult<SocketAddr> {
        self.endpoint.local_addr()
    }
}

type QuicConn = (Arc<WrappedQuinnConnection>, QuicFrameSessions);

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuicConnector {
    name: String,
    server: String,
    port: u16,
    tls_config: TlsClientConfig,
    #[serde(default = "default_bind_addr")]
    bind_addr_str: String,
    #[serde(default = "default_bbr")]
    bbr: bool,
    #[serde(default = "default_inline_udp")]
    inline_udp: bool,

    #[serde(skip, default = "default_endpoint_connector")]
    endpoint_connector: Option<Arc<dyn QuicEndpointConnector<Connection = WrappedQuinnConnection>>>,
    #[serde(skip)]
    connection_cache: Mutex<Option<QuicConn>>,
}

fn default_endpoint_connector() -> Option<Arc<dyn QuicEndpointConnector<Connection = WrappedQuinnConnection>>> { None }


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
    let connector: QuicConnector = serde_yaml_ng::from_value(value.clone()) // Deserialize directly
        .map_err(|e| err_msg(format!("Failed to parse QuicConnector config: {}", e)))?;
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
        let remote_addr = connection_arc.remote_address();

        let local_addr_for_context = self.endpoint_connector.as_ref()
            .ok_or_else(|| err_msg("Endpoint connector not initialized in QuicConnector connect"))?
            .local_addr()
            .context("Failed to get local address from QUIC endpoint connector")?;


        let handshake_result = self.clone().perform_handshake(
            connection_arc.clone(),
            sessions_arc.clone(),
            ctx.clone(),
            remote_addr,
            local_addr_for_context
        ).await;

        match handshake_result {
            Ok(()) => Ok(()),
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("quic:") || err_str.contains("Connection error") || err_str.contains("ConnectionRefused") {
                    self.clear_connection_cache().await;
                }
                Err(e)
            }
        }
    }
}

impl QuicConnector {
    async fn perform_handshake(
        self: Arc<Self>,
        connection: Arc<WrappedQuinnConnection>,
        sessions: QuicFrameSessions,
        ctx: ContextRef,
        remote: SocketAddr,
        local: SocketAddr,
    ) -> Result<(), Error> {
        let (send_stream_like, recv_stream_like) = connection.open_bi().await
            .map_err(|e| err_msg(format!("quic: failed to open bi-stream: {}, cause: {:?}", e, e.source())))?; // Use source() for cause

        let q_stream: QuicStream<WrappedQuinnConnection::SendStream, WrappedQuinnConnection::RecvStream> = QuicStream::new(send_stream_like, recv_stream_like);
        let server_io_stream: IOBufStream = make_buffered_stream(q_stream);

        let channel_type = if self.inline_udp {
            "inline"
        } else {
            "quic-datagrams"
        };

        let conn_for_frames = connection.clone();
        let sessions_for_frames = sessions.clone();
        let frame_io_factory = move |id| {
            let conn_clone = conn_for_frames.clone();
            let sessions_clone = sessions_for_frames.clone();
            async move {
                create_quic_frames(conn_clone, id, sessions_clone).await
            }
        };

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
        Ok(cached_conn_opt.as_ref().map(|(conn_arc, sessions_arc)| (conn_arc.clone(), sessions_arc.clone())).unwrap())
    }

    async fn clear_connection_cache(&self) {
        let mut cached_conn_opt = self.connection_cache.lock().await;
        *cached_conn_opt = None;
        debug!("{}: QUIC connection cache cleared", self.name);
    }

    async fn create_new_connection(self: &Arc<Self>) -> Result<QuicConn, Error> {
        let remote_addr_resolved = (self.server.as_str(), self.port)
            .to_socket_addrs()
            .context("Failed to resolve QUIC server address")?
            .next()
            .ok_or_else(|| err_msg(format!("No IP addresses found for QUIC server: {}", self.server)))?;

        let server_name_for_tls = if self.tls_config.insecure {
            "example.com"
        } else {
            self.server.as_str()
        };

        let endpoint_conn = self.endpoint_connector.as_ref()
            .ok_or_else(|| err_msg("QUIC endpoint connector not initialized"))?
            .connect(remote_addr_resolved, server_name_for_tls)
            .await
            .map_err(|e| err_msg(format!("quic: connection error: {}", e)))?;

        let connection_arc = Arc::new(endpoint_conn);

        debug!("{}: new QUIC connection established to {:?}", self.name, remote_addr_resolved);
        let sessions_arc = Arc::new(CHashMap::new());

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
    use crate::config::context::Contexts as AppContexts;
    use crate::context::TargetAddress;
    use std::sync::atomic::AtomicU32;
    use crate::connectors::Connector;


    fn create_mock_global_state_for_quic_connector() -> Arc<GlobalState> {
        Arc::new(GlobalState {
            contexts: Arc::new(AppContexts::new(1024, Arc::new(AtomicU32::new(0)))),
            rules: Default::default(),
            connectors: Default::default(),
            metrics: Default::default(),
            io_params: Default::default(),
            listeners: Default::default(),
            timeouts: Default::default(),
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

        let mock_endpoint_connector_concrete = MockQuicEndpointConnector::new(proxy_addr_resolved);

        let tls_config = TlsClientConfig {
            sni: Some(server_name.clone()),
            insecure: true,
            ..Default::default()
        };

        // This test will check the error path, as MockQuicEndpointConnector cannot easily provide a
        // functional WrappedQuinnConnection(MockQuicConnection) for the success path's deep interactions.
        mock_endpoint_connector_concrete.add_connect_response(Err(QuinnConnectionError::LocallyClosed));

        // The type of endpoint_connector in QuicConnector is Arc<dyn QuicEndpointConnector<Connection = WrappedQuinnConnection>>
        // The type of mock_endpoint_connector_concrete is MockQuicEndpointConnector, which in connectors/mocks.rs
        // should define `type Connection = WrappedQuinnConnection;` for this to work.
        let mock_endpoint_connector_trait_obj: Arc<dyn QuicEndpointConnector<Connection = WrappedQuinnConnection>> = Arc::new(mock_endpoint_connector_concrete);


        let quic_connector = QuicConnector::new_with_mocks(
            "test_quic_connector".to_string(),
            server_name.clone(),
            server_port,
            tls_config,
            "[::]:0".to_string(),
            false,
            false,
            Some(mock_endpoint_connector_trait_obj),
        );
        let connector_arc : Arc<dyn Connector> = Arc::new(quic_connector);

        let mock_state = create_mock_global_state_for_quic_connector();
        let ctx = mock_state.contexts.create_context("test_listener_quic".to_string(), "1.2.3.4:5555".parse().unwrap()).await;

        ctx.write().await.set_target(TargetAddress::DomainPort("target.service.com".to_string(), 443));
        ctx.write().await.set_feature(Feature::TcpForward);

        let result = connector_arc.connect(mock_state.clone(), ctx.clone()).await;
        assert!(result.is_err(), "QuicConnector connect should have failed due to mocked connection error");
        let err_string = result.err().unwrap().to_string();
        assert!(err_string.contains("quic: connection error"), "Error message mismatch, got: {}", err_string);
        assert!(err_string.contains("Connection locally closed"), "Error message mismatch, got: {}", err_string);
    }
}
