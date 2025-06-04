use async_trait::async_trait;
use chashmap_async::CHashMap;
use easy_error::{Error, ResultExt, err_msg};
use quinn::{Connecting as QuinnConnecting, Endpoint as QuinnEndpoint, ServerConfig as QuinnServerConfig, ConnectionError as QuinnConnectionError, VarInt, Connection as QuinnRsConnection};  // Added QuinnRsConnection
use serde::{Deserialize, Serialize};
use std::io::Result as IoResult;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc::Sender;
use tracing::{debug, info, warn};
use std::error::Error as StdErrorTrait; // For e.cause()

use crate::{
    common::{
        h11c::h11c_handshake,
        quic::{
            create_quic_server, create_quic_frames, quic_frames_thread, QuicFrameSessions,
            QuicStream, QuicConnectionLike, QuinnConnection as WrappedQuinnConnection,
            QuicSendStreamLike, QuicRecvStreamLike
        },
        tls::{TlsServerConfig, TlsServerConfigExt}, // Added TlsServerConfigExt
    },
    context::{make_buffered_stream, ContextRef, IOBufStream},
    listeners::Listener,
    GlobalState,
};


#[async_trait]
pub trait QuicConnectingLike: Send + Sync + 'static {
    type Connection: QuicConnectionLike + Send + Sync + 'static;
    async fn wait_for_connection(self) -> Result<Self::Connection, QuinnConnectionError>;
    fn remote_address(&self) -> SocketAddr;
}

#[async_trait]
pub trait QuicEndpointLike: Send + Sync + 'static {
    type Connecting: QuicConnectingLike<Connection = Self::Connection>;
    type Connection: QuicConnectionLike + Send + Sync + 'static;

    async fn accept(&self) -> Option<Self::Connecting>;
    fn local_addr(&self) -> IoResult<SocketAddr>;
    fn close(&self, error_code: VarInt, reason: &[u8]);
}

pub struct TokioQuinnConnecting(QuinnConnecting);

#[async_trait]
impl QuicConnectingLike for TokioQuinnConnecting {
    type Connection = WrappedQuinnConnection;

    async fn wait_for_connection(self) -> Result<Self::Connection, QuinnConnectionError> {
        self.0.await.map(WrappedQuinnConnection)
    }
    fn remote_address(&self) -> SocketAddr {
        self.0.remote_address()
    }
}

pub struct TokioQuinnEndpoint(QuinnEndpoint);

#[async_trait]
impl QuicEndpointLike for TokioQuinnEndpoint {
    type Connecting = TokioQuinnConnecting;
    type Connection = WrappedQuinnConnection;

    async fn accept(&self) -> Option<Self::Connecting> {
        self.0.accept().await.map(TokioQuinnConnecting) // Simpler map if From is implemented, or |c| TokioQuinnConnecting(c)
    }
    fn local_addr(&self) -> IoResult<SocketAddr> {
        self.0.local_addr()
    }
    fn close(&self, error_code: VarInt, reason: &[u8]) {
        self.0.close(error_code, reason)
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct QuicListener {
    name: String,
    bind: SocketAddr,
    tls: TlsServerConfig,
    #[serde(default = "default_bbr")]
    bbr: bool,
}

fn default_bbr() -> bool {
    true
}

pub fn from_value(value: &serde_yaml_ng::Value) -> Result<Box<dyn Listener>, Error> {
    let mut ret: QuicListener = serde_yaml_ng::from_value(value.clone()).context("parse config")?;
    ret.tls.init().context("Failed to initialize TlsServerConfig for QuicListener")?;
    Ok(Box::new(ret))
}

#[async_trait]
impl Listener for QuicListener {
    fn name(&self) -> &str {
        &self.name
    }
    async fn init(&mut self) -> Result<(), Error> {
        Ok(())
    }
    async fn listen(
        self: Arc<Self>,
        state: Arc<GlobalState>,
        queue: Sender<ContextRef>,
    ) -> Result<(), Error> {
        info!("{} listening on {}", self.name, self.bind);
        let server_config_quinn = create_quic_server(&self.tls)?;

        let quinn_endpoint = QuinnEndpoint::server(server_config_quinn, self.bind).context("quic_listen")?;
        let endpoint_wrapper = TokioQuinnEndpoint(quinn_endpoint);

        tokio::spawn(
            self.clone().accept_loop(endpoint_wrapper, state, queue)
        );
        Ok(())
    }
}
impl QuicListener {
    async fn accept_loop<E: QuicEndpointLike>(
        self: Arc<Self>,
        endpoint: E,
        state: Arc<GlobalState>,
        queue: Sender<ContextRef>,
    )
    {
        while let Some(connecting) = endpoint.accept().await {
            let source = crate::common::try_map_v4_addr(connecting.remote_address());
            debug!("{}: QUIC connecting from {:?}", self.name, source);

            match connecting.wait_for_connection().await {
                Ok(connection) => {
                    let this = self.clone();
                    let state_clone = state.clone();
                    let queue_clone = queue.clone();
                    tokio::spawn(this.client_thread(Arc::new(connection), source, state_clone, queue_clone));
                }
                Err(e) => {
                    warn!("{}, Connection error from {}: {}", self.name, source, e.to_string());
                }
            }
        }
        info!("{}: QUIC accept loop finished.", self.name);
    }

    async fn client_thread<C: QuicConnectionLike + 'static>(
        self: Arc<Self>,
        connection: Arc<C>,
        source: SocketAddr,
        state: Arc<GlobalState>,
        queue: Sender<ContextRef>,
    ) {
        let sessions = Arc::new(CHashMap::new());
        tokio::spawn(quic_frames_thread(
            self.name.to_owned(),
            sessions.clone(),
            connection.clone(),
        ));

        loop {
            match connection.accept_bi().await {
                Ok((send_stream_like, recv_stream_like)) => {
                    debug!("{}: BiStream accepted from {:?}", self.name, source);
                    let q_stream: QuicStream<C::SendStream, C::RecvStream> = QuicStream::new(send_stream_like, recv_stream_like);
                    let buffered_stream: IOBufStream = make_buffered_stream(q_stream);

                    let ctx = state
                        .contexts
                        .create_context(self.name.to_owned(), source)
                        .await;
                    ctx.write().await.set_client_stream(buffered_stream);

                    let this = self.clone();
                    let conn_clone_for_h11c = connection.clone();
                    let sessions_clone_for_h11c = sessions.clone();
                    let queue_clone_for_h11c = queue.clone();

                    tokio::spawn(async move {
                        if let Err(e) = h11c_handshake(ctx, queue_clone_for_h11c, |_ch, id| {
                            let conn_c = conn_clone_for_h11c.clone();
                            let sessions_c = sessions_clone_for_h11c.clone();
                            async move {
                                Ok(create_quic_frames(conn_c, id, sessions_c).await)
                            }
                        }).await {
                             warn!("{}: h11c handshake error from {}: {}: {:?}", this.name, source, e, e.source()); // Use e.source()
                        }
                    });
                }
                Err(e) => {
                    debug!("{}: Error accepting bi-stream from {}: {:?}", self.name, source, e);
                    break;
                }
            }
        }
        debug!("{}: client_thread for {} finished.", self.name, source);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::listeners::mocks::{MockQuicEndpoint, MockQuicConnecting};
    use crate::common::quic::tests::{MockQuicConnection, MockQuicSendStream, MockQuicRecvStream};
    use crate::config::context::Contexts as AppContexts;
    use std::sync::atomic::AtomicU32;
    use std::time::Duration;
    use crate::common::tls::TlsServerConfigExt;

    fn create_mock_global_state() -> Arc<GlobalState> {
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
    async fn test_quic_listener_client_thread_accepts_bi_stream() {
        let mut tls_cfg = TlsServerConfig::generate_self_signed("test.com").unwrap();
        tls_cfg.init().unwrap();
        let listener_config = Arc::new(QuicListener {
            name: "test_quic_listener".to_string(),
            bind: "0.0.0.0:0".parse().unwrap(),
            tls: tls_cfg,
            bbr: false,
        });

        let source_addr: SocketAddr = "1.2.3.4:12345".parse().unwrap();
        let mock_connection = Arc::new(MockQuicConnection::new(source_addr));

        let send_stream = MockQuicSendStream::new("q_send1");
        let recv_stream = MockQuicRecvStream::new("q_recv1");
        mock_connection.add_mock_bi_streams(send_stream, recv_stream);

        let mock_state = create_mock_global_state();
        let (queue_tx, _queue_rx) = tokio::sync::mpsc::channel::<ContextRef>(10);

        let client_thread_task = tokio::spawn(listener_config.clone().client_thread(
            mock_connection.clone(),
            source_addr,
            mock_state.clone(),
            queue_tx
        ));

        tokio::time::sleep(Duration::from_millis(100)).await;

        assert_eq!(mock_connection.mock_send_streams.lock().unwrap().len(), 0, "Mock send stream should have been consumed by accept_bi");
        assert_eq!(mock_connection.mock_recv_streams.lock().unwrap().len(), 0, "Mock recv stream should have been consumed by accept_bi");

        client_thread_task.abort();
    }

    #[tokio::test]
    async fn test_quic_listener_accept_loop_processes_connections() {
        let mut tls_cfg = TlsServerConfig::generate_self_signed("test.com").unwrap();
        tls_cfg.init().unwrap();
        let listener_config = Arc::new(QuicListener {
            name: "test_quic_accept_listener".to_string(),
            bind: "0.0.0.0:0".parse().unwrap(),
            tls: tls_cfg,
            bbr: false,
        });

        let mock_endpoint_addr: SocketAddr = "127.0.0.1:4433".parse().unwrap();
        let mock_endpoint = MockQuicEndpoint::new(mock_endpoint_addr);

        let conn1_source_addr: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let mock_conn1 = Arc::new(MockQuicConnection::new(conn1_source_addr));
        mock_conn1.add_mock_bi_streams(MockQuicSendStream::new("s1_send"), MockQuicRecvStream::new("s1_recv"));
        let connecting1 = MockQuicConnecting::new(conn1_source_addr, mock_conn1.clone());
        mock_endpoint.add_connecting(connecting1);

        let conn2_source_addr: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let mock_conn2 = Arc::new(MockQuicConnection::new(conn2_source_addr));
        mock_conn2.add_mock_bi_streams(MockQuicSendStream::new("s2_send"), MockQuicRecvStream::new("s2_recv"));
        let connecting2 = MockQuicConnecting::new(conn2_source_addr, mock_conn2.clone());
        mock_endpoint.add_connecting(connecting2);

        let mock_state = create_mock_global_state();
        let (queue_tx, _queue_rx) = tokio::sync::mpsc::channel::<ContextRef>(10);

        let listener_arc_clone = listener_config.clone();
        let accept_loop_task = tokio::spawn(async move {
            listener_arc_clone.accept_loop(mock_endpoint, mock_state, queue_tx).await;
        });

        match tokio::time::timeout(Duration::from_secs(1), accept_loop_task).await {
            Ok(Ok(_)) => { /* Task completed successfully */ },
            Ok(Err(e)) => panic!("accept_loop task resulted in an error: {:?}", e),
            Err(_) => panic!("accept_loop task timed out"),
        }

        assert_eq!(mock_conn1.mock_send_streams.lock().unwrap().len(), 0, "Mock send stream on conn1 should have been consumed");
        assert_eq!(mock_conn1.mock_recv_streams.lock().unwrap().len(), 0, "Mock recv stream on conn1 should have been consumed");

        assert_eq!(mock_conn2.mock_send_streams.lock().unwrap().len(), 0, "Mock send stream on conn2 should have been consumed");
        assert_eq!(mock_conn2.mock_recv_streams.lock().unwrap().len(), 0, "Mock recv stream on conn2 should have been consumed");
    }
}
