use async_trait::async_trait;
use chashmap_async::CHashMap;
use easy_error::{Error, ResultExt};
use futures_util::TryFutureExt;
use quinn::{congestion, Connection as QuinnConnection, Connecting as QuinnConnecting, Endpoint as QuinnEndpoint, ServerConfig as QuinnServerConfig};
use serde::{Deserialize, Serialize};
use std::io::Result as IoResult;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc::Sender;
use tracing::{debug, info, warn};

use crate::common::h11c::h11c_handshake;
use crate::common::quic::{
    create_quic_frames, create_quic_server, quic_frames_thread, QuicConnectionLike,
    QuicStream, QuinnConnection as WrappedQuinnConnection, // Use the wrapper from common
};
use crate::common::tls::TlsServerConfig;
use crate::context::{make_buffered_stream, ContextRef};
use crate::listeners::Listener;
use crate::GlobalState;


// --- Testability Traits for Quinn Components ---

#[async_trait]
pub trait QuicConnectingLike: Send + Sync + 'static {
    // Use the trait from common::quic
    type Connection: QuicConnectionLike + Send + Sync + 'static;
    async fn wait_for_connection(self) -> Result<Self::Connection, quinn::ConnectionError>; // Changed from await_connection to avoid keyword
    fn remote_address(&self) -> SocketAddr;
}

#[async_trait]
pub trait QuicEndpointLike: Send + Sync + 'static {
    type Connecting: QuicConnectingLike<Connection = Self::Connection>;
    // Use the trait from common::quic for Self::Connection
    type Connection: QuicConnectionLike + Send + Sync + 'static;


    async fn accept(&self) -> Option<Self::Connecting>;
    fn local_addr(&self) -> IoResult<SocketAddr>; // Added for consistency if needed
    fn close(&self, error_code: quinn::VarInt, reason: &[u8]);
}

// --- Wrappers for real Quinn Types ---

pub struct TokioQuinnConnecting(QuinnConnecting);

#[async_trait]
impl QuicConnectingLike for TokioQuinnConnecting {
    type Connection = WrappedQuinnConnection; // Use the wrapper from common

    async fn wait_for_connection(self) -> Result<Self::Connection, quinn::ConnectionError> {
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
    type Connection = WrappedQuinnConnection; // Use the wrapper from common

    async fn accept(&self) -> Option<Self::Connecting> {
        self.0.accept().await.map(TokioQuinnConnecting)
    }
    fn local_addr(&self) -> IoResult<SocketAddr> {
        self.0.local_addr().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }
    fn close(&self, error_code: quinn::VarInt, reason: &[u8]) {
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
    let ret: QuicListener = serde_yaml_ng::from_value(value.clone()).context("parse config")?;
    Ok(Box::new(ret))
}

#[async_trait]
impl Listener for QuicListener {
    fn name(&self) -> &str {
        &self.name
    }
    async fn init(&mut self) -> Result<(), Error> {
        self.tls.init()?;
        Ok(())
    }
    async fn listen(
        self: Arc<Self>,
        state: Arc<GlobalState>,
        queue: Sender<ContextRef>,
    ) -> Result<(), Error> {
        info!("{} listening on {}", self.name, self.bind);
        let mut server_config = create_quic_server(&self.tls)?;
        if self.bbr {
            let transport = Arc::get_mut(&mut server_config.transport).unwrap();
            transport.congestion_controller_factory(Arc::new(congestion::BbrConfig::default()));
        }
        // QuinnEndpoint is the concrete type from quinn crate
        let quinn_endpoint = QuinnEndpoint::server(server_config, self.bind).context("quic_listen")?;
        let endpoint = TokioQuinnEndpoint(quinn_endpoint);

        tokio::spawn(
            self.accept_loop(endpoint, state, queue)
                // .unwrap_or_else(|e| panic!("{}: {:?}", e, e.cause)), // accept_loop Result is () if it ends gracefully
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
    ) { // Changed Result<(), Error> to () as errors are handled internally or cause panic/log
        while let Some(connecting) = endpoint.accept().await {
            let source = crate::common::try_map_v4_addr(connecting.remote_address());
            debug!("{}: QUIC connecting from {:?}", self.name, source);

            match connecting.wait_for_connection().await {
                Ok(connection) => {
                    let this = self.clone();
                    let state_clone = state.clone(); // Use a different name to avoid conflict
                    let queue_clone = queue.clone(); // Use a different name
                    // Spawn a task to handle this connection
                    tokio::spawn(this.client_thread(Arc::new(connection), source, state_clone, queue_clone));
                }
                Err(e) => {
                    warn!("{}, Connection error from {}: {}: cause: {:?}", self.name, source, e, e.cause);
                }
            }
        }
        // If the loop exits, it means the endpoint was likely closed or encountered a non-recoverable error.
        info!("{}: QUIC accept loop finished.", self.name);
    }

    async fn client_thread<C: QuicConnectionLike + 'static>(
        self: Arc<Self>,
        connection: Arc<C>, // Now Arc<C> where C: QuicConnectionLike
        source: SocketAddr,
        state: Arc<GlobalState>,
        queue: Sender<ContextRef>,
    ) {
        let sessions = Arc::new(CHashMap::new());
        // quic_frames_thread expects Arc<QuinnConnection>, now Arc<C: QuicConnectionLike>
        // This was already refactored in common/quic.rs to take Arc<C: QuicConnectionLike>
        tokio::spawn(quic_frames_thread(
            self.name.to_owned(),
            sessions.clone(),
            connection.clone(),
        ));

        // connection.accept_bi() needs to be called on C: QuicConnectionLike
        loop {
            match connection.accept_bi().await {
                Ok((send_stream, recv_stream)) => {
                    debug!("{}: BiStream accepted from {:?}", self.name, source);
                    // QuicStream::new expects QuicSendStreamLike and QuicRecvStreamLike
                    // These come from C::SendStream and C::RecvStream associated types
                    let q_stream = QuicStream::new(send_stream, recv_stream);
                    let buffered_stream = make_buffered_stream(q_stream); // make_buffered_stream takes S: AsyncRead + AsyncWrite + ...

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
                        if let Err(e) = h11c_handshake(ctx, queue_clone_for_h11c, |_ch, id| async move {
                            // create_quic_frames expects Arc<C: QuicConnectionLike>
                            Ok(create_quic_frames(conn_clone_for_h11c, id, sessions_clone_for_h11c).await)
                        }).await {
                             warn!("{}: h11c handshake error from {}: {}: {:?}", this.name, source, e, e.cause);
                        }
                    });
                }
                Err(e) => {
                    debug!("{}: Error accepting bi-stream from {}: {:?}", self.name, source, e);
                    // This error might mean the connection is closing or closed.
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
    use crate::config::Contexts;
    use std::sync::atomic::AtomicU32;
    use tokio::sync::mpsc;
    use std::time::Duration;

    // Helper from other listener tests
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
    async fn test_quic_listener_client_thread_accepts_bi_stream() {
        let listener_config = Arc::new(QuicListener {
            name: "test_quic_listener".to_string(),
            bind: "0.0.0.0:0".parse().unwrap(), // Not directly used by client_thread
            tls: TlsServerConfig::generate_self_signed("test.com").unwrap(), // Needed for create_quic_server if called, but not directly by client_thread's core path
            bbr: false,
        });

        let source_addr: SocketAddr = "1.2.3.4:12345".parse().unwrap();
        let mock_connection = Arc::new(MockQuicConnection::new(source_addr));

        // Setup mock connection to return one bi-stream pair
        let send_stream = MockQuicSendStream::new("q_send1");
        let recv_stream = MockQuicRecvStream::new("q_recv1");
        mock_connection.add_mock_bi_streams(send_stream, recv_stream);
        // After this, accept_bi will return Ok once, then subsequent calls will get new default streams from the mock.
        // To make it terminate, the mock_connection's accept_bi should eventually signal closure,
        // e.g. by returning an error after the pre-configured streams are exhausted.
        // The current MockQuicConnection::open_bi (used by accept_bi) returns new default streams if queue is empty.
        // For this test, we only care about one stream being processed.

        let mock_state = create_mock_global_state();
        // The queue here is the main one for ContextRefs to go to the router.
        // h11c_handshake for QUIC sets up FrameIO using create_quic_frames.
        // If h11c_handshake were to succeed and queue a ContextRef, we'd check queue_rx.
        // However, the h11c_handshake in QuicListener is for HTTP/1.1 CONNECT style proxying over QUIC.
        // It creates a new context, sets client stream, and then calls h11c_handshake.
        // The h11c_handshake itself takes a queue.
        let (queue_tx, mut queue_rx) = mpsc::channel::<ContextRef>(10);


        let client_thread_task = tokio::spawn(listener_config.clone().client_thread(
            mock_connection.clone(),
            source_addr,
            mock_state.clone(),
            queue_tx
        ));

        // How to verify client_thread behavior?
        // 1. It spawns quic_frames_thread (hard to check directly).
        // 2. It loops on connection.accept_bi().
        // 3. For each accepted stream, it creates a context and spawns h11c_handshake.
        //    - h11c_handshake's callback `create_quic_frames` uses `connection.send_datagram`.
        //    - We can check if any datagrams were sent as a side effect of setting up FrameIO.
        //      (create_quic_frames doesn't send datagrams, QuicFrameWriter does when writing).

        // Let's give some time for the client_thread to run and accept the one stream.
        // The loop in client_thread will call accept_bi(), get the one stream, spawn h11c_handshake.
        // Then it will call accept_bi() again, get default streams, spawn another h11c_handshake.
        // This will continue indefinitely. The test needs a way to make accept_bi() fail to stop the loop.

        // For now, let's check that the first stream was processed by h11c_handshake.
        // One indirect way: h11c_handshake creates a Context. If it were to enqueue it, we could check the queue.
        // In QuicListener, h11c_handshake is given the main `queue_tx`.
        // The `frame_io_factory` for h11c in QuicListener is `create_quic_frames`.
        // `h11c_handshake` itself will enqueue the context if the HTTP handshake part is successful.
        // For a CONNECT request, it would expect a CONNECT request on the QuicStream.

        // Let's simplify: ensure accept_bi was called.
        // The mock_send_streams queue in MockQuicConnection will be empty if streams were taken.
        // This is an indirect way to see if accept_bi was successfully called.
        // Wait a bit for the thread to process the stream.
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Check if the mock streams were taken by accept_bi
        // This requires MockQuicConnection's stream queues to be accessible or have a method.
        // They are Mutex-wrapped, so direct check is not clean.
        // Let's assume if a context for the handshake is created and potentially queued, that's a good sign.

        // If a CONNECT request was sent on the mock QuicStream (by a test client), then h11c_handshake would succeed
        // and enqueue the context. Since we don't simulate a client sending CONNECT,
        // the context created by client_thread will be passed to h11c_handshake,
        // but h11c_handshake will time out or fail reading the request, so it won't enqueue.

        // The goal is to test if client_thread is wired correctly to use QuicConnectionLike.
        // The fact that it calls accept_bi() is the main check.
        // If the pre-added stream is consumed, that's a good sign.
        // MockQuicConnection.mock_send_streams is Arc<Mutex<VecDeque<MockQuicSendStream>>>
        // So we can check its length.
        assert_eq!(mock_connection.mock_send_streams.lock().unwrap().len(), 0, "Mock send stream should have been consumed by accept_bi");
        assert_eq!(mock_connection.mock_recv_streams.lock().unwrap().len(), 0, "Mock recv stream should have been consumed by accept_bi");


        // To gracefully stop client_thread, we'd need mock_connection.accept_bi() to eventually return Err.
        // The current mock returns new default streams.
        // We can abort the task for cleanup.
        client_thread_task.abort();
    }

    // TODO: Test for QuicListener::accept_loop (More comprehensive version)

    #[tokio::test]
    async fn test_quic_listener_accept_loop_processes_connections() {
        let listener_config = Arc::new(QuicListener {
            name: "test_quic_accept_listener".to_string(),
            bind: "0.0.0.0:0".parse().unwrap(),
            tls: TlsServerConfig::generate_self_signed("test.com").unwrap(),
            bbr: false,
        });

        let mock_endpoint_addr: SocketAddr = "127.0.0.1:4433".parse().unwrap();
        let mock_endpoint = MockQuicEndpoint::new(mock_endpoint_addr);

        // Connection 1
        let conn1_source_addr: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let mock_conn1 = Arc::new(MockQuicConnection::new(conn1_source_addr));
        mock_conn1.add_mock_bi_streams(MockQuicSendStream::new("s1_send"), MockQuicRecvStream::new("s1_recv"));
        let connecting1 = MockQuicConnecting::new(conn1_source_addr, mock_conn1.clone());
        mock_endpoint.add_connecting(connecting1);

        // Connection 2
        let conn2_source_addr: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let mock_conn2 = Arc::new(MockQuicConnection::new(conn2_source_addr));
        mock_conn2.add_mock_bi_streams(MockQuicSendStream::new("s2_send"), MockQuicRecvStream::new("s2_recv"));
        let connecting2 = MockQuicConnecting::new(conn2_source_addr, mock_conn2.clone());
        mock_endpoint.add_connecting(connecting2);

        let mock_state = create_mock_global_state();
        let (queue_tx, _queue_rx) = mpsc::channel::<ContextRef>(10); // Not checking queue for this test, focus on accept_loop mechanics

        let listener_arc_clone = listener_config.clone();
        let accept_loop_task = tokio::spawn(async move {
            listener_arc_clone.accept_loop(mock_endpoint, mock_state, queue_tx).await;
        });

        // Wait for the accept_loop to finish. It finishes when mock_endpoint.accept() returns None.
        match tokio::time::timeout(Duration::from_secs(1), accept_loop_task).await {
            Ok(Ok(_)) => { /* Task completed successfully */ },
            Ok(Err(e)) => panic!("accept_loop task resulted in an error: {:?}", e),
            Err(_) => panic!("accept_loop task timed out"),
        }

        // Verify that client_thread was invoked for each connection,
        // by checking if the bi-streams were consumed from each MockQuicConnection.
        assert_eq!(mock_conn1.mock_send_streams.lock().unwrap().len(), 0, "Mock send stream on conn1 should have been consumed");
        assert_eq!(mock_conn1.mock_recv_streams.lock().unwrap().len(), 0, "Mock recv stream on conn1 should have been consumed");

        assert_eq!(mock_conn2.mock_send_streams.lock().unwrap().len(), 0, "Mock send stream on conn2 should have been consumed");
        assert_eq!(mock_conn2.mock_recv_streams.lock().unwrap().len(), 0, "Mock recv stream on conn2 should have been consumed");
    }

    // Note: The test_quic_listener_client_thread_accepts_bi_stream was already added in a previous step.
    // I will verify its content and ensure it's robust.
    // The previous version of this test was:
    // #[tokio::test]
    // async fn test_quic_listener_client_thread_accepts_bi_stream() {
    //     let listener_config = Arc::new(QuicListener { /* ... */ });
    //     let mock_connection = Arc::new(MockQuicConnection::new(source_addr));
    //     mock_connection.add_mock_bi_streams(send_stream, recv_stream);
    //     /* ... spawn client_thread ... */
    //     tokio::time::sleep(Duration::from_millis(100)).await;
    //     assert_eq!(mock_connection.mock_send_streams.lock().unwrap().len(), 0);
    //     client_thread_task.abort();
    // }
    // This test is reasonable for checking accept_bi.
    // No new test for client_thread is strictly needed unless we want to test more complex scenarios
    // like interactions within h11c_handshake via the provided streams.
    // For now, the existing test for client_thread (checking stream consumption) is a good start.
}
