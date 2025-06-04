use async_trait::async_trait;
use easy_error::{bail, Error, ResultExt};
use serde::{Deserialize, Serialize};
use std::io::Result as IoResult;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::Sender;
use tracing::{error, info, warn};

use crate::common::h11c::h11c_handshake;
use crate::common::set_keepalive;
use crate::common::tls::TlsServerConfig;
use crate::context::{make_buffered_stream, ContextRef, IOStream, IOBufStream};
use crate::listeners::Listener;
use crate::GlobalState;

#[async_trait]
pub trait TcpListenerLike: Send + Sync + 'static {
    type Stream: AsyncRead + AsyncWrite + Send + Unpin + Sync + 'static;

    async fn accept(&self) -> IoResult<(Self::Stream, SocketAddr)>;
    fn local_addr(&self) -> IoResult<SocketAddr>;
}

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
pub struct HttpListener {
    name: String,
    bind: SocketAddr,
    tls: Option<TlsServerConfig>,
}

pub fn from_value(value: &serde_yaml_ng::Value) -> Result<Box<dyn Listener>, Error> {
    let mut ret: HttpListener = serde_yaml_ng::from_value(value.clone()).context("parse config")?;
    if let Some(tls_cfg) = ret.tls.as_mut(){
        tls_cfg.init().context("Failed to initialize TlsServerConfig for HttpListener")?;
    }
    Ok(Box::new(ret))
}

#[async_trait]
impl Listener for HttpListener {
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
        let listener = TokioTcpListener(TcpListener::bind(&self.bind).await.context("bind")?);
        let this = self.clone();
        tokio::spawn(this.accept_loop(listener, state, queue));
        Ok(())
    }
}
impl HttpListener {
    async fn accept_loop<L: TcpListenerLike>(
        self: Arc<Self>,
        listener: L,
        state: Arc<GlobalState>,
        queue: Sender<ContextRef>,
    ) where <L as TcpListenerLike>::Stream : Sync
    {
        loop {
            match listener.accept().await.context("accept") {
                Ok((socket, source)) => {
                    let this = self.clone();
                    let queue_clone = queue.clone();
                    let state_clone = state.clone();
                    let source = crate::common::try_map_v4_addr(source);
                    tokio::spawn(async move {
                        let res = match this.create_context(state_clone, source, socket).await {
                            Ok(ctx) => {
                                h11c_handshake(ctx, queue_clone, |_, _| async { bail!("h11c frame_io_factory not supported in HttpListener") })
                                    .await
                            }
                            Err(e) => Err(e),
                        };
                        if let Err(e) = res {
                            warn!(
                                "{}: handshake failed: {}\ncause: {:?}",
                                this.name, e, e.cause
                            );
                        }
                    });
                }
                Err(e) => {
                    error!("{} accept error: {} \ncause: {:?}", self.name, e, e.cause);
                    return;
                }
            }
        }
    }

    async fn create_context<S: AsyncRead + AsyncWrite + Send + Unpin + Sync + 'static>(
        &self,
        state: Arc<GlobalState>,
        source: SocketAddr,
        socket: S,
    ) -> Result<ContextRef, Error> {

        let client_io_stream: IOBufStream = if let Some(tls_options) = &self.tls {
            let acceptor = tls_options.acceptor();
            let tls_stream = acceptor.accept(socket).await.context("tls accept error")?;
            make_buffered_stream(tls_stream)
        } else {
            make_buffered_stream(socket)
        };
        let ctx = state
            .contexts
            .create_context(self.name.to_owned(), source)
            .await;
        ctx.write().await.set_client_stream(client_io_stream);
        Ok(ctx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::listeners::mocks::{MockTcpListener, MockTcpStream};
    use crate::config::context::Contexts as AppContexts;
    use std::sync::atomic::AtomicU32;
    use bytes::Bytes;
    use crate::common::tls::TlsServerConfigExt; // For generate_self_signed

    fn create_mock_global_state() -> Arc<GlobalState> {
        Arc::new(GlobalState {
            contexts: Arc::new(AppContexts::new(1024, Arc::new(AtomicU32::new(0)))),
            rules: Default::default(),
            connectors: Default::default(),
            metrics: Default::default(),
            io_params: Default::default(),
            // dns_resolver, geoip_db, transports, listeners, udp_capacity, timeouts, hostname
            // are not strictly needed for these specific listener context creation tests if not used by them.
            // For a more complete mock GlobalState, they would be initialized appropriately.
            // The GlobalState struct definition has changed. The following are not direct fields anymore.
            // dns_resolver: Arc::new(crate::common::dns::create_resolver(None, false).unwrap()),
            // geoip_db: Default::default(),
            // transports: Default::default(),
            listeners: Default::default(), // This is still a field
            // udp_capacity: 0,
            // timeouts: Default::default(),
            // hostname: "test_host".to_string(),
            #[cfg(feature = "dashboard")] web_ui_port: None,
            #[cfg(feature = "dashboard")] web_ui_path: None,
            #[cfg(feature = "api")] api_port: None,
            #[cfg(feature = "api")] external_controller: None,
        })
    }

    #[tokio::test]
    async fn test_http_create_context_no_tls() {
        let listener_config = HttpListener {
            name: "test_http_listener".to_string(),
            bind: "0.0.0.0:0".parse().unwrap(),
            tls: None,
        };

        let mock_state = create_mock_global_state();
        let source_addr: SocketAddr = "1.2.3.4:12345".parse().unwrap();
        let mock_stream = MockTcpStream::new("test_stream");

        let result = listener_config.create_context(mock_state.clone(), source_addr, mock_stream.clone()).await;
        assert!(result.is_ok(), "create_context failed: {:?}", result.err());
        let ctx_ref = result.unwrap();

        let ctx_read = ctx_ref.read().await;
        assert_eq!(ctx_read.props().source, source_addr, "Source address mismatch");
        assert_eq!(ctx_read.props().listener, "test_http_listener", "Listener name mismatch");
        assert!(ctx_read.client_stream_is_some(), "Client stream was not set");
    }

    #[tokio::test]
    async fn test_http_create_context_with_tls() {
        let mut tls_config = TlsServerConfig::generate_self_signed("test.com")
            .expect("Failed to generate self-signed cert for test");
        tls_config.init().expect("Failed to init TlsServerConfig");

        let listener_config = HttpListener {
            name: "test_http_tls_listener".to_string(),
            bind: "0.0.0.0:0".parse().unwrap(),
            tls: Some(tls_config),
        };

        let mock_state = create_mock_global_state();
        let source_addr: SocketAddr = "1.2.3.5:12345".parse().unwrap();
        let mock_stream = MockTcpStream::new("test_tls_stream");

        mock_stream.add_read_data(Bytes::from_static(&[
             0x16, 0x03, 0x01, 0x00, 0x5f, 0x01, 0x00, 0x00, 0x5b,
             0x03, 0x03,  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
             0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
             0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
             0x00, 0x00, 0x02, 0xc0, 0x2b,  0x01, 0x00,  0x00, 0x2e,
             0x00, 0x00, 0x00, 0x09, 0x00, 0x07, 0x00,  0x00, 0x04,
             0x74, 0x65, 0x73, 0x74,
        ]));


        let result = listener_config.create_context(mock_state.clone(), source_addr, mock_stream.clone()).await;

        assert!(result.is_ok(), "create_context with TLS failed: {:?}", result.err());
        let ctx_ref = result.unwrap();

        let ctx_read = ctx_ref.read().await;
        assert_eq!(ctx_read.props().source, source_addr);
        assert_eq!(ctx_read.props().listener, "test_http_tls_listener");
        assert!(ctx_read.client_stream_is_some(), "Client stream was not set with TLS");
    }

    #[tokio::test]
    async fn test_http_accept_loop_processes_connections() {
        let listener_config = Arc::new(HttpListener {
            name: "test_http_accept_listener".to_string(),
            bind: "0.0.0.0:0".parse().unwrap(),
            tls: None,
        });

        let mock_tcp_listener = MockTcpListener::new("0.0.0.0:0".parse().unwrap());
        let source_addr1: SocketAddr = "1.2.3.4:1111".parse().unwrap();
        let source_addr2: SocketAddr = "1.2.3.4:2222".parse().unwrap();
        mock_tcp_listener.add_connection(MockTcpStream::new("stream1"), source_addr1);
        mock_tcp_listener.add_connection(MockTcpStream::new("stream2"), source_addr2);

        let mock_state = create_mock_global_state();
        let (queue_tx, mut queue_rx) = tokio::sync::mpsc::channel::<ContextRef>(10);

        let listener_arc_clone = listener_config.clone();
        let accept_task = tokio::spawn(async move {
            listener_arc_clone.accept_loop(mock_tcp_listener, mock_state, queue_tx).await;
        });

        match tokio::time::timeout(std::time::Duration::from_secs(1), accept_task).await {
            Ok(Ok(_)) => { /* Task completed successfully */ },
            Ok(Err(e)) => panic!("accept_loop task resulted in an error: {:?}", e),
            Err(_) => panic!("accept_loop task timed out"),
        }

        match tokio::time::timeout(std::time::Duration::from_millis(50), queue_rx.recv()).await {
            Ok(Some(_ctx)) => panic!("Expected no context to be enqueued for basic HTTP listener due to h11c error"),
            Ok(None) => { /* Channel closed, correct */ }
            Err(_) => { /* Timeout, correct, no item received */ }
        }
    }
}
