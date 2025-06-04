use async_trait::async_trait;
use bytes::Bytes;
use chashmap_async::CHashMap;
use easy_error::{Error, ResultExt}; // Removed err_msg as it's unused here
use quinn::{
    congestion,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
    ClientConfig, Connection, Endpoint, RecvStream, SendDatagramError, SendStream, ServerConfig,
    ReadDatagramError, // Assuming quinn::ReadDatagramError is correct
    WriteError, ConnectionError, ClosedStream,
};
use std::{
    convert::TryInto,
    io::{Error as IoError, ErrorKind, Result as IoResult},
    pin::Pin,
    sync::Arc,
    time::Duration,
    net::SocketAddr,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::mpsc::{channel, Receiver, Sender},
};
use tokio_rustls::rustls;

use super::{
    fragment::Fragments,
    frames::{Frame, FrameIO, FrameReader, FrameWriter},
    tls::{TlsClientConfig, TlsServerConfig},
};

#[async_trait]
pub trait QuicSendStreamLike: AsyncWrite + Send + Sync + Unpin {
    async fn finish(&mut self) -> Result<(), ClosedStream>;
}

#[async_trait]
pub trait QuicRecvStreamLike: AsyncRead + Send + Sync + Unpin {}

#[async_trait]
pub trait QuicConnectionLike: Send + Sync {
    type SendStream: QuicSendStreamLike + 'static;
    type RecvStream: QuicRecvStreamLike + 'static;

    async fn open_bi(&self) -> IoResult<(Self::SendStream, Self::RecvStream)>;
    async fn open_uni(&self) -> IoResult<Self::SendStream>;
    async fn accept_bi(&self) -> IoResult<(Self::SendStream, Self::RecvStream)>;
    async fn accept_uni(&self) -> IoResult<Self::RecvStream>;
    async fn send_datagram(&self, data: Bytes) -> Result<(), SendDatagramError>;
    async fn read_datagram(&self) -> Result<Bytes, ReadDatagramError>;
    fn max_datagram_size(&self) -> Option<usize>;
    fn close(&self, error_code: u32, reason: &[u8]);
    fn remote_address(&self) -> SocketAddr;
}

pub struct QuinnSendStream(pub SendStream);
#[async_trait]
impl QuicSendStreamLike for QuinnSendStream {
    async fn finish(&mut self) -> Result<(), ClosedStream> { self.0.finish() }
}
impl AsyncWrite for QuinnSendStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &[u8]) -> std::task::Poll<IoResult<usize>> { Pin::new(&mut self.0).poll_write(cx, buf).map_err(|e| IoError::new(ErrorKind::Other, e.to_string())) }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<IoResult<()>> { Pin::new(&mut self.0).poll_flush(cx).map_err(|e| IoError::new(ErrorKind::Other, e.to_string())) }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<IoResult<()>> { Pin::new(&mut self.0).poll_shutdown(cx).map_err(|e| IoError::new(ErrorKind::Other, e.to_string())) }
}

pub struct QuinnRecvStream(pub RecvStream);
#[async_trait]
impl QuicRecvStreamLike for QuinnRecvStream {}
impl AsyncRead for QuinnRecvStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> std::task::Poll<IoResult<()>> { Pin::new(&mut self.0).poll_read(cx, buf) }
}

pub struct QuinnConnection(pub Connection);
#[async_trait]
impl QuicConnectionLike for QuinnConnection {
    type SendStream = QuinnSendStream;
    type RecvStream = QuinnRecvStream;
    async fn open_bi(&self) -> IoResult<(Self::SendStream, Self::RecvStream)> { self.0.open_bi().await.map(|(s, r)| (QuinnSendStream(s), QuinnRecvStream(r))).map_err(|e| IoError::new(ErrorKind::Other, e.to_string())) }
    async fn open_uni(&self) -> IoResult<Self::SendStream> { self.0.open_uni().await.map(QuinnSendStream).map_err(|e| IoError::new(ErrorKind::Other, e.to_string())) }
    async fn accept_bi(&self) -> IoResult<(Self::SendStream, Self::RecvStream)> { self.0.accept_bi().await.map(|(s, r)| (QuinnSendStream(s), QuinnRecvStream(r))).map_err(|e| IoError::new(ErrorKind::Other, e.to_string())) }
    async fn accept_uni(&self) -> IoResult<Self::RecvStream> { self.0.accept_uni().await.map(QuinnRecvStream).map_err(|e| IoError::new(ErrorKind::Other, e.to_string())) }
    async fn send_datagram(&self, data: Bytes) -> Result<(), SendDatagramError> { self.0.send_datagram(data) }
    async fn read_datagram(&self) -> Result<Bytes, ReadDatagramError> { self.0.read_datagram().await }
    fn max_datagram_size(&self) -> Option<usize> { self.0.max_datagram_size() }
    fn close(&self, error_code: u32, reason: &[u8]) { self.0.close(error_code.into(), reason) }
    fn remote_address(&self) -> SocketAddr { self.0.remote_address() }
}

pub const ALPN_QUIC_HTTP11C: &[&[u8]] = &[b"h11c"];

pub fn create_quic_server(tls: &TlsServerConfig) -> Result<ServerConfig, Error> {
    let (certs, key) = tls.certs()?;
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("load certificate")?;
    server_crypto.alpn_protocols = ALPN_QUIC_HTTP11C.iter().map(|&x| x.into()).collect();
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_concurrent_uni_streams(0u8.into());
    transport_config.keep_alive_interval(Some(Duration::from_secs(30)));
    transport_config.max_idle_timeout(Some(Duration::from_secs(3600).try_into().unwrap()));
    let cfg_rustls: QuicServerConfig = server_crypto.try_into().context("failed to convert rustls::ServerConfig to quinn::ServerConfig")?;
    let mut server_cfg = ServerConfig::with_crypto(Arc::new(cfg_rustls));
    server_cfg.transport = Arc::new(transport_config);
    Ok(server_cfg)
}

pub fn create_quic_client(tls: &TlsClientConfig, enable_bbr: bool) -> Result<ClientConfig, Error> {
    let builder = rustls::ClientConfig::builder().with_root_certificates(tls.root_store()?);
    let mut client_crypto = if let Some(auth) = &tls.auth {
        let (certs, key) = auth.certs()?;
        builder.with_client_auth_cert(certs, key).context("load client certs")?
    } else {
        builder.with_no_client_auth()
    };
    client_crypto.alpn_protocols = ALPN_QUIC_HTTP11C.iter().map(|&x| x.into()).collect();
    if tls.insecure {
        client_crypto.dangerous().set_certificate_verifier(tls.insecure_verifier());
    }
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_concurrent_uni_streams(0u8.into());
    transport_config.keep_alive_interval(Some(Duration::from_secs(30)));
    transport_config.max_idle_timeout(Some(Duration::from_secs(3600).try_into().unwrap()));
    if enable_bbr {
        transport_config.congestion_controller_factory(Arc::new(congestion::BbrConfig::default()));
    }
    let client_cfg_rustls: QuicClientConfig = client_crypto.try_into().context("failed to convert rustls::ClientConfig to quinn::ClientConfig")?;
    let mut client_final_cfg = ClientConfig::new(Arc::new(client_cfg_rustls));
    client_final_cfg.transport_config(Arc::new(transport_config));
    Ok(client_final_cfg)
}

pin_project_lite::pin_project! {
    pub struct QuicStream<S: QuicSendStreamLike, R: QuicRecvStreamLike> {
        #[pin]
        pub read: R,
        #[pin]
        pub write: S,
    }
}

impl<S: QuicSendStreamLike, R: QuicRecvStreamLike> QuicStream<S, R> {
    pub fn new(send_stream: S, recv_stream: R) -> Self {
        Self { read: recv_stream, write: send_stream }
    }
}

impl<S: QuicSendStreamLike, R: QuicRecvStreamLike> AsyncRead for QuicStream<S, R> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> std::task::Poll<std::io::Result<()>> {
        self.project().read.poll_read(cx, buf)
    }
}

impl<S: QuicSendStreamLike, R: QuicRecvStreamLike> AsyncWrite for QuicStream<S, R> {
    fn poll_write(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &[u8]) -> std::task::Poll<Result<usize, std::io::Error>> {
        self.project().write.poll_write(cx, buf)
    }
    fn poll_flush(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), std::io::Error>> {
        self.project().write.poll_flush(cx)
    }
    fn poll_shutdown(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), std::io::Error>> {
        self.project().write.poll_shutdown(cx)
    }
}

pub async fn create_quic_frames<C: QuicConnectionLike + 'static>(
    conn: Arc<C>,
    id: u32,
    sessions: Arc<CHashMap<u32, Sender<Frame>>>,
) -> FrameIO {
    let (tx, rx) = channel(10);
    sessions.insert(id, tx).await;
    (QuicFrameReader::new(rx), QuicFrameWriter::new(conn, id))
}

struct QuicFrameReader { rx: Receiver<Frame> }
impl QuicFrameReader { fn new(rx: Receiver<Frame>) -> Box<Self> { Box::new(Self { rx }) } }
#[async_trait]
impl FrameReader for QuicFrameReader {
    async fn read(&mut self) -> IoResult<Option<Frame>> { Ok(self.rx.recv().await) }
}

struct QuicFrameWriter<C: QuicConnectionLike + 'static> {
    conn: Arc<C>,
    session_id: u32,
    frame_id: u16,
}
impl<C: QuicConnectionLike + 'static> QuicFrameWriter<C> {
    fn new(conn: Arc<C>, session_id: u32) -> Box<Self> { Box::new(Self { conn, session_id, frame_id: 0 }) }
}
#[async_trait]
impl<C: QuicConnectionLike + 'static> FrameWriter for QuicFrameWriter<C> {
    async fn write(&mut self, mut frame: Frame) -> IoResult<usize> {
        frame.session_id = self.session_id;
        let mtu = self.conn.max_datagram_size().ok_or_else(|| IoError::new(ErrorKind::Unsupported, "Datagram not allowed for this connection"))?;
        let fragments = Fragments::make_fragments(mtu, &mut self.frame_id, frame);
        let mut len = 0;
        for fragment in fragments {
            len += fragment.len();
            self.conn.send_datagram(fragment).await
                .map_err(|e| IoError::other(format!("SendDatagramError: {:?}", e)))?;
        }
        Ok(len)
    }
    async fn shutdown(&mut self) -> IoResult<()> { Ok(()) }
}

pub type QuicFrameSessions = Arc<CHashMap<u32, Sender<Frame>>>;

pub async fn quic_frames_thread<C: QuicConnectionLike + 'static>(
    name: String,
    sessions: QuicFrameSessions,
    input_conn: Arc<C>,
) {
    let mut f: Fragments<Frame> = Fragments::new(Duration::from_secs(5));
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    loop {
        let next_datagram = input_conn.read_datagram();
        tokio::select! {
            _ = interval.tick() => { f.timer() },
            datagram_result = next_datagram => {
                if let Err(e) = datagram_result {
                    tracing::warn!("{}: QUIC connection error reading datagram: {:?}", name, e);
                    break;
                }
                let datagram_bytes = datagram_result.unwrap();
                let frame_opt = f.reassemble(datagram_bytes);
                if frame_opt.is_none() { continue; }
                let frame = frame_opt.unwrap();
                let sid = frame.session_id;
                if let Some(session) = sessions.get(&sid).await {
                    if session.is_closed() || session.send(frame).await.is_err() {
                        drop(session);
                        sessions.remove(&sid).await;
                        tracing::trace!("quic recv error or closed session: sid={}", sid);
                    }
                }
            },
            else => break,
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};
    use tokio::io::{ReadBuf};
    use bytes::{BytesMut, BufMut};
    use crate::common::fragment::FRAGMENT_HEADER_SIZE; // Import for tests

    #[derive(Debug, Clone)]
    pub struct MockQuicSendStream {
        pub name: String,
        write_buffer: Arc<Mutex<Vec<u8>>>,
    }
    impl MockQuicSendStream {
        pub fn new(name: &str) -> Self { Self { name: name.to_string(), write_buffer: Arc::new(Mutex::new(Vec::new())) } }
        pub fn get_written_data(&self) -> Vec<u8> { self.write_buffer.lock().unwrap().clone() }
    }
    #[async_trait]
    impl QuicSendStreamLike for MockQuicSendStream { async fn finish(&mut self) -> Result<(), ClosedStream> { Ok(()) } }
    impl AsyncWrite for MockQuicSendStream {
        fn poll_write(self: Pin<&mut Self>, _cx: &mut std::task::Context<'_>, buf: &[u8]) -> std::task::Poll<IoResult<usize>> { self.write_buffer.lock().unwrap().extend_from_slice(buf); std::task::Poll::Ready(Ok(buf.len())) }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> std::task::Poll<IoResult<()>> { std::task::Poll::Ready(Ok(())) }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> std::task::Poll<IoResult<()>> { std::task::Poll::Ready(Ok(())) }
    }

    #[derive(Debug, Clone)]
    pub struct MockQuicRecvStream {
        pub name: String,
        read_buffer: Arc<Mutex<VecDeque<Bytes>>>,
    }
    impl MockQuicRecvStream {
        pub fn new(name: &str) -> Self { Self { name: name.to_string(), read_buffer: Arc::new(Mutex::new(VecDeque::new())) } }
        pub fn add_read_data(&self, data: Bytes) { self.read_buffer.lock().unwrap().push_back(data); }
    }
    #[async_trait]
    impl QuicRecvStreamLike for MockQuicRecvStream {}
    impl AsyncRead for MockQuicRecvStream {
        fn poll_read(self: Pin<&mut Self>, _cx: &mut std::task::Context<'_>, buf: &mut ReadBuf<'_>) -> std::task::Poll<IoResult<()>> {
            let mut buffer_guard = self.read_buffer.lock().unwrap();
            if let Some(front_bytes) = buffer_guard.front_mut() {
                let available = front_bytes.len();
                let to_read = std::cmp::min(available, buf.remaining());
                buf.put_slice(&front_bytes[..to_read]);
                if to_read == available { buffer_guard.pop_front(); } else { *front_bytes = front_bytes.split_off(to_read); }
                std::task::Poll::Ready(Ok(()))
            } else { std::task::Poll::Ready(Ok(())) }
        }
    }

    #[derive(Debug, Clone)]
    pub struct MockQuicConnection {
        pub remote_addr: SocketAddr,
        datagram_recv_buffer: Arc<Mutex<VecDeque<Bytes>>>,
        datagram_send_buffer: Arc<Mutex<Vec<Bytes>>>,
        pub mock_send_streams: Arc<Mutex<VecDeque<MockQuicSendStream>>>,
        pub mock_recv_streams: Arc<Mutex<VecDeque<MockQuicRecvStream>>>,
        max_datagram_payload_size_val: Arc<Mutex<Option<usize>>>,
        next_send_datagram_error: Arc<Mutex<Option<SendDatagramError>>>,
        next_read_datagram_error: Arc<Mutex<Option<ReadDatagramError>>>,
    }
    impl MockQuicConnection {
        pub fn new(remote_addr: SocketAddr) -> Self {
            Self {
                remote_addr,
                datagram_recv_buffer: Arc::new(Mutex::new(VecDeque::new())),
                datagram_send_buffer: Arc::new(Mutex::new(Vec::new())),
                mock_send_streams: Arc::new(Mutex::new(VecDeque::new())),
                mock_recv_streams: Arc::new(Mutex::new(VecDeque::new())),
                max_datagram_payload_size_val: Arc::new(Mutex::new(Some(1200))),
                next_send_datagram_error: Arc::new(Mutex::new(None)),
                next_read_datagram_error: Arc::new(Mutex::new(None)),
            }
        }
        pub fn add_datagram_to_recv(&self, data: Bytes) { self.datagram_recv_buffer.lock().unwrap().push_back(data); }
        pub fn get_sent_datagrams(&self) -> Vec<Bytes> { self.datagram_send_buffer.lock().unwrap().clone() }
        pub fn add_mock_bi_streams(&self, send_stream: MockQuicSendStream, recv_stream: MockQuicRecvStream) {
            self.mock_send_streams.lock().unwrap().push_back(send_stream);
            self.mock_recv_streams.lock().unwrap().push_back(recv_stream);
        }
        pub fn set_max_datagram_size(&self, size: Option<usize>) { *self.max_datagram_payload_size_val.lock().unwrap() = size; }
        pub fn set_next_send_datagram_error(&self, err: Option<SendDatagramError>) { *self.next_send_datagram_error.lock().unwrap() = err; }
        pub fn set_next_read_datagram_error(&self, err: Option<ReadDatagramError>) { *self.next_read_datagram_error.lock().unwrap() = err; }
    }
    #[async_trait]
    impl QuicConnectionLike for MockQuicConnection {
        type SendStream = MockQuicSendStream;
        type RecvStream = MockQuicRecvStream;
        async fn open_bi(&self) -> IoResult<(Self::SendStream, Self::RecvStream)> {
            let mut send_streams_guard = self.mock_send_streams.lock().unwrap();
            let mut recv_streams_guard = self.mock_recv_streams.lock().unwrap();
            if let (Some(send_stream), Some(recv_stream)) = (send_streams_guard.pop_front(), recv_streams_guard.pop_front()) { Ok((send_stream, recv_stream)) }
            else { Ok((MockQuicSendStream::new("default_bi_send"), MockQuicRecvStream::new("default_bi_recv"))) }
        }
        async fn open_uni(&self) -> IoResult<Self::SendStream> { Ok(MockQuicSendStream::new("default_uni_send")) }
        async fn accept_bi(&self) -> IoResult<(Self::SendStream, Self::RecvStream)> { self.open_bi().await }
        async fn accept_uni(&self) -> IoResult<Self::RecvStream> { Ok(MockQuicRecvStream::new("default_uni_recv")) }
        async fn send_datagram(&self, data: Bytes) -> Result<(), SendDatagramError> {
            if let Some(err) = self.next_send_datagram_error.lock().unwrap().take() { return Err(err); }
            self.datagram_send_buffer.lock().unwrap().push(data); Ok(())
        }
        async fn read_datagram(&self) -> Result<Bytes, ReadDatagramError> {
            if let Some(err) = self.next_read_datagram_error.lock().unwrap().take() { return Err(err); }
            if let Some(data) = self.datagram_recv_buffer.lock().unwrap().pop_front() { Ok(data) }
            else { Err(ReadDatagramError::ConnectionLost("MockConnection: No more datagrams in buffer".into())) }
        }
        fn max_datagram_size(&self) -> Option<usize> { *self.max_datagram_payload_size_val.lock().unwrap() }
        fn close(&self, _error_code: u32, _reason: &[u8]) { /* no-op */ }
        fn remote_address(&self) -> SocketAddr { self.remote_addr }
    }

    #[test] fn test_mock_quic_send_stream_poll_write() { /* ... */ }
    #[test] fn test_mock_quic_recv_stream_poll_read() { /* ... */ }
    #[tokio::test] async fn test_quic_frame_writer_write_single_fragment() { /* ... */ }
    #[tokio::test] async fn test_quic_frame_writer_write_multiple_fragments() { /* ... */ }
    #[tokio::test] async fn test_quic_stream_read_write() { /* ... */ }
    #[tokio::test] async fn test_create_quic_frames_setup_and_write() { /* ... */ }
    #[tokio::test] async fn test_quic_frames_thread_reassembly_and_dispatch() { /* ... */ }
    #[tokio::test] async fn test_quic_frame_writer_send_datagram_error() { /* ... */ }
    #[tokio::test] async fn test_quic_frame_writer_no_max_datagram_size() { /* ... */ }
    #[tokio::test] async fn test_quic_frames_thread_read_datagram_error() { /* ... */ }
}
