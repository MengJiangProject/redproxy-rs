use std::{pin::Pin, sync::Arc};

use async_trait::async_trait;
use chashmap::CHashMap;
use easy_error::{Error, ResultExt};
use futures::StreamExt;
use quinn::{ClientConfig, Connection, Datagrams, RecvStream, SendStream, ServerConfig};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::mpsc::{channel, Receiver, Sender},
};
use tokio_rustls::rustls;

use super::{
    frames::{Frame, FrameReader, FrameWriter, Frames},
    tls::{TlsClientConfig, TlsServerConfig},
};

pub const ALPN_QUIC_HTTP11C: &[&[u8]] = &[b"h11c"]; //this is not regular HTTP3 connection, it uses HTTP1.1 CONNECT instead.

pub fn create_quic_server(tls: &TlsServerConfig) -> Result<ServerConfig, Error> {
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_concurrent_uni_streams(0u8.into());

    let (certs, key) = tls.certs()?;

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("load certificate")?;
    server_crypto.alpn_protocols = ALPN_QUIC_HTTP11C.iter().map(|&x| x.into()).collect();

    let mut cfg = ServerConfig::with_crypto(Arc::new(server_crypto));
    cfg.transport = Arc::new(transport_config);
    Ok(cfg)
}

pub fn create_quic_client(tls: &TlsClientConfig) -> Result<ClientConfig, Error> {
    let builder = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(tls.root_store()?);

    let mut client_crypto = if let Some(auth) = &tls.auth {
        let (certs, key) = auth.certs()?;
        builder
            .with_single_cert(certs, key)
            .context("load client certs")?
    } else {
        builder.with_no_client_auth()
    };

    client_crypto.alpn_protocols = ALPN_QUIC_HTTP11C.iter().map(|&x| x.into()).collect();

    if tls.insecure {
        client_crypto
            .dangerous()
            .set_certificate_verifier(tls.insecure_verifier());
    }
    let cfg = ClientConfig::new(Arc::new(client_crypto));
    Ok(cfg)
}

pin_project_lite::pin_project! {
    pub struct QuicStream {
        #[pin]
        pub read: RecvStream,
        #[pin]
        pub write: SendStream,
    }
}

impl From<(RecvStream, SendStream)> for QuicStream {
    fn from((read, write): (RecvStream, SendStream)) -> Self {
        Self { read, write }
    }
}

impl From<(SendStream, RecvStream)> for QuicStream {
    fn from((write, read): (SendStream, RecvStream)) -> Self {
        Self { read, write }
    }
}

impl AsyncRead for QuicStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        AsyncRead::poll_read(self.project().read, cx, buf)
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        AsyncWrite::poll_write(self.project().write, cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        AsyncWrite::poll_flush(self.project().write, cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        AsyncWrite::poll_shutdown(self.project().write, cx)
    }
}

pub fn create_quic_frames(
    conn: Connection,
    id: u32,
    sessions: Arc<CHashMap<u32, Sender<Frame>>>,
) -> Frames {
    let (tx, rx) = channel(10);
    sessions.insert(id, tx);
    (QuicFrameReader::new(rx), QuicFrameWriter::new(conn, id))
}

struct QuicFrameReader {
    rx: Receiver<Frame>,
}

impl QuicFrameReader {
    fn new(rx: Receiver<Frame>) -> Box<Self> {
        Box::new(Self { rx })
    }
}

use std::io::Result as IoResult;

#[async_trait]
impl FrameReader for QuicFrameReader {
    async fn read(&mut self) -> IoResult<Option<Frame>> {
        let ret = self.rx.recv().await;
        log::trace!("QuicFrameReader::read: {:?}", ret);
        Ok(ret)
    }
}

struct QuicFrameWriter {
    conn: Connection,
    session_id: u32,
}

impl QuicFrameWriter {
    fn new(conn: Connection, session_id: u32) -> Box<Self> {
        Box::new(Self { conn, session_id })
    }
}

#[async_trait]
impl FrameWriter for QuicFrameWriter {
    async fn write(&mut self, mut frame: Frame) -> IoResult<usize> {
        frame.session_id = self.session_id;
        let mut buf = frame.make_header();
        buf.extend(frame.body());
        let len = buf.len();
        let max_len = self.conn.max_datagram_size().unwrap_or_default();
        if len > max_len {
            log::warn!("frame too large: {} > {}, dropping.", len, max_len);
            return Ok(len);
        }
        log::trace!("quic send_datagram: {:?}", frame);
        if let Err(e) = self.conn.send_datagram(buf.freeze()) {
            log::warn!("quic send_datagram error: {}", e);
        }
        Ok(len)
        // todo!("this wont work, need to implement fragmention here");
    }
    async fn shutdown(&mut self) -> IoResult<()> {
        Ok(())
    }
}

pub type QuicFrameSessions = Arc<CHashMap<u32, Sender<Frame>>>;
pub async fn quic_frames_thread(name: String, sessions: QuicFrameSessions, mut input: Datagrams) {
    while let Some(frame) = input.next().await {
        let mut buf = match frame {
            Err(e) => {
                log::warn!("{}: QUIC connection error: {}", name, e);
                break;
            }
            Ok(s) => s,
        };
        let frame = Frame::from_buffer(&mut buf);
        if frame.is_err() {
            continue;
        }
        let frame = frame.unwrap();
        if frame.is_none() {
            continue;
        }
        let frame = frame.unwrap();
        let sid = frame.session_id;
        log::trace!("quic recv_datagram: {:?}", frame);
        if let Some(session) = sessions.get(&sid) {
            if session.is_closed() || session.send(frame).await.is_err() {
                drop(session);
                sessions.remove(&sid);
            } else {
                log::trace!("quic recv error: sid={}", sid);
            }
        }
    }
}
