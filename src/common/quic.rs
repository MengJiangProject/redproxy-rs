use anyhow::{Context, Result};
use async_trait::async_trait;
use chashmap_async::CHashMap;
use quinn::{
    ClientConfig, Connection, RecvStream, SendStream, ServerConfig, congestion,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
};
use std::{
    convert::TryInto,
    io::{Error as IoError, ErrorKind, Result as IoResult},
    pin::Pin,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::mpsc::{Receiver, Sender, channel},
};
use tokio_rustls::rustls;

use super::{
    fragment::Fragments,
    frames::{Frame, FrameIO, FrameReader, FrameWriter},
    tls::{TlsClientConfig, TlsServerConfig},
};

pub const ALPN_QUIC_HTTP1: &[&[u8]] = &[b"http"]; //this is not regular HTTP3 connection, it uses HTTP1.1 CONNECT instead.

pub fn create_quic_server(tls: &TlsServerConfig) -> Result<ServerConfig> {
    let (certs, key) = tls.certs()?;
    let mut server_crypto = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into()
    )
    .with_safe_default_protocol_versions()
    .context("failed to configure TLS protocol versions")?
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .context("load certificate")?;
    tracing::info!("server_crypto created");
    server_crypto.alpn_protocols = ALPN_QUIC_HTTP1.iter().map(|&x| x.into()).collect();

    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_concurrent_uni_streams(0u8.into());
    transport_config.keep_alive_interval(Some(Duration::from_secs(30)));
    transport_config.max_idle_timeout(Some(Duration::from_secs(3600).try_into().unwrap()));

    let cfg: QuicServerConfig = server_crypto
        .try_into()
        .context("failed to convert rustls::ServerConfig to quinn::ServerConfig")?;
    let mut cfg = ServerConfig::with_crypto(Arc::new(cfg));
    cfg.transport = Arc::new(transport_config);
    Ok(cfg)
}

pub fn create_quic_client(tls: &TlsClientConfig, enable_bbr: bool) -> Result<ClientConfig> {
    let builder = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into()
    )
    .with_safe_default_protocol_versions()
    .context("failed to configure TLS protocol versions")?
    .with_root_certificates(tls.root_store()?);

    let mut client_crypto = if let Some(auth) = &tls.auth {
        let (certs, key) = auth.certs()?;
        builder
            .with_client_auth_cert(certs, key)
            .context("load client certs")?
    } else {
        builder.with_no_client_auth()
    };

    client_crypto.alpn_protocols = ALPN_QUIC_HTTP1.iter().map(|&x| x.into()).collect();

    if tls.insecure {
        client_crypto
            .dangerous()
            .set_certificate_verifier(tls.insecure_verifier());
    }

    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_concurrent_uni_streams(0u8.into());
    transport_config.keep_alive_interval(Some(Duration::from_secs(30)));
    transport_config.max_idle_timeout(Some(Duration::from_secs(3600).try_into().unwrap()));
    if enable_bbr {
        transport_config.congestion_controller_factory(Arc::new(congestion::BbrConfig::default()));
    }
    let cfg: QuicClientConfig = client_crypto
        .try_into()
        .context("failed to convert rustls::ClientConfig to quinn::ClientConfig")?;
    let mut cfg = ClientConfig::new(Arc::new(cfg));
    cfg.transport_config(Arc::new(transport_config));
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

pub async fn create_quic_frames(
    conn: Connection,
    id: u32,
    sessions: Arc<CHashMap<u32, Sender<Frame>>>,
) -> FrameIO {
    let (tx, rx) = channel(10);
    sessions.insert(id, tx).await;
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

#[async_trait]
impl FrameReader for QuicFrameReader {
    async fn read(&mut self) -> IoResult<Option<Frame>> {
        let ret = self.rx.recv().await;
        tracing::trace!("QuicFrameReader::read: {:?}", ret);
        Ok(ret)
    }
}

struct QuicFrameWriter {
    conn: Connection,
    session_id: u32,
    frame_id: u16,
}

impl QuicFrameWriter {
    fn new(conn: Connection, session_id: u32) -> Box<Self> {
        Box::new(Self {
            conn,
            session_id,
            frame_id: 0,
        })
    }
}

#[async_trait]
impl FrameWriter for QuicFrameWriter {
    async fn write(&mut self, mut frame: Frame) -> IoResult<usize> {
        frame.session_id = self.session_id;
        tracing::trace!(
            "quic send_datagram: sid={} len={}",
            frame.session_id,
            frame.len()
        );
        let mtu = self.conn.max_datagram_size();
        if mtu.is_none() {
            return Err(IoError::new(
                ErrorKind::Unsupported,
                "Datagram not allowed for this connection",
            ));
        }
        let fragments = Fragments::make_fragments(mtu.unwrap(), &mut self.frame_id, frame);
        let mut len = 0;
        for fragment in fragments {
            len += fragment.len();
            self.conn
                .send_datagram(fragment)
                .map_err(|e| IoError::other(e.to_string()))?;
        }
        Ok(len)
    }
    async fn shutdown(&mut self) -> IoResult<()> {
        Ok(())
    }
}

pub type QuicFrameSessions = Arc<CHashMap<u32, Sender<Frame>>>;
pub async fn quic_frames_thread(name: String, sessions: QuicFrameSessions, input: Connection) {
    let mut f: Fragments<Frame> = Fragments::new(Duration::from_secs(5));
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    loop {
        let next = input.read_datagram();
        tokio::select! {
            _ = interval.tick() => {
                f.timer()
            },
            frame = next => {
                if let Err(e) = frame {
                    tracing::warn!("{}: QUIC connection error: {}", name, e);
                    break;
                }
                let frame = f.reassemble(frame.unwrap());
                if frame.is_none() {
                    continue;
                }
                let frame = frame.unwrap();
                let sid = frame.session_id;
                if let Some(session) = sessions.get(&sid).await
                    && (session.is_closed() || session.send(frame).await.is_err()) {
                        drop(session);
                        sessions.remove(&sid).await;
                        tracing::trace!("quic recv error: sid={}", sid);
                    }
            },
            else => break,
        }
    }
}
