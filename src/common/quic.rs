use std::{pin::Pin, sync::Arc};

use easy_error::{Error, ResultExt};
use quinn::{ClientConfig, RecvStream, SendStream, ServerConfig};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::rustls;

use super::tls::{TlsClientConfig, TlsServerConfig};

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
