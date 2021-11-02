use std::{pin::Pin, sync::Arc};

use easy_error::{Error, ResultExt};
use quinn::{EndpointBuilder, RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncWrite};
// use tokio_rustls::rustls;

use super::tls::{TlsClientConfig, TlsServerConfig};

pub const ALPN_QUIC_HTTP11C: &[&[u8]] = &[b"h11c"]; //this is not regular HTTP3 connection, it uses HTTP1.1 CONNECT instead.

pub fn create_quic_server(tls: &TlsServerConfig) -> Result<EndpointBuilder, Error> {
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_concurrent_uni_streams(0).unwrap();
    let mut server_config = quinn::ServerConfig::default();
    server_config.transport = Arc::new(transport_config);

    let mut server_config = quinn::ServerConfigBuilder::new(server_config);
    server_config.protocols(ALPN_QUIC_HTTP11C);
    server_config.enable_keylog();
    server_config.use_stateless_retry(true);

    let mut cfg = server_config.build();
    let tls_cfg = std::sync::Arc::get_mut(&mut cfg.crypto).unwrap();

    let (certs, key) = tls.certs()?;
    // let certs = certs
    //     .into_iter()
    //     .map(|cert| rustls::Certificate(cert.0))
    //     .collect();
    // let key = rustls::PrivateKey(key.0);
    tls_cfg
        .set_single_cert(certs, key)
        .context("load certificate")?;

    let mut endpoint = quinn::Endpoint::builder();
    endpoint.listen(cfg);
    Ok(endpoint)
}

pub fn create_quic_client(tls: &TlsClientConfig) -> Result<EndpointBuilder, Error> {
    let mut endpoint = quinn::Endpoint::builder();
    let mut client_config = quinn::ClientConfigBuilder::default();
    client_config.protocols(ALPN_QUIC_HTTP11C);
    client_config.enable_keylog();
    let mut cfg = client_config.build();
    let tls_cfg: &mut rustls::ClientConfig = std::sync::Arc::get_mut(&mut cfg.crypto).unwrap();
    if tls.ca.is_some() {
        tls_cfg.root_store = tls.root_store()?;
    }
    if tls.auth.is_some() {
        tls.auth.as_ref().map(|auth| auth.setup(tls_cfg)).unwrap()?;
    }
    if tls.insecure {
        tls_cfg
            .dangerous()
            .set_certificate_verifier(tls.insecure_verifier());
    }
    endpoint.default_client_config(cfg);

    Ok(endpoint)
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
