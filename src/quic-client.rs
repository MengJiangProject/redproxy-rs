use std::{
    fs,
    io::{self, Write},
    net::ToSocketAddrs,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use easy_error::{err_msg, Error, ResultExt};

struct Opt {
    keylog: bool,
    host: Option<String>,
    ca: Option<PathBuf>,
    rebind: bool,
}

fn main() {
    let opt = Opt {
        keylog: false,
        host: None,
        ca: None,
        rebind: false,
    };
    let code = {
        if let Err(e) = run(opt) {
            eprintln!("ERROR: {}", e);
            1
        } else {
            0
        }
    };
    ::std::process::exit(code);
}
pub const ALPN_QUIC_HTTP: &[&[u8]] = &[b"hq-29"];

struct SkipCertificationVerification;

use quinn::ClientConfig;
use tokio_rustls::rustls;
use tokio_rustls::webpki;
impl rustls::ServerCertVerifier for SkipCertificationVerification {
    fn verify_server_cert(
        &self,
        _: &rustls::RootCertStore,
        _: &[rustls::Certificate],
        _: webpki::DNSNameRef,
        _: &[u8],
    ) -> Result<rustls::ServerCertVerified, rustls::TLSError> {
        Ok(rustls::ServerCertVerified::assertion())
    }
}
pub fn insecure(mut cfg: ClientConfig) -> ClientConfig {
    // let mut cfg = quinn::ClientConfigBuilder::default().build();

    // Get a mutable reference to the 'crypto' config in the 'client config'.
    let tls_cfg: &mut rustls::ClientConfig = std::sync::Arc::get_mut(&mut cfg.crypto).unwrap();

    // Change the certification verifier.
    // This is only available when compiled with the 'dangerous_configuration' feature.
    tls_cfg
        .dangerous()
        .set_certificate_verifier(Arc::new(SkipCertificationVerification));
    cfg
}

#[tokio::main]
async fn run(options: Opt) -> Result<(), Error> {
    let url = "/";
    let remote = "127.0.0.1:4433".parse().unwrap();

    let mut endpoint = quinn::Endpoint::builder();
    let mut client_config = quinn::ClientConfigBuilder::default();
    client_config.protocols(ALPN_QUIC_HTTP);
    if options.keylog {
        client_config.enable_keylog();
    }
    let cfg = insecure(client_config.build());
    endpoint.default_client_config(cfg);

    let (endpoint, _) = endpoint.bind(&"[::]:0".parse().unwrap()).context("bind")?;

    let request = format!("GET {}\r\n", url);
    let start = Instant::now();
    let rebind = options.rebind;
    let host = "localhost";

    eprintln!("connecting to {} at {}", host, remote);
    let new_conn = endpoint
        .connect(&remote, host)
        .context("connect")?
        .await
        .map_err(|e| err_msg(format!("failed to connect: {}", e)))?;
    eprintln!("connected at {:?}", start.elapsed());
    let quinn::NewConnection {
        connection: conn, ..
    } = new_conn;
    let (mut send, recv) = conn
        .open_bi()
        .await
        .map_err(|e| err_msg(format!("failed to open stream: {}", e)))?;
    if rebind {
        let socket = std::net::UdpSocket::bind("[::]:0").unwrap();
        let addr = socket.local_addr().unwrap();
        eprintln!("rebinding to {}", addr);
        endpoint.rebind(socket).expect("rebind failed");
    }

    send.write_all(request.as_bytes())
        .await
        .map_err(|e| err_msg(format!("failed to send request: {}", e)))?;
    send.finish()
        .await
        .map_err(|e| err_msg(format!("failed to shutdown stream: {}", e)))?;
    let response_start = Instant::now();
    eprintln!("request sent at {:?}", response_start - start);
    let resp = recv
        .read_to_end(usize::max_value())
        .await
        .map_err(|e| err_msg(format!("failed to read response: {}", e)))?;
    let duration = response_start.elapsed();
    eprintln!(
        "response received in {:?} - {} KiB/s",
        duration,
        resp.len() as f32 / (duration_secs(&duration) * 1024.0)
    );
    io::stdout().write_all(&resp).unwrap();
    io::stdout().flush().unwrap();
    conn.close(0u32.into(), b"done");

    // Give the server a fair chance to receive the close packet
    endpoint.wait_idle().await;

    Ok(())
}

fn duration_secs(x: &Duration) -> f32 {
    x.as_secs() as f32 + x.subsec_nanos() as f32 * 1e-9
}
