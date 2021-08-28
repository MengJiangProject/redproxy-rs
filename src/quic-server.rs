use std::{
    ascii, fs,
    net::SocketAddr,
    path::{self, Path, PathBuf},
    str,
    sync::Arc,
};

use easy_error::{bail, err_msg, Error, ResultExt};
use futures_util::{stream::StreamExt, TryFutureExt};
use log::{error, info};

pub const ALPN_QUIC_HTTP: &[&[u8]] = &[b"hq-29"];

struct Opt {
    keylog: bool,
    root: PathBuf,
    key: Option<PathBuf>,
    cert: Option<PathBuf>,
    stateless_retry: bool,
    listen: SocketAddr,
}

fn main() {
    env_logger::init_from_env(env_logger::Env::default());
    let opt = Opt {
        keylog: false,
        root: PathBuf::from("./"),
        key: Some(PathBuf::from("test.key")),
        cert: Some(PathBuf::from("test.crt")),
        stateless_retry: false,
        listen: "0.0.0.0:4433".parse().unwrap(),
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

#[tokio::main]
async fn run(options: Opt) -> Result<(), Error> {
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_concurrent_uni_streams(0).unwrap();
    let mut server_config = quinn::ServerConfig::default();
    server_config.transport = Arc::new(transport_config);
    let mut server_config = quinn::ServerConfigBuilder::new(server_config);
    server_config.protocols(ALPN_QUIC_HTTP);

    if options.keylog {
        server_config.enable_keylog();
    }

    if options.stateless_retry {
        server_config.use_stateless_retry(true);
    }

    if let (Some(key_path), Some(cert_path)) = (&options.key, &options.cert) {
        let key = fs::read(key_path).context("failed to read private key")?;
        let key = if key_path.extension().map_or(false, |x| x == "der") {
            quinn::PrivateKey::from_der(&key).context("from_der")?
        } else {
            quinn::PrivateKey::from_pem(&key).context("from_pem")?
        };
        let cert_chain = fs::read(cert_path).context("failed to read certificate chain")?;
        let cert_chain = if cert_path.extension().map_or(false, |x| x == "der") {
            quinn::CertificateChain::from_certs(Some(
                quinn::Certificate::from_der(&cert_chain).unwrap(),
            ))
        } else {
            quinn::CertificateChain::from_pem(&cert_chain).context("from_pem")?
        };
        server_config
            .certificate(cert_chain, key)
            .context("certificate")?;
    } else {
        bail!("failed to read certificate");
    }

    let mut endpoint = quinn::Endpoint::builder();
    endpoint.listen(server_config.build());

    let root = Arc::<Path>::from(options.root.clone());
    if !root.exists() {
        bail!("root path does not exist");
    }

    let (endpoint, mut incoming) = endpoint.bind(&options.listen).context("bind")?;
    eprintln!("listening on {}", endpoint.local_addr().context("")?);

    while let Some(conn) = incoming.next().await {
        info!("connection incoming");
        tokio::spawn(
            handle_connection(root.clone(), conn).unwrap_or_else(move |e| {
                error!("connection failed: {reason}", reason = e.to_string())
            }),
        );
    }

    Ok(())
}

async fn handle_connection(root: Arc<Path>, conn: quinn::Connecting) -> Result<(), Error> {
    let quinn::NewConnection { mut bi_streams, .. } = conn.await.context("connection")?;

    async {
        info!("established");

        // Each stream initiated by the client constitutes a new request.
        while let Some(stream) = bi_streams.next().await {
            let stream = match stream {
                Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                    info!("connection closed");
                    return Ok(());
                }
                Err(e) => {
                    return Err(e);
                }
                Ok(s) => s,
            };
            tokio::spawn(
                handle_request(root.clone(), stream)
                    .unwrap_or_else(move |e| error!("failed: {reason}", reason = e.to_string())),
            );
        }
        Ok(())
    }
    .await
    .context("")?;
    Ok(())
}

async fn handle_request(
    root: Arc<Path>,
    (mut send, recv): (quinn::SendStream, quinn::RecvStream),
) -> Result<(), Error> {
    let req = recv
        .read_to_end(64 * 1024)
        .await
        .map_err(|e| err_msg(format!("failed reading request: {}", e)))?;
    let mut escaped = String::new();
    for &x in &req[..] {
        let part = ascii::escape_default(x).collect::<Vec<_>>();
        escaped.push_str(str::from_utf8(&part).unwrap());
    }
    info!("content = {}", escaped);
    // Execute the request
    let resp = process_get(&root, &req).unwrap_or_else(|e| {
        error!("failed: {}", e);
        format!("failed to process request: {}\n", e).into_bytes()
    });
    // Write the response
    send.write_all(&resp)
        .await
        .map_err(|e| err_msg(format!("failed to send response: {}", e)))?;
    // Gracefully terminate the stream
    send.finish()
        .await
        .map_err(|e| err_msg(format!("failed to shutdown stream: {}", e)))?;
    info!("complete");
    Ok(())
}

fn process_get(root: &Path, x: &[u8]) -> Result<Vec<u8>, Error> {
    if x.len() < 4 || &x[0..4] != b"GET " {
        bail!("missing GET");
    }
    if x[4..].len() < 2 || &x[x.len() - 2..] != b"\r\n" {
        bail!("missing \\r\\n");
    }
    let x = &x[4..x.len() - 2];
    let end = x.iter().position(|&c| c == b' ').unwrap_or_else(|| x.len());
    let path = str::from_utf8(&x[..end]).context("path is malformed UTF-8")?;
    let path = Path::new(&path);
    let mut real_path = PathBuf::from(root);
    let mut components = path.components();
    match components.next() {
        Some(path::Component::RootDir) => {}
        _ => {
            bail!("path must be absolute");
        }
    }
    for c in components {
        match c {
            path::Component::Normal(x) => {
                real_path.push(x);
            }
            x => {
                bail!("illegal component in path: {:?}", x);
            }
        }
    }
    let data = fs::read(&real_path).context("failed reading file")?;
    Ok(data)
}
