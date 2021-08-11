use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use easy_error::{err_msg, Error, ResultExt};
use tokio_rustls::rustls::internal::pemfile::{certs, rsa_private_keys};
use tokio_rustls::rustls::{Certificate, NoClientAuth, PrivateKey, ServerConfig};
use tokio_rustls::TlsAcceptor;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct TlsOptions {
    cert: PathBuf,
    key: PathBuf,
}

fn load_certs(path: &Path) -> Result<Vec<Certificate>, Error> {
    let file = File::open(path).context("open")?;
    let mut reader = BufReader::new(file);
    certs(&mut reader).map_err(|_| err_msg("load certificate"))
}

fn load_keys(path: &Path) -> Result<Vec<PrivateKey>, Error> {
    let file = File::open(path).context("open")?;
    let mut reader = BufReader::new(file);
    rsa_private_keys(&mut reader).map_err(|_| err_msg("load private key"))
}

pub fn acceptor(options: &TlsOptions) -> Result<TlsAcceptor, Error> {
    let certs = load_certs(&options.cert)?;
    let mut keys = load_keys(&options.key)?;
    // let flag_echo = options.echo_mode;

    let mut config = ServerConfig::new(NoClientAuth::new());
    config
        .set_single_cert(certs, keys.remove(0))
        .context("set_single_cert")?;
    Ok(TlsAcceptor::from(Arc::new(config)))

    // let listener = TcpListener::bind(&addr).await?;

    // loop {
    //     let (stream, peer_addr) = listener.accept().await?;
    //     let acceptor = acceptor.clone();

    //     let fut = async move {
    //         let mut stream = acceptor.accept(stream).await?;

    //         if flag_echo {
    //             let (mut reader, mut writer) = split(stream);
    //             let n = copy(&mut reader, &mut writer).await?;
    //             writer.flush().await?;
    //             println!("Echo: {} - {}", peer_addr, n);
    //         } else {
    //             let mut output = sink();
    //             stream
    //                 .write_all(
    //                     &b"HTTP/1.0 200 ok\r\n\
    //                 Connection: close\r\n\
    //                 Content-length: 12\r\n\
    //                 \r\n\
    //                 Hello world!"[..],
    //                 )
    //                 .await?;
    //             stream.shutdown().await?;
    //             copy(&mut stream, &mut output).await?;
    //             println!("Hello: {}", peer_addr);
    //         }

    //         Ok(()) as io::Result<()>
    //     };

    //     tokio::spawn(async move {
    //         if let Err(err) = fut.await {
    //             eprintln!("{:?}", err);
    //         }
    //     });
    // }
}
