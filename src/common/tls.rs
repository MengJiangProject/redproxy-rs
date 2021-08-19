use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use easy_error::{err_msg, Error, ResultExt};
use tokio_rustls::rustls::internal::pemfile::{certs, rsa_private_keys};
use tokio_rustls::rustls::{Certificate, NoClientAuth, PrivateKey, ServerConfig};
use tokio_rustls::TlsAcceptor;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TlsServerConfig {
    cert: PathBuf,
    key: PathBuf,
    client: Option<TlsClientAuthConfig>,
    #[serde(skip)]
    populated: Option<TlsServerConfigPopulated>,
}

#[derive(Clone)]
struct TlsServerConfigPopulated {
    config: Arc<ServerConfig>,
}
impl std::fmt::Debug for TlsServerConfigPopulated {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Populated")
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TlsClientAuthConfig {
    ca: Option<PathBuf>,
    required: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TlsClientConfig {
    enabled: bool,
    ca: Option<PathBuf>,
    cert: Option<PathBuf>,
    key: Option<PathBuf>,
}

fn load_certs(path: &Path) -> Result<Vec<Certificate>, Error> {
    let file = File::open(path).context("failed to read certificates")?;
    let mut reader = BufReader::new(file);
    certs(&mut reader).map_err(|_| err_msg("load certificate"))
}

fn load_keys(path: &Path) -> Result<Vec<PrivateKey>, Error> {
    let file = File::open(path).context("failed to read private key")?;
    let mut reader = BufReader::new(file);
    rsa_private_keys(&mut reader).map_err(|_| err_msg("load private key"))
}

impl TlsServerConfig {
    pub fn init(&mut self) -> Result<(), Error> {
        let certs = load_certs(&self.cert)?;
        let mut keys = load_keys(&self.key)?;
        let key = keys.remove(0);
        let mut config = ServerConfig::new(NoClientAuth::new());
        config
            .set_single_cert(certs, key)
            .context("failed to load certificate")?;
        let config = Arc::new(config);
        self.populated = Some(TlsServerConfigPopulated { config });
        Ok(())
    }
    pub fn acceptor(&self) -> TlsAcceptor {
        if let Some(populated) = &self.populated {
            TlsAcceptor::from(populated.config.clone())
        } else {
            panic!("TlsServerConfig not initilazed")
        }
    }
}
