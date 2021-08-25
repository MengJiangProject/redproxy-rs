use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use easy_error::{err_msg, Error, ResultExt};
use serde::{Deserialize, Serialize};
use tokio_rustls::rustls::{ClientConfig, ServerCertVerified, ServerCertVerifier, TLSError};
use tokio_rustls::TlsConnector;
use tokio_rustls::{
    rustls::{
        internal::pemfile::{certs, rsa_private_keys},
        AllowAnyAnonymousOrAuthenticatedClient, AllowAnyAuthenticatedClient, Certificate,
        ClientCertVerifier, NoClientAuth, PrivateKey, RootCertStore, ServerConfig,
    },
    TlsAcceptor,
};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TlsServerConfig {
    cert: String,
    key: String,
    client: Option<TlsClientVerifyConfig>,
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
pub struct TlsClientVerifyConfig {
    ca: String,
    required: bool,
}

impl TlsClientVerifyConfig {
    fn root_store(&self) -> Result<RootCertStore, Error> {
        let mut ret = RootCertStore::empty();
        let certs = load_certs(&self.ca)?;
        for cert in certs {
            ret.add(&cert).context("fail to add trusted certificate")?;
        }
        Ok(ret)
    }
    fn verifier(&self) -> Result<Arc<dyn ClientCertVerifier>, Error> {
        let ret = if self.required {
            AllowAnyAuthenticatedClient::new(self.root_store()?)
        } else {
            AllowAnyAnonymousOrAuthenticatedClient::new(self.root_store()?)
        };
        Ok(ret)
    }
}

impl TlsServerConfig {
    fn certs(&self) -> Result<(Vec<Certificate>, PrivateKey), Error> {
        let certs = load_certs(&self.cert)?;
        let mut keys = load_keys(&self.key)?;
        let key = keys.remove(0);
        Ok((certs, key))
    }

    fn client_auth(&self) -> Result<Arc<dyn ClientCertVerifier>, Error> {
        self.client
            .as_ref()
            .map(TlsClientVerifyConfig::verifier)
            .unwrap_or_else(|| Ok(NoClientAuth::new()))
    }

    pub fn init(&mut self) -> Result<(), Error> {
        let client_auth = self.client_auth()?;
        let mut config = ServerConfig::new(client_auth);
        let (certs, key) = self.certs()?;
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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TlsClientConfig {
    ca: Option<PathBuf>,
    #[serde(default)]
    pub insecure: bool,
    auth: Option<TlsClientAuthConfig>,
    #[serde(skip)]
    populated: Option<TlsClientConfigPopulated>,
}

impl TlsClientConfig {
    fn insecure_verifier(&self) -> Arc<dyn ServerCertVerifier> {
        struct InsecureVerifier;
        impl ServerCertVerifier for InsecureVerifier {
            fn verify_server_cert(
                &self,
                _roots: &RootCertStore,
                _presented_certs: &[Certificate],
                _dns_name: tokio_rustls::webpki::DNSNameRef,
                _ocsp_response: &[u8],
            ) -> Result<ServerCertVerified, TLSError> {
                Ok(ServerCertVerified::assertion())
            }
        }
        Arc::new(InsecureVerifier)
    }
    fn root_store(&self) -> Result<RootCertStore, Error> {
        let mut ret = RootCertStore::empty();
        let certs = self
            .ca
            .as_ref()
            .map(load_certs)
            .unwrap_or_else(|| Ok(vec![]))?;
        for cert in certs {
            ret.add(&cert).context("fail to add trusted certificate")?;
        }
        Ok(ret)
    }

    pub fn init(&mut self) -> Result<(), Error> {
        let mut config = ClientConfig::new();
        if self.ca.is_some() {
            config.root_store = self.root_store()?;
        }
        if self.auth.is_some() {
            self.auth
                .as_ref()
                .map(|auth| auth.setup(&mut config))
                .unwrap()?;
        }
        if self.insecure {
            config
                .dangerous()
                .set_certificate_verifier(self.insecure_verifier())
        }
        let config = Arc::new(config);
        self.populated = Some(TlsClientConfigPopulated { config });
        Ok(())
    }

    pub fn connector(&self) -> TlsConnector {
        if let Some(populated) = &self.populated {
            TlsConnector::from(populated.config.clone())
        } else {
            panic!("TlsClientConfig not initilazed")
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TlsClientAuthConfig {
    cert: PathBuf,
    key: PathBuf,
}

impl TlsClientAuthConfig {
    fn certs(&self) -> Result<(Vec<Certificate>, PrivateKey), Error> {
        let certs = load_certs(&self.cert)?;
        let mut keys = load_keys(&self.key)?;
        let key = keys.remove(0);
        Ok((certs, key))
    }

    fn setup(&self, config: &mut ClientConfig) -> Result<(), Error> {
        let (certs, key) = self.certs()?;
        config
            .set_single_client_cert(certs, key)
            .context("failed to load certificate")?;
        Ok(())
    }
}

#[derive(Clone)]
struct TlsClientConfigPopulated {
    config: Arc<ClientConfig>,
}
impl std::fmt::Debug for TlsClientConfigPopulated {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Populated")
    }
}

fn load_certs<P: AsRef<Path>>(path: P) -> Result<Vec<Certificate>, Error> {
    let file = File::open(path).context("failed to read certificates")?;
    let mut reader = BufReader::new(file);
    certs(&mut reader).map_err(|_| err_msg("fail to load certificate"))
}

fn load_keys<P: AsRef<Path>>(path: P) -> Result<Vec<PrivateKey>, Error> {
    let file = File::open(path).context("failed to read private key")?;
    let mut reader = BufReader::new(file);
    rsa_private_keys(&mut reader).map_err(|_| err_msg("fail to load private key"))
}
