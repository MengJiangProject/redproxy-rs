use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use easy_error::{err_msg, Error, ResultExt};
use rustls_pemfile::{certs, rsa_private_keys};
use serde::{Deserialize, Serialize};
use tokio_rustls::rustls::client::{ServerCertVerified, ServerCertVerifier, WebPkiVerifier};
use tokio_rustls::rustls::server::{
    AllowAnyAnonymousOrAuthenticatedClient, AllowAnyAuthenticatedClient, ClientCertVerifier,
    NoClientAuth,
};
use tokio_rustls::rustls::{Certificate, ClientConfig, OwnedTrustAnchor, ServerName};
use tokio_rustls::TlsConnector;
use tokio_rustls::{
    rustls::{PrivateKey, RootCertStore, ServerConfig},
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
    pub fn certs(&self) -> Result<(Vec<Certificate>, PrivateKey), Error> {
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
        let (certs, key) = self.certs()?;
        let config: ServerConfig = ServerConfig::builder()
            .with_safe_defaults()
            .with_client_cert_verifier(client_auth)
            .with_single_cert(certs, key)
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
    pub ca: Option<PathBuf>,
    #[serde(default)]
    pub insecure: bool,
    pub auth: Option<TlsClientAuthConfig>,
    #[serde(skip)]
    populated: Option<TlsClientConfigPopulated>,
    #[serde(default)]
    disable_early_data: bool,
}

impl TlsClientConfig {
    pub fn insecure_verifier(&self) -> Arc<dyn ServerCertVerifier> {
        struct InsecureVerifier;
        impl ServerCertVerifier for InsecureVerifier {
            fn verify_server_cert(
                &self,
                _end_entity: &Certificate,
                _intermediates: &[Certificate],
                _server_name: &ServerName,
                _scts: &mut dyn Iterator<Item = &[u8]>,
                _ocsp_response: &[u8],
                _now: SystemTime,
            ) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
                Ok(ServerCertVerified::assertion())
            }
        }
        Arc::new(InsecureVerifier)
    }

    // return default roots if ca is undefined
    pub fn root_store(&self) -> Result<RootCertStore, Error> {
        let mut ret = RootCertStore::empty();
        let certs = self
            .ca
            .as_ref()
            .map(load_certs)
            .unwrap_or_else(|| Ok(vec![]))?;
        if certs.is_empty() {
            ret.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
                OwnedTrustAnchor::from_subject_spki_name_constraints(
                    ta.subject,
                    ta.spki,
                    ta.name_constraints,
                )
            }));
        } else {
            for cert in certs {
                ret.add(&cert).context("fail to add trusted certificate")?;
            }
        }
        Ok(ret)
    }

    pub fn init(&mut self) -> Result<(), Error> {
        let root_store = self.root_store()?;
        let config = ClientConfig::builder().with_safe_defaults();
        // config.enable_early_data = !self.disable_early_data;
        let config = if self.insecure {
            config.with_custom_certificate_verifier(self.insecure_verifier())
        } else {
            config.with_custom_certificate_verifier(Arc::new(WebPkiVerifier::new(root_store, None)))
        };

        let config = if self.auth.is_some() {
            let certs = self.auth.as_ref().unwrap().certs()?;
            config
                .with_single_cert(certs.0, certs.1)
                .context("failed to load certificate")?
        } else {
            config.with_no_client_auth()
        };

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
    pub fn certs(&self) -> Result<(Vec<Certificate>, PrivateKey), Error> {
        let certs = load_certs(&self.cert)?;
        let mut keys = load_keys(&self.key)?;
        let key = keys.remove(0);
        Ok((certs, key))
    }

    // pub fn setup(&self, config: &mut ClientConfig) -> Result<(), Error> {
    //     let (certs, key) = self.certs()?;
    //     config
    //         .set_single_client_cert(certs, key)
    //         .context("failed to load certificate")?;
    //     Ok(())
    // }
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
    certs(&mut reader)
        .map(|x| x.into_iter().map(Certificate).collect())
        .map_err(|_| err_msg("fail to load certificate"))
}

fn load_keys<P: AsRef<Path>>(path: P) -> Result<Vec<PrivateKey>, Error> {
    let file = File::open(path).context("failed to read private key")?;
    let mut reader = BufReader::new(file);
    rsa_private_keys(&mut reader)
        .map(|x| x.into_iter().map(PrivateKey).collect())
        .map_err(|_| err_msg("fail to load private key"))
}
