use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use easy_error::{err_msg, Error, ResultExt};
use rustls_pemfile::{certs, read_one, Item};
use serde::{Deserialize, Serialize};
use tokio_rustls::rustls::{
    client::danger::HandshakeSignatureValid,
    client::danger::{ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime},
    server::{danger::ClientCertVerifier, NoClientAuth, WebPkiClientVerifier},
    ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig, SignatureScheme,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

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
            ret.add(cert).context("fail to add trusted certificate")?;
        }
        Ok(ret)
    }
    fn verifier(&self) -> Result<Arc<dyn ClientCertVerifier>, Error> {
        let roots = Arc::new(self.root_store()?);
        let builder = WebPkiClientVerifier::builder(roots.clone());
        let builder = if self.required {
            builder
        } else {
            builder.allow_unauthenticated()
        };
        let verifier = builder
            .build()
            .map_err(|e| err_msg(format!("fail to build client verifier: {:?}", e)))?;
        Ok(verifier)
    }
}

impl TlsServerConfig {
    pub fn certs(&self) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), Error> {
        let certs = load_certs(&self.cert)?;
        let key = load_keys(&self.key)?;
        Ok((certs, key))
    }

    fn client_auth(&self) -> Result<Arc<dyn ClientCertVerifier>, Error> {
        self.client
            .as_ref()
            .map(TlsClientVerifyConfig::verifier)
            .unwrap_or_else(|| Ok(Arc::new(NoClientAuth)))
    }

    pub fn init(&mut self) -> Result<(), Error> {
        let client_auth = self.client_auth()?;
        let (certs, key) = self.certs()?;
        let config: ServerConfig = ServerConfig::builder()
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
        #[derive(Debug)]
        struct InsecureVerifier;
        impl ServerCertVerifier for InsecureVerifier {
            fn verify_server_cert(
                &self,
                _end_entity: &CertificateDer<'_>,
                _intermediates: &[CertificateDer<'_>],
                _server_name: &ServerName<'_>,
                _ocsp_response: &[u8],
                _now: UnixTime,
            ) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
                Ok(ServerCertVerified::assertion())
            }
            fn verify_tls12_signature(
                &self,
                _message: &[u8],
                _cert: &CertificateDer<'_>,
                _dss: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }
            fn verify_tls13_signature(
                &self,
                _message: &[u8],
                _cert: &CertificateDer<'_>,
                _dss: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }
            fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
                Vec::new()
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
            ret.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        } else {
            for cert in certs {
                ret.add(cert).context("fail to add trusted certificate")?;
            }
        }
        Ok(ret)
    }

    pub fn init(&mut self) -> Result<(), Error> {
        let root_store = self.root_store()?;
        let builder = ClientConfig::builder();
        let builder = if self.insecure {
            builder
                .dangerous()
                .with_custom_certificate_verifier(self.insecure_verifier())
        } else {
            builder.with_root_certificates(root_store)
        };
        let config = if let Some(auth_cfg) = &self.auth {
            let (chain, key) = auth_cfg.certs()?;
            builder
                .with_client_auth_cert(chain, key)
                .context("failed to load certificate")?
        } else {
            builder.with_no_client_auth()
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
    pub fn certs(&self) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), Error> {
        let certs = load_certs(&self.cert)?;
        let key = load_keys(&self.key)?;
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

fn load_certs<P: AsRef<Path>>(path: P) -> Result<Vec<CertificateDer<'static>>, Error> {
    let file = File::open(path).context("failed to read certificates")?;
    let mut reader = BufReader::new(file);
    let raw = certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| err_msg("fail to load certificate"))?;
    Ok(raw.into_iter().map(CertificateDer::from).collect())
}

fn load_keys<P: AsRef<Path>>(path: P) -> Result<PrivateKeyDer<'static>, Error> {
    let file = File::open(path).context("failed to read private key")?;
    let mut reader = BufReader::new(file);
    let item = read_one(&mut reader)
        .map_err(|_| err_msg("fail to load private key"))?
        .expect("pem file");
    let key = match item {
        Item::Pkcs1Key(key) => PrivateKeyDer::Pkcs1(key),
        Item::Pkcs8Key(key) => PrivateKeyDer::Pkcs8(key),
        Item::Sec1Key(key) => PrivateKeyDer::Sec1(key),
        _ => return Err(err_msg("fail to load private key")),
    };
    Ok(key)
}
