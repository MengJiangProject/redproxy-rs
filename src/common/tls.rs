use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use rustls_pemfile::{Item, certs, read_one};
use serde::{Deserialize, Serialize};
use tokio_rustls::rustls::{
    ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig, SignatureScheme,
    client::danger::HandshakeSignatureValid,
    client::danger::{ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime},
    server::{
        NoClientAuth, ResolvesServerCertUsingSni, WebPkiClientVerifier, danger::ClientCertVerifier,
    },
    sign::CertifiedKey,
    version::{TLS12, TLS13},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// TLS protocol version configuration
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TlsProtocolConfig {
    #[serde(default = "default_true")]
    pub tls_1_2: bool,
    #[serde(default = "default_true")]
    pub tls_1_3: bool,
}

impl Default for TlsProtocolConfig {
    fn default() -> Self {
        Self {
            tls_1_2: true,
            tls_1_3: true,
        }
    }
}

impl TlsProtocolConfig {
    /// Get the rustls supported protocol versions based on configuration
    pub fn to_rustls_versions(&self) -> Vec<&'static rustls::SupportedProtocolVersion> {
        let mut versions = Vec::new();
        if self.tls_1_2 {
            versions.push(&TLS12);
        }
        if self.tls_1_3 {
            versions.push(&TLS13);
        }
        // If no versions are enabled, default to both for safety
        if versions.is_empty() {
            versions.push(&TLS12);
            versions.push(&TLS13);
        }
        versions
    }
}

/// Advanced TLS security configuration
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct TlsSecurityConfig {
    /// Server Name Indication (SNI) configuration
    #[serde(default)]
    pub sni: TlsSniConfig,

    /// OCSP stapling support
    #[serde(default)]
    pub ocsp_stapling: bool,

    /// Require SNI extension from clients
    #[serde(default)]
    pub require_sni: bool,
}

/// SNI (Server Name Indication) configuration
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct TlsSniConfig {
    /// Enable SNI support
    #[serde(default)]
    pub enable: bool,

    /// SNI certificate mappings (hostname -> cert/key paths)
    #[serde(default)]
    pub certificates: HashMap<String, TlsServerCertConfig>,
}

/// Server certificate configuration for SNI
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TlsServerCertConfig {
    pub cert: String,
    pub key: String,
}

impl TlsServerCertConfig {
    /// Load certificate chain and private key for this configuration
    pub fn load_certs(&self) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
        let certs = load_certs(&self.cert)?;
        let key = load_keys(&self.key)?;
        Ok((certs, key))
    }
}

fn default_true() -> bool {
    true
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(default)]
#[derive(Default)]
pub struct TlsServerConfig {
    // Certificate and key files
    pub cert: String,
    pub key: String,

    // Client certificate verification
    pub client: Option<TlsClientVerifyConfig>,

    // Protocol configuration
    #[serde(default)]
    pub protocols: TlsProtocolConfig,

    // Advanced security settings
    #[serde(default)]
    pub security: TlsSecurityConfig,

    // Internal runtime state (not serialized)
    #[serde(skip)]
    server_config: Option<Arc<ServerConfig>>,
    #[serde(skip)]
    alpn_protocols: Vec<Vec<u8>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TlsClientVerifyConfig {
    ca: String,
    required: bool,
}

impl TlsClientVerifyConfig {
    fn root_store(&self) -> Result<RootCertStore> {
        let mut ret = RootCertStore::empty();
        let certs = load_certs(&self.ca)?;
        for cert in certs {
            ret.add(cert)
                .with_context(|| "fail to add trusted certificate")?;
        }
        Ok(ret)
    }
    fn verifier(&self) -> Result<Arc<dyn ClientCertVerifier>> {
        let roots = Arc::new(self.root_store()?);
        let builder = WebPkiClientVerifier::builder(roots.clone());
        let builder = if self.required {
            builder
        } else {
            builder.allow_unauthenticated()
        };
        let verifier = builder
            .build()
            .map_err(|e| anyhow!("fail to build client verifier: {:?}", e))?;
        Ok(verifier)
    }
}

impl TlsServerConfig {
    pub fn certs(&self) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
        let certs = load_certs(&self.cert)?;
        let key = load_keys(&self.key)?;
        Ok((certs, key))
    }

    fn client_auth(&self) -> Result<Arc<dyn ClientCertVerifier>> {
        self.client
            .as_ref()
            .map(TlsClientVerifyConfig::verifier)
            .unwrap_or_else(|| Ok(Arc::new(NoClientAuth)))
    }

    /// Load SNI certificates and create a certificate resolver
    fn create_sni_resolver(&self) -> Result<ResolvesServerCertUsingSni> {
        let mut resolver = ResolvesServerCertUsingSni::new();

        // Get the crypto provider to load private keys
        let crypto_provider = rustls::crypto::CryptoProvider::get_default()
            .ok_or_else(|| anyhow!("No default crypto provider available"))?;

        // Load certificates for each SNI hostname
        for (hostname, cert_config) in &self.security.sni.certificates {
            let (cert_chain, private_key_der) = cert_config.load_certs().with_context(|| {
                format!("Failed to load SNI certificate for hostname: {}", hostname)
            })?;

            // Convert PrivateKeyDer to SigningKey using the crypto provider
            let signing_key = crypto_provider
                .key_provider
                .load_private_key(private_key_der)
                .map_err(|e| anyhow!("Failed to load private key for {}: {:?}", hostname, e))?;

            // Create a CertifiedKey with the certificate chain and signing key
            let certified_key = CertifiedKey::new(cert_chain, signing_key);

            resolver
                .add(hostname, certified_key)
                .map_err(|e| anyhow!("Failed to add SNI certificate for {}: {:?}", hostname, e))?;
        }

        Ok(resolver)
    }

    pub fn init(&mut self) -> Result<()> {
        let client_auth = self.client_auth()?;

        // Build server config with protocol version support
        let protocol_versions = self.protocols.to_rustls_versions();
        let builder =
            if protocol_versions.len() == 2 && self.protocols.tls_1_2 && self.protocols.tls_1_3 {
                // Use default builder when both protocols are enabled
                ServerConfig::builder()
            } else {
                // Use specific protocol versions
                tracing::info!(
                    "Configuring TLS with specific protocol versions: TLS 1.2={}, TLS 1.3={}",
                    self.protocols.tls_1_2,
                    self.protocols.tls_1_3
                );
                ServerConfig::builder_with_protocol_versions(&protocol_versions)
            };

        let mut config: ServerConfig =
            if self.security.sni.enable && !self.security.sni.certificates.is_empty() {
                // Use SNI certificate resolver when SNI is enabled and certificates are configured
                let sni_resolver = self.create_sni_resolver()?;
                tracing::info!(
                    "SNI certificate resolver configured with {} certificates",
                    self.security.sni.certificates.len()
                );

                builder
                    .with_client_cert_verifier(client_auth)
                    .with_cert_resolver(Arc::new(sni_resolver))
            } else {
                // Use single certificate configuration
                let (certs, key) = self.certs()?;
                builder
                    .with_client_cert_verifier(client_auth)
                    .with_single_cert(certs, key)
                    .with_context(|| "failed to load certificate")?
            };

        // ALPN protocols will be set by protocol handlers via set_alpn_protocols()
        if !self.alpn_protocols.is_empty() {
            config.alpn_protocols = self.alpn_protocols.clone();
            tracing::info!(
                "ALPN protocols configured: {:?}",
                self.alpn_protocols
                    .iter()
                    .map(|p| String::from_utf8_lossy(p))
                    .collect::<Vec<_>>()
            );
        }

        let config = Arc::new(config);
        self.server_config = Some(config);
        Ok(())
    }

    pub fn acceptor(&self) -> Result<TlsAcceptor> {
        if let Some(config) = &self.server_config {
            Ok(TlsAcceptor::from(config.clone()))
        } else {
            Err(anyhow!("TlsServerConfig not initialized"))
        }
    }

    /// Set ALPN protocols for this server configuration (for internal use by protocol handlers)
    pub fn set_alpn_protocols(&mut self, protocols: Vec<Vec<u8>>) {
        self.alpn_protocols = protocols;
        // Clear server config to force re-initialization with new ALPN
        self.server_config = None;
    }

    /// Get currently configured ALPN protocols
    pub fn alpn_protocols(&self) -> &[Vec<u8>] {
        &self.alpn_protocols
    }

    /// Validate TLS configuration
    pub fn validate(&self) -> Result<()> {
        if self.cert.is_empty() {
            bail!("TLS certificate path cannot be empty");
        }

        if self.key.is_empty() {
            bail!("TLS private key path cannot be empty");
        }

        if !self.protocols.tls_1_2 && !self.protocols.tls_1_3 {
            bail!("At least one TLS protocol version must be enabled");
        }

        // Validate SNI certificate configurations
        if self.security.sni.enable {
            for (hostname, cert_config) in &self.security.sni.certificates {
                if cert_config.cert.is_empty() {
                    bail!("SNI certificate path for {} cannot be empty", hostname);
                }
                if cert_config.key.is_empty() {
                    bail!("SNI private key path for {} cannot be empty", hostname);
                }
            }
        }

        Ok(())
    }
}

/// Client-specific TLS security configuration
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct TlsClientSecurityConfig {
    /// Server Name Indication (SNI) hostname to use
    #[serde(default)]
    pub sni_hostname: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(default)]
#[derive(Default)]
pub struct TlsClientConfig {
    // Certificate verification configuration
    pub ca: Option<PathBuf>,
    #[serde(default)]
    pub insecure: bool,

    // Client authentication
    pub auth: Option<TlsClientAuthConfig>,

    // Protocol configuration
    #[serde(default)]
    pub protocols: TlsProtocolConfig,

    // Advanced security settings
    #[serde(default)]
    pub security: TlsClientSecurityConfig,

    // Runtime state (not serialized)
    #[serde(skip)]
    client_config: Option<Arc<ClientConfig>>,
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
                vec![
                    SignatureScheme::RSA_PKCS1_SHA256,
                    SignatureScheme::RSA_PKCS1_SHA384,
                    SignatureScheme::RSA_PKCS1_SHA512,
                    SignatureScheme::RSA_PSS_SHA256,
                    SignatureScheme::RSA_PSS_SHA384,
                    SignatureScheme::RSA_PSS_SHA512,
                    SignatureScheme::ECDSA_NISTP256_SHA256,
                    SignatureScheme::ECDSA_NISTP384_SHA384,
                    SignatureScheme::ECDSA_NISTP521_SHA512,
                    SignatureScheme::ED25519,
                ]
            }
        }
        Arc::new(InsecureVerifier)
    }

    // return default roots if ca is undefined
    pub fn root_store(&self) -> Result<RootCertStore> {
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
                ret.add(cert)
                    .with_context(|| "fail to add trusted certificate")?;
            }
        }
        Ok(ret)
    }

    pub fn init(&mut self) -> Result<()> {
        let root_store = self.root_store()?;

        // Configure protocol versions
        let protocol_versions = self.protocols.to_rustls_versions();
        let builder = if protocol_versions.len() == 2
            && self.protocols.tls_1_2
            && self.protocols.tls_1_3
        {
            // Use default builder when both protocols are enabled
            ClientConfig::builder()
        } else {
            // Use specific protocol versions
            tracing::info!(
                "Configuring TLS client with specific protocol versions: TLS 1.2={}, TLS 1.3={}",
                self.protocols.tls_1_2,
                self.protocols.tls_1_3
            );
            ClientConfig::builder_with_protocol_versions(&protocol_versions)
        };

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
                .with_context(|| "failed to load certificate")?
        } else {
            builder.with_no_client_auth()
        };

        // ALPN protocols are managed internally by protocol handlers
        // Client config uses default ALPN negotiation

        let config = Arc::new(config);
        self.client_config = Some(config);
        Ok(())
    }

    pub fn connector(&self) -> Result<TlsConnector> {
        if let Some(config) = &self.client_config {
            Ok(TlsConnector::from(config.clone()))
        } else {
            Err(anyhow!("TlsClientConfig not initialized"))
        }
    }

    /// Get SNI hostname to use for connection
    pub fn sni_hostname(&self) -> Option<&str> {
        self.security.sni_hostname.as_deref()
    }

    /// Validate TLS client configuration
    pub fn validate(&self) -> Result<()> {
        if !self.protocols.tls_1_2 && !self.protocols.tls_1_3 {
            bail!("At least one TLS protocol version must be enabled");
        }

        if let Some(ref ca_path) = self.ca
            && !ca_path.exists()
        {
            bail!("CA certificate file does not exist: {:?}", ca_path);
        }

        if let Some(ref auth_cfg) = self.auth {
            if !auth_cfg.cert.exists() {
                bail!(
                    "Client certificate file does not exist: {:?}",
                    auth_cfg.cert
                );
            }
            if !auth_cfg.key.exists() {
                bail!("Client private key file does not exist: {:?}", auth_cfg.key);
            }
        }

        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TlsClientAuthConfig {
    cert: PathBuf,
    key: PathBuf,
}

impl TlsClientAuthConfig {
    pub fn certs(&self) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
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

fn load_certs<P: AsRef<Path> + std::fmt::Debug>(path: P) -> Result<Vec<CertificateDer<'static>>> {
    let file =
        File::open(&path).with_context(|| format!("failed to read certificates: {:?}", path))?;
    let mut reader = BufReader::new(file);
    let raw = certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| anyhow!("fail to load certificate: {:?}", path))?;
    Ok(raw.into_iter().collect())
}

fn load_keys<P: AsRef<Path> + std::fmt::Debug>(path: P) -> Result<PrivateKeyDer<'static>> {
    let file =
        File::open(&path).with_context(|| format!("failed to read private key: {:?}", path))?;
    let mut reader = BufReader::new(file);
    let item = read_one(&mut reader)
        .with_context(|| format!("fail to load private key: {:?}", path))?
        .ok_or_else(|| anyhow!("no keys loaded from {:?}", path))?;
    let key = match item {
        Item::Pkcs1Key(key) => PrivateKeyDer::Pkcs1(key),
        Item::Pkcs8Key(key) => PrivateKeyDer::Pkcs8(key),
        Item::Sec1Key(key) => PrivateKeyDer::Sec1(key),
        _ => return Err(anyhow!("fail to load private key: {:?}", path)),
    };
    Ok(key)
}
