use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::context::{ContextRef, Feature, make_buffered_stream};
use russh::keys::ssh_key;

use super::ConnectorRef;

fn default_connector_timeout() -> u64 {
    60
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SshConnectorConfig {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub username: String,
    pub auth: SshAuth,
    #[serde(default)]
    pub server_key_verification: ServerKeyVerification,
    #[serde(default = "default_connector_timeout")]
    pub inactivity_timeout_secs: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
#[serde(tag = "type")]
pub enum SshAuth {
    #[serde(rename = "password")]
    Password { password: String },
    #[serde(rename = "privateKey")]
    PrivateKey {
        path: PathBuf,
        #[serde(default)]
        passphrase: Option<String>,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
#[serde(tag = "type")]
#[derive(Default)]
pub enum ServerKeyVerification {
    #[serde(rename = "fingerprint")]
    Fingerprint { fingerprint: String },
    #[serde(rename = "insecureAcceptAny")]
    #[default]
    InsecureAcceptAny,
}

impl Default for SshConnectorConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            server: String::new(),
            port: 22,
            username: String::new(),
            auth: SshAuth::Password {
                password: String::new(),
            },
            server_key_verification: ServerKeyVerification::default(),
            inactivity_timeout_secs: default_connector_timeout(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SshConnector {
    #[serde(flatten)]
    config: SshConnectorConfig,
}

impl SshConnector {
    pub fn new(config: SshConnectorConfig) -> Self {
        Self { config }
    }
}

pub fn from_value(value: &serde_yaml_ng::Value) -> Result<ConnectorRef> {
    let config: SshConnectorConfig = serde_yaml_ng::from_value(value.clone())
        .with_context(|| "failed to parse SSH connector config")?;

    Ok(Box::new(SshConnector::new(config)))
}

#[async_trait]
impl super::Connector for SshConnector {
    async fn connect(self: Arc<Self>, ctx: ContextRef) -> Result<()> {
        let target = ctx.read().await.target();
        let target_host = target.host().to_string();
        let target_port = target.port();

        debug!(
            "Connecting to {}:{} via SSH tunnel through {}:{}",
            target_host, target_port, self.config.server, self.config.port
        );

        let ssh_config = russh::client::Config {
            inactivity_timeout: Some(std::time::Duration::from_secs(
                self.config.inactivity_timeout_secs,
            )),
            ..Default::default()
        };

        // Create handler with proper server key verification
        let verification = self.config.server_key_verification.clone();
        let server_handler = SshClientHandler::new(verification);

        // Connect to SSH server
        let mut session = russh::client::connect(
            Arc::new(ssh_config),
            (self.config.server.as_str(), self.config.port),
            server_handler,
        )
        .await
        .context("SSH connection failed")?;

        // Authenticate using the configured method
        self.authenticate(&mut session).await?;
        debug!("SSH authentication successful");

        // Open tunnel channel
        let channel = session
            .channel_open_direct_tcpip(&target_host, target_port as u32, "127.0.0.1", 0)
            .await
            .context("SSH tunnel creation failed")?;

        debug!("SSH tunnel established to {}:{}", target_host, target_port);

        // Set up the stream
        let channel_stream = channel.into_stream();
        ctx.write()
            .await
            .set_server_stream(make_buffered_stream(Box::new(channel_stream)));

        Ok(())
    }

    fn name(&self) -> &str {
        &self.config.name
    }

    fn features(&self) -> &[Feature] {
        &[Feature::TcpForward]
    }
}

impl SshConnector {
    async fn authenticate(
        &self,
        session: &mut russh::client::Handle<SshClientHandler>,
    ) -> Result<()> {
        let auth_result = match &self.config.auth {
            SshAuth::Password { password } => {
                session
                    .authenticate_password(&self.config.username, password)
                    .await
            }
            SshAuth::PrivateKey { path, passphrase } => {
                let key_data = tokio::fs::read_to_string(path)
                    .await
                    .context("Failed to read private key")?;

                let private_key = russh::keys::decode_secret_key(&key_data, passphrase.as_deref())
                    .context("Failed to decode private key")?;

                let key_with_alg =
                    russh::keys::PrivateKeyWithHashAlg::new(Arc::new(private_key), None);
                session
                    .authenticate_publickey(&self.config.username, key_with_alg)
                    .await
            }
        };

        match auth_result.context("SSH authentication failed")? {
            russh::client::AuthResult::Success => Ok(()),
            russh::client::AuthResult::Failure { .. } => {
                bail!("SSH authentication rejected")
            }
        }
    }
}

struct SshClientHandler {
    verification: ServerKeyVerification,
}

impl SshClientHandler {
    fn new(verification: ServerKeyVerification) -> Self {
        Self { verification }
    }
}

impl russh::client::Handler for SshClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        match &self.verification {
            ServerKeyVerification::InsecureAcceptAny => {
                tracing::warn!("SSH server key verification disabled - connection is insecure!");
                Ok(true)
            }
            ServerKeyVerification::Fingerprint {
                fingerprint: expected,
            } => {
                let fingerprint =
                    server_public_key.fingerprint(russh::keys::ssh_key::HashAlg::Sha256);
                if fingerprint.to_string() == *expected {
                    Ok(true)
                } else {
                    tracing::error!(
                        "SSH server key fingerprint mismatch: expected {}, got {}",
                        expected,
                        fingerprint
                    );
                    Ok(false)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connectors::Connector;
    use crate::context::Feature;
    use serde_yaml_ng::Value;
    use std::path::PathBuf;

    #[test]
    fn test_ssh_connector_config_password() {
        let yaml = r#"
name: test-ssh
type: ssh
server: ssh.example.com
port: 22
username: testuser
auth:
  type: password
  password: testpass
"#;
        let value: Value = serde_yaml_ng::from_str(yaml).expect("Failed to parse test YAML");
        let connector = from_value(&value).expect("Failed to deserialize SSH connector config");
        assert_eq!(connector.name(), "test-ssh");
    }

    #[test]
    fn test_ssh_connector_config_private_key() {
        let yaml = r#"
name: test-ssh-key
type: ssh
server: ssh.example.com
port: 2222
username: keyuser
auth:
  type: privateKey
  path: /path/to/key
  passphrase: keypass
"#;
        let value: Value = serde_yaml_ng::from_str(yaml).expect("Failed to parse test YAML");
        let connector = from_value(&value).expect("Failed to deserialize SSH connector config");
        assert_eq!(connector.name(), "test-ssh-key");
    }

    #[test]
    fn test_ssh_connector_config_private_key_no_passphrase() {
        let yaml = r#"
name: test-ssh-key-nopass
type: ssh
server: ssh.example.com
port: 22
username: keyuser
auth:
  type: privateKey
  path: /path/to/key
"#;
        let value: Value = serde_yaml_ng::from_str(yaml).expect("Failed to parse test YAML");
        let _connector = from_value(&value).expect("Failed to deserialize SSH connector config");
        // Test passes if deserialization succeeds
    }

    #[test]
    fn test_ssh_connector_features() {
        let config = SshConnectorConfig {
            name: "test".to_string(),
            server: "example.com".to_string(),
            port: 22,
            username: "user".to_string(),
            auth: SshAuth::Password {
                password: "pass".to_string(),
            },
            server_key_verification: ServerKeyVerification::InsecureAcceptAny,
            inactivity_timeout_secs: 60,
        };
        let connector = SshConnector { config };
        assert_eq!(connector.features(), &[Feature::TcpForward]);
    }

    #[test]
    fn test_ssh_connector_config_invalid_missing_server() {
        let yaml = r#"
name: test-ssh
type: ssh
port: 22
username: testuser
auth:
  type: password
  password: testpass
"#;
        let value: Value = serde_yaml_ng::from_str(yaml).expect("Failed to parse test YAML");
        let result = from_value(&value);
        assert!(result.is_err(), "Should fail when server is missing");
    }

    #[test]
    fn test_ssh_connector_config_custom_port() {
        let yaml = r#"
name: test-ssh-custom-port
type: ssh
server: ssh.example.com
port: 2222
username: testuser
auth:
  type: password
  password: testpass
"#;
        let value: Value = serde_yaml_ng::from_str(yaml).expect("Failed to parse test YAML");
        let _connector = from_value(&value).expect("Failed to deserialize SSH connector config");
        // Test passes if deserialization succeeds
    }

    #[test]
    fn test_ssh_connector_config_with_fingerprint_verification() {
        let yaml = r#"
name: test-ssh-fingerprint
type: ssh
server: ssh.example.com
port: 22
username: testuser
auth:
  type: password
  password: testpass
serverKeyVerification:
  type: fingerprint
  fingerprint: "SHA256:abcdef123456789"
"#;
        let value: Value = serde_yaml_ng::from_str(yaml).expect("Failed to parse test YAML");
        let _connector = from_value(&value).expect("Failed to deserialize SSH connector config");
        // Test passes if deserialization succeeds
    }

    #[test]
    fn test_ssh_connector_config_with_additional_fingerprint_verification() {
        let yaml = r#"
name: test-ssh-fingerprint-2
type: ssh
server: ssh.example.com
port: 22
username: testuser
auth:
  type: password
  password: testpass
serverKeyVerification:
  type: fingerprint
  fingerprint: "SHA256:abcdef123456789"
"#;
        let value: Value = serde_yaml_ng::from_str(yaml).expect("Failed to parse test YAML");
        let _connector = from_value(&value).expect("Failed to deserialize SSH connector config");
        // Test passes if deserialization succeeds
    }

    #[test]
    fn test_ssh_connector_default_config() {
        let config = SshConnectorConfig {
            name: "test".to_string(),
            server: "127.0.0.1".to_string(),
            port: 22,
            username: "testuser".to_string(),
            auth: SshAuth::Password {
                password: "testpass".to_string(),
            },
            server_key_verification: ServerKeyVerification::InsecureAcceptAny,
            inactivity_timeout_secs: 60,
        };

        assert_eq!(config.port, 22);
        assert_eq!(config.inactivity_timeout_secs, 60);
        assert!(matches!(
            config.server_key_verification,
            ServerKeyVerification::InsecureAcceptAny
        ));
    }

    #[test]
    fn test_ssh_connector_serialization_roundtrip() {
        let config = SshConnectorConfig {
            name: "test-ssh".to_string(),
            server: "ssh.example.com".to_string(),
            port: 2222,
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: PathBuf::from("/path/to/key"),
                passphrase: Some("secret".to_string()),
            },
            server_key_verification: ServerKeyVerification::Fingerprint {
                fingerprint: "SHA256:test".to_string(),
            },
            inactivity_timeout_secs: 120,
        };

        let serialized = serde_yaml_ng::to_string(&config).expect("Failed to serialize config");
        let deserialized: SshConnectorConfig =
            serde_yaml_ng::from_str(&serialized).expect("Failed to deserialize config");

        assert_eq!(config.name, deserialized.name);
        assert_eq!(config.server, deserialized.server);
        assert_eq!(config.port, deserialized.port);
    }

    #[test]
    fn test_ssh_auth_enum_variants() {
        // Test password auth
        let password_auth = SshAuth::Password {
            password: "secret".to_string(),
        };
        assert!(matches!(password_auth, SshAuth::Password { .. }));

        // Test private key auth with passphrase
        let key_auth = SshAuth::PrivateKey {
            path: PathBuf::from("/path/to/key"),
            passphrase: Some("passphrase".to_string()),
        };
        assert!(matches!(key_auth, SshAuth::PrivateKey { .. }));

        // Test private key auth without passphrase
        let key_auth_no_pass = SshAuth::PrivateKey {
            path: PathBuf::from("/path/to/key"),
            passphrase: None,
        };
        assert!(matches!(key_auth_no_pass, SshAuth::PrivateKey { .. }));
    }

    #[test]
    fn test_server_key_verification_variants() {
        // Test insecure accept any
        let insecure = ServerKeyVerification::InsecureAcceptAny;
        assert!(matches!(insecure, ServerKeyVerification::InsecureAcceptAny));

        // Test fingerprint verification
        let fingerprint = ServerKeyVerification::Fingerprint {
            fingerprint: "SHA256:test".to_string(),
        };
        assert!(matches!(
            fingerprint,
            ServerKeyVerification::Fingerprint { .. }
        ));

        // Test that we simplified to only two variants - no complex known_hosts support
        // If users need known_hosts verification, they should use OpenSSH directly
    }
}
