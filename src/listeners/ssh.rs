use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::Arc,
};

use anyhow::{Context as AnyhowContext, Result, bail};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::Sender;
use tracing::{debug, info, warn};

use crate::{
    config::Timeouts,
    context::{
        Context, ContextCallback, ContextManager, ContextRef, ContextRefOps, Feature,
        TargetAddress, make_buffered_stream,
    },
};
use russh::Channel;
use russh::keys::ssh_key;
use russh::server::{Auth, Msg, Server};

fn default_listener_timeout() -> u64 {
    300
}

fn default_bind_addr() -> SocketAddr {
    "0.0.0.0:2222".parse().unwrap()
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SshListenerConfig {
    pub name: String,
    pub bind: SocketAddr,
    pub host_key_path: String,
    #[serde(default)]
    pub authorized_keys_path: Option<String>,
    #[serde(default)]
    pub allow_password: bool,
    #[serde(default)]
    pub password_users: Option<HashMap<String, String>>,
    #[serde(default = "default_listener_timeout")]
    pub inactivity_timeout_secs: u64,
}

impl Default for SshListenerConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            bind: default_bind_addr(),
            host_key_path: String::new(),
            authorized_keys_path: None,
            allow_password: false,
            password_users: None,
            inactivity_timeout_secs: default_listener_timeout(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SshListener {
    #[serde(flatten)]
    config: SshListenerConfig,
    #[serde(skip)]
    authorized_keys: Option<HashSet<russh::keys::ssh_key::PublicKey>>,
    #[serde(skip)]
    host_key: Option<russh::keys::ssh_key::PrivateKey>,
}

impl SshListener {
    pub fn new(config: SshListenerConfig) -> Self {
        Self {
            config,
            authorized_keys: None,
            host_key: None,
        }
    }

    // Load authorized keys from file
    async fn load_authorized_keys(path: &str) -> Result<HashSet<russh::keys::ssh_key::PublicKey>> {
        let keys_content = tokio::fs::read_to_string(path)
            .await
            .with_context(|| format!("failed to read authorized keys from {}", path))?;

        let mut keys = HashSet::new();
        for line in keys_content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse SSH public key format: "ssh-ed25519 AAAAC3Nz... comment"
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                match russh::keys::parse_public_key_base64(parts[1]) {
                    Ok(key) => {
                        keys.insert(key);
                    }
                    Err(e) => {
                        warn!("Failed to parse public key in {}: {}", path, e);
                        continue;
                    }
                }
            } else {
                warn!("Invalid SSH key format in {}: {}", path, line);
                continue;
            }
        }
        Ok(keys)
    }
}

pub fn from_value(value: &serde_yaml_ng::Value) -> Result<Box<dyn super::Listener>> {
    let config: SshListenerConfig = serde_yaml_ng::from_value(value.clone())
        .with_context(|| "failed to parse SSH listener config")?;

    // Validate authentication configuration
    if !config.allow_password && config.authorized_keys_path.is_none() {
        bail!(
            "SSH listener must allow either password authentication or have authorized_keys_path"
        );
    }

    Ok(Box::new(SshListener::new(config)))
}

struct SshCallback {
    result_sender: tokio::sync::Mutex<Option<tokio::sync::oneshot::Sender<bool>>>,
}

impl SshCallback {
    fn new(sender: tokio::sync::oneshot::Sender<bool>) -> Self {
        Self {
            result_sender: tokio::sync::Mutex::new(Some(sender)),
        }
    }

    async fn send_result(&self, success: bool) {
        if let Some(sender) = self.result_sender.lock().await.take() {
            let _ = sender.send(success); // Ignore if receiver dropped
        }
    }
}

#[async_trait]
impl ContextCallback for SshCallback {
    async fn on_connect(&self, _ctx: &mut Context) {
        // Connection successful - notify SSH handler
        debug!("SSH tunnel upstream connection established");
        self.send_result(true).await;
    }

    async fn on_error(&self, _ctx: &mut Context, error: anyhow::Error) {
        // Connection failed - notify SSH handler
        warn!("SSH tunnel upstream connection failed: {}", error);
        self.send_result(false).await;
    }

    async fn on_finish(&self, _ctx: &mut Context) {
        // Connection finished normally - this shouldn't affect the initial result
        debug!("SSH tunnel connection finished");
    }
}

#[async_trait]
impl super::Listener for SshListener {
    async fn init(&mut self) -> Result<()> {
        // Load host key during initialization
        let host_key_data = tokio::fs::read(&self.config.host_key_path)
            .await
            .with_context(|| {
                format!("failed to read host key from {}", self.config.host_key_path)
            })?;

        self.host_key = Some(
            russh::keys::decode_secret_key(&String::from_utf8_lossy(&host_key_data), None)
                .with_context(|| "failed to decode host key during init")?,
        );

        // Load authorized keys during initialization if configured
        if let Some(ref path) = self.config.authorized_keys_path {
            self.authorized_keys = Some(
                Self::load_authorized_keys(path)
                    .await
                    .with_context(|| "failed to load authorized keys during init")?,
            );
        }
        Ok(())
    }

    async fn verify(&self) -> Result<()> {
        // Verify SSH configuration is valid

        // Check that authentication is properly configured
        if !self.config.allow_password && self.config.authorized_keys_path.is_none() {
            bail!(
                "SSH listener must allow either password authentication or have authorized_keys_path"
            );
        }

        // Verify host key file exists and is readable
        if let Err(e) = tokio::fs::metadata(&self.config.host_key_path).await {
            bail!(
                "SSH host key file '{}' is not accessible: {}",
                self.config.host_key_path,
                e
            );
        }

        // Verify authorized keys file exists and is readable if configured
        if let Some(ref path) = self.config.authorized_keys_path
            && let Err(e) = tokio::fs::metadata(path).await
        {
            bail!(
                "SSH authorized keys file '{}' is not accessible: {}",
                path,
                e
            );
        }

        Ok(())
    }
    async fn listen(
        self: Arc<Self>,
        contexts: Arc<ContextManager>,
        _timeouts: Timeouts,
        queue: Sender<ContextRef>,
    ) -> Result<()> {
        info!("Starting SSH listener on {}", self.config.bind);

        // Use pre-loaded host key and authorized keys from init()
        let host_key = self
            .host_key
            .clone()
            .ok_or_else(|| anyhow::anyhow!("Host key not loaded - init() must be called first"))?;
        let authorized_keys = self.authorized_keys.clone();

        // Create SSH server configuration
        let ssh_config = Arc::new(russh::server::Config {
            inactivity_timeout: Some(std::time::Duration::from_secs(
                self.config.inactivity_timeout_secs,
            )),
            auth_rejection_time: std::time::Duration::from_secs(1),
            auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
            keys: vec![host_key],
            ..Default::default()
        });

        // Create SSH server
        let mut ssh_server = SshServer::new(
            self.name().to_string(),
            contexts,
            queue,
            self.config.clone(),
            authorized_keys,
        );

        info!("SSH listener started on {}", self.config.bind);

        // Run the SSH server
        ssh_server
            .run_on_address(ssh_config, self.config.bind)
            .await
            .with_context(|| "SSH server failed")?;

        Ok(())
    }

    fn name(&self) -> &str {
        &self.config.name
    }
}

#[derive(Clone)]
struct SshServer {
    name: String,
    contexts: Arc<ContextManager>,
    queue: Sender<ContextRef>,
    config: SshListenerConfig,
    authorized_keys: Option<HashSet<russh::keys::ssh_key::PublicKey>>,
}

impl SshServer {
    fn new(
        name: String,
        contexts: Arc<ContextManager>,
        queue: Sender<ContextRef>,
        config: SshListenerConfig,
        authorized_keys: Option<HashSet<russh::keys::ssh_key::PublicKey>>,
    ) -> Self {
        Self {
            name,
            contexts,
            queue,
            config,
            authorized_keys,
        }
    }
}

#[async_trait]
impl russh::server::Server for SshServer {
    type Handler = Self;

    fn new_client(&mut self, peer_addr: Option<std::net::SocketAddr>) -> Self::Handler {
        debug!("SSH new client connection from: {:?}", peer_addr);
        self.clone()
    }
}

impl russh::server::Handler for SshServer {
    type Error = anyhow::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        if !self.config.allow_password {
            return Ok(Auth::reject());
        }

        if let Some(ref users) = self.config.password_users
            && let Some(expected_password) = users.get(user)
            && password == expected_password
        {
            debug!("SSH password authentication successful for user: {}", user);
            return Ok(Auth::Accept);
        }

        debug!("SSH password authentication failed for user: {}", user);
        Ok(Auth::reject())
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &ssh_key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        debug!("SSH auth_publickey called for user: {}", user);

        if let Some(ref keys) = self.authorized_keys {
            if keys.contains(public_key) {
                debug!("SSH public key authentication ACCEPTED for user: {}", user);
                return Ok(Auth::Accept);
            }
        } else {
            debug!("No authorized keys configured");
        }

        debug!("SSH public key authentication REJECTED for user: {}", user);
        Ok(Auth::reject())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
        _session: &mut russh::server::Session,
    ) -> Result<bool, Self::Error> {
        debug!(
            "SSH direct-tcpip request: {}:{} from {}:{}",
            host_to_connect, port_to_connect, originator_address, originator_port
        );

        // Create a context for this connection
        let target = TargetAddress::from((host_to_connect.to_string(), port_to_connect as u16));

        // Parse originator address - if it fails, log warning and use localhost
        let source_addr = match originator_address.parse::<std::net::IpAddr>() {
            Ok(ip) => std::net::SocketAddr::new(ip, originator_port as u16),
            Err(e) => {
                warn!(
                    "Invalid SSH originator address '{}': {}, using localhost instead",
                    originator_address, e
                );
                std::net::SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                    originator_port as u16,
                )
            }
        };

        let ctx = self
            .contexts
            .create_context(self.name.clone(), source_addr)
            .await;

        // Create a channel to wait for connection result
        let (result_tx, result_rx) = tokio::sync::oneshot::channel::<bool>();

        // Create callback that signals the result
        let callback = SshCallback::new(result_tx);

        // Convert channel to stream
        let channel_stream = channel.into_stream();

        // Set the client stream and configure context with callback
        ctx.write()
            .await
            .set_client_stream(make_buffered_stream(Box::new(channel_stream)))
            .set_target(target)
            .set_feature(Feature::TcpForward)
            .set_callback(callback);

        // Queue the context for processing through the framework
        ctx.enqueue(&self.queue).await?;

        debug!(
            "SSH tunnel context queued for {}:{}, waiting for connection result",
            host_to_connect, port_to_connect
        );

        // Wait for the connection result before returning to SSH client
        match result_rx.await {
            Ok(success) => {
                if success {
                    debug!(
                        "SSH tunnel connection successful for {}:{}",
                        host_to_connect, port_to_connect
                    );
                } else {
                    debug!(
                        "SSH tunnel connection failed for {}:{}",
                        host_to_connect, port_to_connect
                    );
                }
                Ok(success)
            }
            Err(_) => {
                warn!("SSH tunnel callback channel closed unexpectedly");
                Ok(false)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_yaml_ng::Value;
    use std::collections::HashMap;

    #[test]
    fn test_ssh_listener_config_password() {
        let yaml = r#"
name: test-ssh-listener
type: ssh
bind: "127.0.0.1:2222"
hostKeyPath: /etc/ssh/ssh_host_rsa_key
allowPassword: true
passwordUsers:
  testuser: testpass
"#;
        let value: Value = serde_yaml_ng::from_str(yaml).expect("Failed to parse test YAML");
        let listener = from_value(&value).expect("Failed to deserialize SSH listener config");
        assert_eq!(listener.name(), "test-ssh-listener");
    }

    #[test]
    fn test_ssh_listener_config_keys() {
        let yaml = r#"
name: test-ssh-listener-keys
type: ssh
bind: "127.0.0.1:2222"
hostKeyPath: /etc/ssh/ssh_host_rsa_key
authorizedKeysPath: /home/user/.ssh/authorized_keys
"#;
        let value: Value = serde_yaml_ng::from_str(yaml).expect("Failed to parse test YAML");
        let listener = from_value(&value).expect("Failed to deserialize SSH listener config");
        assert_eq!(listener.name(), "test-ssh-listener-keys");
    }

    #[test]
    fn test_ssh_listener_config_both_auth() {
        let yaml = r#"
name: test-ssh-listener-both
type: ssh
bind: "127.0.0.1:2222"
hostKeyPath: /etc/ssh/ssh_host_rsa_key
allowPassword: true
passwordUsers:
  testuser: testpass
authorizedKeysPath: /home/user/.ssh/authorized_keys
"#;
        let value: Value = serde_yaml_ng::from_str(yaml).expect("Failed to parse test YAML");
        let listener = from_value(&value).expect("Failed to deserialize SSH listener config");
        assert_eq!(listener.name(), "test-ssh-listener-both");
    }

    #[test]
    fn test_ssh_listener_config_no_auth() {
        let yaml = r#"
name: test-ssh-listener-invalid
type: ssh
bind: "127.0.0.1:2222"
hostKeyPath: /etc/ssh/ssh_host_rsa_key
"#;
        let value: Value = serde_yaml_ng::from_str(yaml).expect("Failed to parse test YAML");
        assert!(
            from_value(&value).is_err(),
            "Should fail with no auth methods"
        );
    }

    #[test]
    fn test_ssh_listener_config_password_disabled() {
        let yaml = r#"
name: test-ssh-listener-keys-only
type: ssh
bind: "127.0.0.1:2222"
hostKeyPath: /etc/ssh/ssh_host_rsa_key
allowPassword: false
authorizedKeysPath: /home/user/.ssh/authorized_keys
"#;
        let value: Value = serde_yaml_ng::from_str(yaml).expect("Failed to parse test YAML");
        let listener = from_value(&value).expect("Failed to deserialize SSH listener config");
        assert_eq!(listener.name(), "test-ssh-listener-keys-only");
    }

    #[test]
    fn test_ssh_listener_config_custom_port() {
        let yaml = r#"
name: test-ssh-listener-custom
type: ssh
bind: "0.0.0.0:2222"
hostKeyPath: /etc/ssh/ssh_host_rsa_key
allowPassword: true
passwordUsers:
  admin: admin123
"#;
        let value: Value = serde_yaml_ng::from_str(yaml).expect("Failed to parse test YAML");
        let listener = from_value(&value).expect("Failed to deserialize SSH listener config");
        assert_eq!(listener.name(), "test-ssh-listener-custom");
    }

    #[test]
    fn test_ssh_listener_config_ipv6() {
        let yaml = r#"
name: test-ssh-listener-ipv6
type: ssh
bind: "[::1]:2222"
hostKeyPath: /etc/ssh/ssh_host_rsa_key
allowPassword: true
passwordUsers:
  user: pass
"#;
        let value: Value = serde_yaml_ng::from_str(yaml).expect("Failed to parse test YAML");
        let listener = from_value(&value).expect("Failed to deserialize SSH listener config");
        assert_eq!(listener.name(), "test-ssh-listener-ipv6");
    }

    #[test]
    fn test_ssh_listener_config_multiple_users() {
        let yaml = r#"
name: test-ssh-listener-multi
type: ssh
bind: "127.0.0.1:2222"
hostKeyPath: /etc/ssh/ssh_host_rsa_key
allowPassword: true
passwordUsers:
  user1: pass1
  user2: pass2
  admin: secretpass
"#;
        let value: Value = serde_yaml_ng::from_str(yaml).expect("Failed to parse test YAML");
        let listener = from_value(&value).expect("Failed to deserialize SSH listener config");
        assert_eq!(listener.name(), "test-ssh-listener-multi");
    }

    #[test]
    fn test_ssh_listener_config_missing_host_key() {
        let yaml = r#"
name: test-ssh-listener-invalid
type: ssh
bind: "127.0.0.1:2222"
allowPassword: true
passwordUsers:
  testuser: testpass
"#;
        let value: Value = serde_yaml_ng::from_str(yaml).expect("Failed to parse test YAML");
        // Should fail due to missing required hostKeyPath
        assert!(
            from_value(&value).is_err(),
            "Should fail when hostKeyPath is missing"
        );
    }

    #[test]
    fn test_ssh_listener_config_missing_bind() {
        let yaml = r#"
name: test-ssh-listener-invalid
type: ssh
hostKeyPath: /etc/ssh/ssh_host_rsa_key
allowPassword: true
passwordUsers:
  testuser: testpass
"#;
        let value: Value = serde_yaml_ng::from_str(yaml).expect("Failed to parse test YAML");
        // Should fail due to missing required bind address
        assert!(
            from_value(&value).is_err(),
            "Should fail when bind is missing"
        );
    }

    #[test]
    fn test_ssh_listener_config_deserialize() {
        let config = SshListenerConfig {
            name: "test".to_string(),
            bind: "127.0.0.1:2222"
                .parse()
                .expect("Failed to parse bind address"),
            host_key_path: "/etc/ssh/host_key".to_string(),
            authorized_keys_path: Some("/home/user/.ssh/authorized_keys".to_string()),
            allow_password: true,
            password_users: Some({
                let mut users = HashMap::new();
                users.insert("user".to_string(), "pass".to_string());
                users
            }),
            inactivity_timeout_secs: 60,
        };

        // Test that the config can be serialized and deserialized
        let serialized = serde_yaml_ng::to_string(&config).expect("Failed to serialize config");
        let deserialized: SshListenerConfig =
            serde_yaml_ng::from_str(&serialized).expect("Failed to deserialize config");
        assert_eq!(config.name, deserialized.name);
        assert_eq!(config.bind, deserialized.bind);
        assert_eq!(config.allow_password, deserialized.allow_password);
    }
}
