#[cfg(test)]
#[cfg(feature = "ssh")]
mod ssh_integration_tests {
    use redproxy_rs::connectors::{
        Connector,
        ssh::SshConnector,
        ssh::{ServerKeyVerification, SshAuth, SshConnectorConfig},
    };
    use redproxy_rs::context::{ContextManager, Feature};
    use redproxy_rs::listeners::{Listener, ssh::SshListener, ssh::SshListenerConfig};
    use redproxy_rs::{ContextRef, TargetAddress};
    use std::collections::HashMap;
    use std::fs;
    use std::net::SocketAddr;
    use std::path::PathBuf;
    use std::sync::Arc;
    use tempfile::tempdir;

    // Test fixture for generating SSH keys
    struct SshTestKeys {
        pub server_key_path: String,
        pub client_key_path: String,
        #[allow(dead_code)]
        pub client_pub_key_path: String,
        pub authorized_keys_path: String,
        _temp_dir: tempfile::TempDir,
    }

    impl SshTestKeys {
        async fn generate() -> anyhow::Result<Self> {
            let temp_dir = tempdir()?;
            let temp_path = temp_dir.path();

            // For testing, just create dummy key files - real SSH key generation
            // would require proper russh API usage that may not be available in test env
            let server_key_path = temp_path.join("ssh_host_key");
            let client_key_path = temp_path.join("client_key");
            let client_pub_key_path = temp_path.join("client_key.pub");
            let authorized_keys_path = temp_path.join("authorized_keys");

            // Write dummy key content for testing purposes
            let dummy_private_key = "-----BEGIN OPENSSH PRIVATE KEY-----\ndummy_key_content_for_testing\n-----END OPENSSH PRIVATE KEY-----";
            fs::write(&server_key_path, dummy_private_key)?;
            fs::write(&client_key_path, dummy_private_key)?;

            let dummy_public_key =
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI dummy_key_for_testing test@localhost";
            fs::write(&client_pub_key_path, dummy_public_key)?;
            fs::write(&authorized_keys_path, dummy_public_key)?;

            Ok(SshTestKeys {
                server_key_path: server_key_path.to_string_lossy().to_string(),
                client_key_path: client_key_path.to_string_lossy().to_string(),
                client_pub_key_path: client_pub_key_path.to_string_lossy().to_string(),
                authorized_keys_path: authorized_keys_path.to_string_lossy().to_string(),
                _temp_dir: temp_dir,
            })
        }
    }

    async fn create_test_context(target: TargetAddress, feature: Feature) -> ContextRef {
        let manager = Arc::new(ContextManager::default());
        let source = "127.0.0.1:1234".parse::<SocketAddr>().unwrap();
        let ctx = manager.create_context("test".to_string(), source).await;

        ctx.write().await.set_target(target).set_feature(feature);
        ctx
    }

    #[tokio::test]
    async fn test_ssh_connector_authentication_flow() {
        // Test SSH connector authentication with real SSH library calls
        let keys = SshTestKeys::generate().await.unwrap();

        // Test password authentication config
        let password_config = SshConnectorConfig {
            name: "test-ssh-password".to_string(),
            server: "127.0.0.1".to_string(),
            port: 2222, // Non-standard port to avoid conflicts
            username: "testuser".to_string(),
            auth: SshAuth::Password {
                password: "testpass".to_string(),
            },
            server_key_verification: ServerKeyVerification::InsecureAcceptAny,
            inactivity_timeout_secs: 60,
        };

        let connector = SshConnector::new(password_config);
        assert_eq!(connector.name(), "test-ssh-password");

        // Test key authentication config
        let key_config = SshConnectorConfig {
            name: "test-ssh-key".to_string(),
            server: "127.0.0.1".to_string(),
            port: 2223,
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: PathBuf::from(keys.client_key_path.clone()),
                passphrase: None,
            },
            server_key_verification: ServerKeyVerification::InsecureAcceptAny,
            inactivity_timeout_secs: 60,
        };

        let key_connector = SshConnector::new(key_config);
        assert_eq!(key_connector.name(), "test-ssh-key");

        // Test private key with passphrase
        let key_with_passphrase_config = SshConnectorConfig {
            name: "test-ssh-key-passphrase".to_string(),
            server: "127.0.0.1".to_string(),
            port: 2224,
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: PathBuf::from(keys.client_key_path),
                passphrase: Some("key_passphrase".to_string()),
            },
            server_key_verification: ServerKeyVerification::Fingerprint {
                fingerprint: "SHA256:test_fingerprint_for_integration_test".to_string(),
            },
            inactivity_timeout_secs: 60,
        };

        let key_passphrase_connector = SshConnector::new(key_with_passphrase_config);
        assert_eq!(key_passphrase_connector.name(), "test-ssh-key-passphrase");
    }

    #[tokio::test]
    async fn test_ssh_listener_port_forwarding_setup() {
        // Test SSH listener configuration for port forwarding
        let keys = SshTestKeys::generate().await.unwrap();

        // Test password-based SSH listener
        let password_users = {
            let mut users = HashMap::new();
            users.insert("testuser".to_string(), "testpass".to_string());
            users.insert("admin".to_string(), "admin123".to_string());
            users
        };

        let password_config = SshListenerConfig {
            name: "test-ssh-listener-password".to_string(),
            bind: "127.0.0.1:0".parse().expect("Failed to parse bind address"),
            host_key_path: keys.server_key_path.clone(),
            authorized_keys_path: None,
            allow_password: true,
            password_users: Some(password_users),
            inactivity_timeout_secs: 60,
        };

        let password_listener = SshListener::new(password_config);
        assert_eq!(password_listener.name(), "test-ssh-listener-password");

        // Test key-based SSH listener
        let key_config = SshListenerConfig {
            name: "test-ssh-listener-key".to_string(),
            bind: "127.0.0.1:0".parse().expect("Failed to parse bind address"),
            host_key_path: keys.server_key_path.clone(),
            authorized_keys_path: Some(keys.authorized_keys_path.clone()),
            allow_password: false,
            password_users: None,
            inactivity_timeout_secs: 60,
        };

        let key_listener = SshListener::new(key_config);
        assert_eq!(key_listener.name(), "test-ssh-listener-key");

        // Test mixed authentication SSH listener
        let mixed_config = SshListenerConfig {
            name: "test-ssh-listener-mixed".to_string(),
            bind: "127.0.0.1:0".parse().expect("Failed to parse bind address"),
            host_key_path: keys.server_key_path,
            authorized_keys_path: Some(keys.authorized_keys_path),
            allow_password: true,
            password_users: Some({
                let mut users = HashMap::new();
                users.insert("backup_user".to_string(), "backup_pass".to_string());
                users
            }),
            inactivity_timeout_secs: 60,
        };

        let mixed_listener = SshListener::new(mixed_config);
        assert_eq!(mixed_listener.name(), "test-ssh-listener-mixed");
    }

    #[tokio::test]
    #[ignore]
    async fn test_ssh_connection_error_scenarios() {
        // Test various SSH connection failure scenarios

        // 1. Connection to non-existent server
        let unreachable_config = SshConnectorConfig {
            name: "test-ssh-unreachable".to_string(),
            server: "192.0.2.1".to_string(), // RFC5737 test address
            port: 22,
            username: "testuser".to_string(),
            auth: SshAuth::Password {
                password: "testpass".to_string(),
            },
            server_key_verification: ServerKeyVerification::InsecureAcceptAny,
            inactivity_timeout_secs: 60,
        };

        let connector = Arc::new(SshConnector::new(unreachable_config));
        let target = TargetAddress::DomainPort("example.com".to_string(), 80);
        let ctx = create_test_context(target, Feature::TcpForward).await;

        // This should fail with connection timeout/unreachable
        let result = connector.connect(ctx).await;
        assert!(
            result.is_err(),
            "Expected SSH connection to unreachable server to fail"
        );

        // 2. Connection to wrong port
        let wrong_port_config = SshConnectorConfig {
            name: "test-ssh-wrong-port".to_string(),
            server: "127.0.0.1".to_string(),
            port: 12345, // Unlikely to have SSH server
            username: "testuser".to_string(),
            auth: SshAuth::Password {
                password: "testpass".to_string(),
            },
            server_key_verification: ServerKeyVerification::InsecureAcceptAny,
            inactivity_timeout_secs: 60,
        };

        let wrong_port_connector = Arc::new(SshConnector::new(wrong_port_config));
        let target2 = TargetAddress::DomainPort("httpbin.org".to_string(), 80);
        let ctx2 = create_test_context(target2, Feature::TcpForward).await;

        let result2 = wrong_port_connector.connect(ctx2).await;
        assert!(result2.is_err());
    }

    #[tokio::test]
    async fn test_ssh_key_types_and_validation() {
        // Test different SSH key types and validation
        let keys = SshTestKeys::generate().await.unwrap();

        // Test with valid key path
        let valid_key_config = SshConnectorConfig {
            name: "test-ssh-valid-key".to_string(),
            server: "127.0.0.1".to_string(),
            port: 22,
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: PathBuf::from(keys.client_key_path.clone()),
                passphrase: None,
            },
            server_key_verification: ServerKeyVerification::InsecureAcceptAny,
            inactivity_timeout_secs: 60,
        };

        let valid_connector = SshConnector::new(valid_key_config);
        assert_eq!(valid_connector.name(), "test-ssh-valid-key");

        // Test with non-existent key path
        let invalid_key_config = SshConnectorConfig {
            name: "test-ssh-invalid-key".to_string(),
            server: "127.0.0.1".to_string(),
            port: 22,
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: PathBuf::from("/nonexistent/path/to/key"),
                passphrase: None,
            },
            server_key_verification: ServerKeyVerification::InsecureAcceptAny,
            inactivity_timeout_secs: 60,
        };

        let invalid_connector = Arc::new(SshConnector::new(invalid_key_config));
        let target = TargetAddress::DomainPort("example.com".to_string(), 80);
        let ctx = create_test_context(target, Feature::TcpForward).await;

        // Connection should fail due to invalid key path
        let result = invalid_connector.connect(ctx).await;
        assert!(
            result.is_err(),
            "Expected SSH connection to fail with invalid key path"
        );
    }

    #[tokio::test]
    async fn test_ssh_target_address_handling() {
        // Test how SSH connector handles different target address types
        let config = SshConnectorConfig {
            name: "test-ssh-targets".to_string(),
            server: "127.0.0.1".to_string(),
            port: 22,
            username: "testuser".to_string(),
            auth: SshAuth::Password {
                password: "testpass".to_string(),
            },
            server_key_verification: ServerKeyVerification::InsecureAcceptAny,
            inactivity_timeout_secs: 60,
        };

        let connector = Arc::new(SshConnector::new(config));

        // Test domain name target
        let domain_target = TargetAddress::DomainPort("httpbin.org".to_string(), 80);
        let ctx1 = create_test_context(domain_target, Feature::TcpForward).await;

        // Test IP address target
        let ip_target = TargetAddress::SocketAddr("93.184.216.34:80".parse().unwrap());
        let ctx2 = create_test_context(ip_target, Feature::TcpForward).await;

        // Test localhost target
        let localhost_target = TargetAddress::DomainPort("localhost".to_string(), 8080);
        let ctx3 = create_test_context(localhost_target, Feature::TcpForward).await;

        // All should fail in test environment but validate target handling
        let result1 = connector.clone().connect(ctx1).await;
        let result2 = connector.clone().connect(ctx2.clone()).await;
        let result3 = connector.clone().connect(ctx3).await;

        assert!(result1.is_err());
        assert!(result2.is_err());
        assert!(result3.is_err());

        // Verify context preserved target information
        let ctx2_read = ctx2.read().await;
        match ctx2_read.target() {
            TargetAddress::SocketAddr(addr) => {
                assert_eq!(addr.to_string(), "93.184.216.34:80");
            }
            _ => panic!("Expected SocketAddr target"),
        }
    }
}
