use redproxy_rs::connectors::ssh::{SshConnectorConfig, ServerKeyVerification};
use serde_yaml_ng::Value;

#[test]
fn test_missing_verification_fails() {
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
    let result: Result<SshConnectorConfig, _> = serde_yaml_ng::from_str(yaml);
    assert!(result.is_err(), "Deserialization should fail when serverKeyVerification is missing");
    let err = result.err().unwrap().to_string();
    assert!(err.contains("missing field `serverKeyVerification`"), "Error message should mention missing field: {}", err);
}

#[test]
fn test_explicit_insecure_verification_succeeds() {
    let yaml = r#"
name: test-ssh
type: ssh
server: ssh.example.com
port: 22
username: testuser
auth:
  type: password
  password: testpass
serverKeyVerification:
  type: insecureAcceptAny
"#;
    let config: SshConnectorConfig = serde_yaml_ng::from_str(yaml).expect("Deserialization should succeed with explicit insecureAcceptAny");
    assert!(matches!(config.server_key_verification, ServerKeyVerification::InsecureAcceptAny));
}

#[test]
fn test_explicit_fingerprint_verification_succeeds() {
    let yaml = r#"
name: test-ssh
type: ssh
server: ssh.example.com
port: 22
username: testuser
auth:
  type: password
  password: testpass
serverKeyVerification:
  type: fingerprint
  fingerprint: "SHA256:abcd"
"#;
    let config: SshConnectorConfig = serde_yaml_ng::from_str(yaml).expect("Deserialization should succeed with explicit fingerprint");
    if let ServerKeyVerification::Fingerprint { fingerprint } = config.server_key_verification {
        assert_eq!(fingerprint, "SHA256:abcd");
    } else {
        panic!("Expected Fingerprint variant");
    }
}
