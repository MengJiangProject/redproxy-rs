#!/usr/bin/env python3
"""
Generate test certificates and SSH keys for matrix testing
"""

import os
import subprocess
import sys

def generate_test_certificates():
    """Generate self-signed certificates for QUIC testing"""
    config_dir = "/config/generated"
    cert_path = f"{config_dir}/server.crt"
    key_path = f"{config_dir}/server.key"
    
    print("Generating self-signed certificate for QUIC testing...")
    
    # Generate RSA certificate for QUIC testing with debug logging
    cmd = [
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key_path,
        "-out", cert_path, "-days", "365", "-nodes", "-subj", 
        "/C=US/ST=Test/L=Test/O=RedProxy/CN=quic-proxy",
        "-addext", "subjectAltName=DNS:quic-proxy,DNS:localhost,IP:127.0.0.1",
        "-addext", "keyUsage=digitalSignature,keyEncipherment",
        "-addext", "extendedKeyUsage=serverAuth,clientAuth",
        "-sha256"
    ]
    
    try:
        subprocess.run(cmd, check=True)
        print(f"✅ Generated certificate: {cert_path}")
        print(f"✅ Generated key: {key_path}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to generate certificates: {e}")
        return False

def generate_ssh_host_key():
    """Generate SSH host key for SSH listener testing"""
    config_dir = "/config/generated"
    key_path = f"{config_dir}/ssh_host_key"
    
    print("Generating SSH host key using OpenSSL...")
    
    # Use openssl to generate SSH key since ssh-keygen might not be available
    cmd = ["openssl", "genrsa", "-out", key_path, "2048"]
    
    try:
        subprocess.run(cmd, check=True)
        # Set proper permissions
        os.chmod(key_path, 0o600)
        print(f"✅ Generated SSH host key: {key_path}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to generate SSH host key: {e}")
        return False
    except Exception as e:
        print(f"❌ Failed to set permissions on SSH key: {e}")
        return False

def main():
    """Generate all test credentials"""
    print("=== Generating Test Credentials for Matrix Testing ===")
    
    # Ensure generated directory exists
    config_dir = "/config/generated"
    os.makedirs(config_dir, exist_ok=True)
    
    success = True
    
    # Generate certificates
    if not generate_test_certificates():
        success = False
    
    # Generate SSH keys
    if not generate_ssh_host_key():
        success = False
    
    if success:
        print("✅ All test credentials generated successfully!")
    else:
        print("❌ Some credentials failed to generate")
        sys.exit(1)

if __name__ == "__main__":
    main()