#!/usr/bin/env python3
"""
Minimal QUIC test to reproduce NoSignatureSchemes error
This creates the simplest possible QUIC client/server setup using RedProxy code
"""

import subprocess
import tempfile
import os
import time
import sys

def create_minimal_configs():
    """Create minimal client and server configs for QUIC testing"""
    
    # Simple QUIC server config
    server_config = """
listeners:
  - name: test-server
    type: quic
    bind: "0.0.0.0:9443"
    tls:
      cert: "/config/generated/server.crt"  
      key: "/config/generated/server.key"

connectors:
  - name: direct
    type: direct

rules:
  - target: direct

log:
  level: trace
  
accessLog:
  path: "/logs/quic-test-server.log"
  format: "json"
"""

    # Config for testing QUIC client connection  
    client_config = """
listeners:
  - name: test-client-listener
    type: http
    bind: "0.0.0.0:9080"

connectors:
  - name: test-quic-client
    type: quic
    server: quic-test-server
    port: 9443
    tls:
      insecure: true
      disableEarlyData: true

rules:
  - target: test-quic-client

log:
  level: trace
  
accessLog:
  path: "/logs/quic-test-client.log" 
  format: "json"
"""

    # Write configs
    with open('/config/generated/quic-test-server.yaml', 'w') as f:
        f.write(server_config)
    
    with open('/config/generated/quic-test-client.yaml', 'w') as f:
        f.write(client_config)
    
    print("✅ Created minimal QUIC test configs")
    return '/config/generated/quic-test-server.yaml', '/config/generated/quic-test-client.yaml'

def run_quic_test():
    """Run minimal QUIC client/server test"""
    print("🔧 === Minimal QUIC NoSignatureSchemes Reproduction Test ===")
    
    # Create test configs
    server_config, client_config = create_minimal_configs()
    
    print("📋 Test setup:")
    print(f"  Server config: {server_config}")
    print(f"  Client config: {client_config}")
    print(f"  Certificate: /config/generated/server.crt")
    print(f"  Server will listen on: 0.0.0.0:9443")
    print(f"  Client will connect via: HTTP proxy on 0.0.0.0:9080")
    
    # Check if certificate exists
    if not os.path.exists('/config/generated/server.crt'):
        print("❌ Certificate not found, generating...")
        return False
        
    print("\n🚀 Starting QUIC test...")
    print("\nTo run this test manually:")
    print("1. Terminal 1 (QUIC Server): docker run --rm -v ./config:/config -v ./logs:/logs redproxy -c /config/generated/quic-test-server.yaml")
    print("2. Terminal 2 (QUIC Client): docker run --rm -v ./config:/config -v ./logs:/logs redproxy -c /config/generated/quic-test-client.yaml") 
    print("3. Terminal 3 (Test Client): curl -x http://client-container:9080 http://test-target/")
    print("\n📝 Check logs in /logs/quic-test-*.log for NoSignatureSchemes errors")
    print("\n🔍 Expected error: 'received corrupt message of type NoSignatureSchemes'")
    
    return True

if __name__ == "__main__":
    run_quic_test()