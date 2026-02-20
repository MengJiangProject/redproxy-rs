#!/usr/bin/env python3
"""
RedProxy Matrix Configuration Generator
Generates a single config with all listener×connector combinations
"""

import os
import sys
import yaml
import itertools
from typing import Dict, List, Any
from dataclasses import dataclass, field



@dataclass
class ListenerConfig:
    """Configuration for a specific listener type"""
    name: str
    type: str
    required_features: List[str] = field(default_factory=list)
    platforms: List[str] = field(default_factory=lambda: ["linux", "windows", "macos"])
    config_template: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ConnectorConfig:
    """Configuration for a specific connector type"""  
    name: str
    type: str
    required_features: List[str] = field(default_factory=list)
    config_template: Dict[str, Any] = field(default_factory=dict)


class MatrixGenerator:
    """Generates a single RedProxy config with all listener×connector combinations"""
    
    def __init__(self):
        self.listeners = self._define_listeners()
        self.connectors = self._define_connectors()
        
    def _define_listeners(self) -> List[ListenerConfig]:
        """Define all available listener types based on RedProxy source code"""
        return [
            ListenerConfig(
                name="http-connect",
                type="http", 
                config_template={
                    "bind": "0.0.0.0:8800",
                }
            ),
            ListenerConfig(
                name="socks",
                type="socks",
                config_template={
                    "bind": "0.0.0.0:1081", 
                }
            ),
            ListenerConfig(
                name="reverse",
                type="reverse",
                config_template={
                    "bind": "0.0.0.0:8080",
                    "protocol": "tcp",
                    "target": "http-echo:8080"
                }
            ),
            ListenerConfig(
                name="quic", 
                type="quic",
                required_features=["quic"],
                config_template={
                    "bind": "0.0.0.0:8443",
                    "tls": {
                        "cert": "/config/generated/server.crt",
                        "key": "/config/generated/server.key"
                    }
                }
            ),
            ListenerConfig(
                name="ssh",
                type="ssh", 
                required_features=["ssh"],
                config_template={
                    "bind": "0.0.0.0:2222",
                    "hostKeyPath": "/config/generated/ssh_host_key",
                    "allowPassword": True,
                    "passwordUsers": {
                        "test": "password"
                    }
                }
            ),
        ]
    
    def _define_connectors(self) -> List[ConnectorConfig]:
        """Define all available connector types based on RedProxy source code"""
        return [
            ConnectorConfig(
                name="direct",
                type="direct",
                config_template={}
            ),
            ConnectorConfig(
                name="http-upstream",
                type="http",
                config_template={
                    "server": "http-proxy",
                    "port": 3128
                }
            ),
            ConnectorConfig(
                name="socks-upstream", 
                type="socks",
                config_template={
                    "server": "socks-proxy",
                    "port": 1080
                }
            ),
            ConnectorConfig(
                name="loadbalance",
                type="loadbalance",
                config_template={
                    "connectors": ["direct", "http-upstream"],
                    "strategy": "round-robin"
                }
            ),
            ConnectorConfig(
                name="quic-upstream",
                type="quic", 
                required_features=["quic"],
                config_template={
                    "server": "quic-proxy",
                    "port": 8443,
                    "tls": {
                        "insecure": True,
                        "disableEarlyData": True
                    }
                }
            ),
            ConnectorConfig(
                name="ssh-upstream",
                type="ssh",
                required_features=["ssh"], 
                config_template={
                    "server": "ssh-proxy",
                    "port": 2222,
                    "username": "proxy",
                    "auth": {
                        "type": "password",
                        "password": "proxy123"
                    },
                    "serverKeyVerification": {
                        "type": "insecureAcceptAny"
                    }
                }
            ),
        ]
    
    def get_available_combinations(self, 
                                 platform: str = "linux",
                                 features: List[str] = None) -> List[tuple]:
        """Get all valid listener×connector combinations for a platform/feature set"""
        if features is None:
            features = []
            
        valid_listeners = [
            l for l in self.listeners 
            if (platform in l.platforms and 
                all(f in features for f in l.required_features))
        ]
        
        valid_connectors = [
            c for c in self.connectors
            if all(f in features for f in c.required_features)
        ]
        
        return list(itertools.product(valid_listeners, valid_connectors))
    
    def generate_matrix_config(self, 
                               platform: str = "linux", 
                               features: List[str] = None) -> Dict[str, Any]:
        """Generate one config file with all listener×connector combinations"""
        
        if features is None:
            features = ["quic", "ssh"]  # Enable SSH and QUIC for comprehensive testing
            
        combinations = self.get_available_combinations(platform, features)
        
        print(f"Generating matrix config for {len(combinations)} listener×connector combinations")
        
        config = {
            "listeners": [],
            "connectors": [],
            "rules": [],
            "accessLog": {
                "path": "/logs/matrix-access.log",
                "format": "json"
            },
            "timeouts": {
                "idle": 300,
                "udp": 300,
                "shutdownConnection": 10,
                "shutdownListener": 2
            },
            "metrics": {
                "bind": "0.0.0.0:9090",
                "apiPrefix": "/api",
            },
        }
        
        # Add all defined connectors from self.connectors
        valid_connectors = [
            c for c in self.connectors
            if all(f in features for f in c.required_features)
        ]
        
        print(f"Found {len(valid_connectors)} valid connectors: {[c.name for c in valid_connectors]}")
        
        for connector_config in valid_connectors:
            connector = {
                "name": connector_config.name,
                "type": connector_config.type,
            }
            # Add all config template fields
            connector.update(connector_config.config_template)
            
            config["connectors"].append(connector)
            print(f"Added connector: {connector_config.name} ({connector_config.type})")
        
        # Generate listeners and rules for each combination
        print(f"Generating {len(combinations)} listeners and rules...")
        
        for i, (listener_config, connector_config) in enumerate(combinations):
            port_offset = i * 10
            
            # Create unique listener name
            listener_name = f"{listener_config.name}-{i}"
            
            print(f"Creating listener {i+1}/{len(combinations)}: {listener_name} → {connector_config.name}")
            
            # Create listener with unique port
            listener = {
                "name": listener_name,
                "type": listener_config.type,
            }
            
            # Add bind address with port offset
            if "bind" in listener_config.config_template:
                bind_parts = listener_config.config_template["bind"].split(":")
                if len(bind_parts) == 2:
                    host, base_port = bind_parts
                    new_port = int(base_port) + port_offset
                    listener["bind"] = f"{host}:{new_port}"
            
            # Add other config template fields
            for key, value in listener_config.config_template.items():
                if key != "bind":
                    listener[key] = value
                    
            config["listeners"].append(listener)
            
            # Create routing rule for this listener→connector combination
            rule = {
                "filter": f'request.listener == "{listener_name}"',
                "target": connector_config.name
            }
            config["rules"].append(rule)
        
        # Add fallback rule to direct connector for any unmatched requests
        fallback_rule = {"target": "direct"}
        config["rules"].append(fallback_rule)
        
        return config
    
    def generate_test_matrix(self, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate test matrix information from the config"""
        test_matrix = []
        
        for i, listener in enumerate(config["listeners"]):
            # Find corresponding rule
            rule = config["rules"][i] if i < len(config["rules"]) else None
            target_connector = rule["target"] if rule else "unknown"
            
            # Extract port from bind address
            port = None
            if "bind" in listener:
                port_str = listener["bind"].split(":")[-1]
                port = int(port_str)
            
            test_info = {
                "listener_name": listener["name"],
                "listener_type": listener["type"], 
                "listener_port": port,
                "connector_name": target_connector,
                "test_name": f"{listener['type']}_port_{port}_to_{target_connector}",
                "rule_filter": rule["filter"] if rule else None
            }
            
            test_matrix.append(test_info)
            
        return test_matrix
    
    def save_config(self, config: Dict[str, Any], filename: str = "matrix.yaml") -> str:
        """Save the matrix configuration"""
        config_path = f"/config/generated/{filename}"
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        
        with open(config_path, 'w') as f:
            yaml.dump(config, f, default_flow_style=False, sort_keys=False)
            
        return config_path


def main():
    """Generate matrix configuration"""
    print("=== RedProxy Matrix Configuration Generator ===")
    
    generator = MatrixGenerator()
    
    # Generate matrix config for Linux platform with all features
    print("Generating matrix config for Linux platform...")
    config = generator.generate_matrix_config(platform="linux", features=["quic", "ssh"])
    
    # Save config
    config_path = generator.save_config(config)
    print(f"Matrix configuration saved to: {config_path}")
    
    # Generate test matrix
    test_matrix = generator.generate_test_matrix(config)
    
    print(f"Generated matrix config with {len(config['listeners'])} listeners")
    print(f"Config saved: {config_path}")
    print(f"Listener×Connector combinations:")
    
    for test_info in test_matrix:
        print(f"  - {test_info['test_name']} (port {test_info['listener_port']})")
    
    print(f"\nTo test matrix: use this config with RedProxy")


if __name__ == "__main__":
    main()