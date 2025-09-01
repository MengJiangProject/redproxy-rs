"""
Matrix configuration loader for dynamic test generation

Loads the generated matrix config and provides test case data for pytest
"""

import os
import sys
import yaml
from typing import List, Dict, Tuple, Any

# Add generator script to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../'))
from generate_matrix_config import MatrixGenerator


class MatrixConfigLoader:
    """Loads matrix configuration and provides test case data"""
    
    def __init__(self):
        self.config_path = "/config/generated/matrix.yaml"
        self.generator = MatrixGenerator()
        self._config = None
        self._test_matrix = None
        
    def load_config(self) -> Dict[str, Any]:
        """Load the generated matrix configuration"""
        if self._config is None:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    self._config = yaml.safe_load(f)
            else:
                # Generate config if it doesn't exist
                self._config = self.generator.generate_matrix_config()
        return self._config
    
    def get_listeners_by_type(self, listener_type: str) -> List[Dict[str, Any]]:
        """Get all listeners of a specific type with their ports"""
        config = self.load_config()
        listeners = []
        
        for listener in config.get("listeners", []):
            if listener.get("type") == listener_type:
                # Extract port from bind address
                bind = listener.get("bind", "")
                if ":" in bind:
                    port = int(bind.split(":")[-1])
                    listeners.append({
                        "name": listener.get("name"),
                        "port": port,
                        "bind": bind,
                        "config": listener
                    })
        
        return listeners
    
    def get_listener_connector_combinations(self) -> List[Tuple[str, int, str, str]]:
        """Get all listener×connector combinations as (listener_type, port, listener_name, connector_name)"""
        config = self.load_config()
        combinations = []
        
        # Build lookup for rules to find connector names
        rule_lookup = {}
        for rule in config.get("rules", []):
            # Rules use 'filter' with listener name matching
            rule_filter = rule.get("filter", "")
            target = rule.get("target", "")
            
            # Parse filter like: request.listener == "http-connect-0"
            if "request.listener ==" in rule_filter and target:
                # Extract listener name from filter
                import re
                match = re.search(r'request\.listener == "([^"]+)"', rule_filter)
                if match:
                    listener_name = match.group(1)
                    rule_lookup[listener_name] = target
        
        # Match listeners with their connectors
        for listener in config.get("listeners", []):
            listener_name = listener.get("name")
            listener_type = listener.get("type")
            bind = listener.get("bind", "")
            
            if ":" in bind:
                port = int(bind.split(":")[-1])
                
                # Find corresponding connector
                connector_name = rule_lookup.get(listener_name, "unknown")
                
                combinations.append((listener_type, port, listener_name, connector_name))
        
        return combinations
    
    def get_http_listener_ports(self) -> List[Tuple[int, str]]:
        """Get HTTP listener ports with their connector names as (port, connector_name)"""
        combinations = self.get_listener_connector_combinations()
        return [(port, connector) for listener_type, port, _, connector in combinations 
                if listener_type == "http"]
    
    def get_socks_listener_ports(self) -> List[Tuple[int, str]]:
        """Get SOCKS listener ports with their connector names as (port, connector_name)"""
        combinations = self.get_listener_connector_combinations()
        return [(port, connector) for listener_type, port, _, connector in combinations 
                if listener_type == "socks"]
    
    def get_listeners_by_connector_type(self, connector_type: str) -> List[Tuple[str, int, str]]:
        """Get listeners that use a specific connector type as (listener_type, port, listener_name)"""
        config = self.load_config()
        
        # Find connectors of the specified type
        target_connectors = set()
        for connector in config.get("connectors", []):
            if connector.get("type") == connector_type:
                target_connectors.add(connector.get("name"))
        
        # Find listeners that route to these connectors
        combinations = self.get_listener_connector_combinations()
        return [(listener_type, port, listener_name) for listener_type, port, listener_name, connector_name 
                in combinations if connector_name in target_connectors]


# Global instance for test modules to use
matrix_config = MatrixConfigLoader()