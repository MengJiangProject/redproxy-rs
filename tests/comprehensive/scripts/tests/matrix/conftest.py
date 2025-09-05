"""
pytest configuration for matrix tests

Provides fixtures and configuration specific to protocol matrix combination testing
"""

import pytest

# ============================================================================
# Test configuration
# ============================================================================

def pytest_configure(config):
    """Configure matrix-specific test markers"""
    config.addinivalue_line(
        "markers", "matrix: Protocol combination matrix tests"
    )
    config.addinivalue_line(
        "markers", "http_listener: HTTP listener protocol tests"
    )
    config.addinivalue_line(
        "markers", "socks_listener: SOCKS listener protocol tests"
    )
    config.addinivalue_line(
        "markers", "reverse_listener: Reverse proxy listener tests"
    )
    config.addinivalue_line(
        "markers", "quic_listener: QUIC listener protocol tests"
    )
    config.addinivalue_line(
        "markers", "ssh_listener: SSH listener protocol tests"
    )
    config.addinivalue_line(
        "markers", "protocol_combination: Listener×connector combination tests"
    )


def pytest_collection_modifyitems(config, items):
    """Auto-mark matrix tests based on their file names and content"""
    for item in items:
        # Auto-mark based on file name
        if "test_http_listener.py" in str(item.fspath):
            item.add_marker(pytest.mark.http_listener)
        elif "test_socks_listener.py" in str(item.fspath):
            item.add_marker(pytest.mark.socks_listener)
        elif "test_reverse_listener.py" in str(item.fspath):
            item.add_marker(pytest.mark.reverse_listener)
        elif "test_quic_listener.py" in str(item.fspath):
            item.add_marker(pytest.mark.quic_listener)
        elif "test_ssh_listener.py" in str(item.fspath):
            item.add_marker(pytest.mark.ssh_listener)
        elif "test_combinations.py" in str(item.fspath):
            item.add_marker(pytest.mark.protocol_combination)
        
        # All matrix tests get the matrix marker
        if "tests/matrix/" in str(item.fspath):
            item.add_marker(pytest.mark.matrix)