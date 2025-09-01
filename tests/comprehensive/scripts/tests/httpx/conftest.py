"""
pytest configuration for httpx listener tests

Provides fixtures and configuration specific to HTTP proxy testing
"""

import pytest

# ============================================================================
# Test configuration
# ============================================================================

def pytest_configure(config):
    """Configure httpx-specific test markers"""
    config.addinivalue_line(
        "markers", "http: HTTP protocol tests"
    )
    config.addinivalue_line(
        "markers", "connect: HTTP CONNECT tunneling tests"
    )
    config.addinivalue_line(
        "markers", "forward: HTTP forward proxy tests"
    )
    config.addinivalue_line(
        "markers", "keepalive: HTTP keep-alive connection tests"
    )
    config.addinivalue_line(
        "markers", "chunked: HTTP chunked encoding tests"
    )
    config.addinivalue_line(
        "markers", "http_continue: HTTP 100-continue tests"
    )
    config.addinivalue_line(
        "markers", "websocket: WebSocket upgrade tests"
    )
    config.addinivalue_line(
        "markers", "destructive: Error handling and malformed input tests"
    )


def pytest_collection_modifyitems(config, items):
    """Auto-mark httpx tests based on their file names and content"""
    for item in items:
        # Auto-mark based on file name
        if "test_connect.py" in str(item.fspath):
            item.add_marker(pytest.mark.connect)
        elif "test_forward.py" in str(item.fspath):
            item.add_marker(pytest.mark.forward)
        elif "test_keepalive.py" in str(item.fspath):
            item.add_marker(pytest.mark.keepalive)
        elif "test_chunked.py" in str(item.fspath):
            item.add_marker(pytest.mark.chunked)
        elif "test_continue.py" in str(item.fspath):
            item.add_marker(pytest.mark.http_continue)
        elif "test_websocket.py" in str(item.fspath):
            item.add_marker(pytest.mark.websocket)
        elif "test_destructive.py" in str(item.fspath):
            item.add_marker(pytest.mark.destructive)
        
        # All httpx tests get the http marker
        if "tests/httpx/" in str(item.fspath):
            item.add_marker(pytest.mark.http)