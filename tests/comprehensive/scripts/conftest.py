"""
pytest configuration and fixtures for redproxy-rs comprehensive tests

This replaces the custom test_framework.py with pytest-native patterns.
Provides fixtures for test environment setup, proxy instances, and common utilities.
"""

import asyncio
import os
import socket
import time
from pathlib import Path
from typing import AsyncGenerator, Dict, Optional

import pytest
import httpx
from pytest_httpserver import HTTPServer
import yaml

# ============================================================================
# Session-level fixtures (setup once per test session)
# ============================================================================


@pytest.fixture(scope="session") 
def redproxy_config_path():
    """Path to the generated redproxy configuration"""
    return Path("/config/generated/matrix.yaml")


@pytest.fixture(scope="session")
def redproxy_config(redproxy_config_path):
    """Load redproxy configuration"""
    if not redproxy_config_path.exists():
        pytest.skip(f"Redproxy config not found at {redproxy_config_path}")
    
    with open(redproxy_config_path) as f:
        return yaml.safe_load(f)


# ============================================================================
# Test server fixtures (HTTP/HTTPS test targets)
# ============================================================================

@pytest.fixture(scope="session")
def http_test_server():
    """HTTP test server for proxy testing"""
    server = HTTPServer(host="0.0.0.0", port=9999)
    server.expect_request("/get").respond_with_json({"status": "ok", "method": "GET"})
    server.expect_request("/post", method="POST").respond_with_json({"status": "ok", "method": "POST"})
    server.expect_request("/chunked").respond_with_data("chunk1\nchunk2\nchunk3", 
                                                        headers={"Transfer-Encoding": "chunked"})
    
    server.start()
    yield server
    server.stop()


@pytest.fixture(scope="session")
def https_test_server():
    """HTTPS test server for secure proxy testing"""
    # Use trustme for certificate generation
    import trustme
    
    ca = trustme.CA()
    cert = ca.issue_cert("localhost", "127.0.0.1")
    
    import ssl
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    cert.configure_cert(context)
    
    server = HTTPServer(host="0.0.0.0", port=9443, ssl_context=context)
    server.expect_request("/secure").respond_with_json({"status": "secure", "tls": True})
    
    server.start()
    yield server
    server.stop()


# ============================================================================
# Proxy client fixtures (different protocol combinations)
# ============================================================================

@pytest.fixture
async def http_proxy_client():
    """HTTP client configured to use redproxy HTTP proxy"""
    proxies = {"http://": "http://127.0.0.1:8080", "https://": "http://127.0.0.1:8080"}
    async with httpx.AsyncClient(proxies=proxies, timeout=30.0) as client:
        yield client


@pytest.fixture
async def socks_proxy_client():
    """HTTP client configured to use redproxy SOCKS proxy"""
    # Use httpx[socks] support
    proxy_url = "socks5://127.0.0.1:1080"
    async with httpx.AsyncClient(proxy=proxy_url, timeout=30.0) as client:
        yield client


@pytest.fixture
async def direct_client():
    """Direct HTTP client (no proxy) for baseline testing"""
    async with httpx.AsyncClient(timeout=30.0) as client:
        yield client


# ============================================================================
# Utility fixtures
# ============================================================================

@pytest.fixture
def free_port():
    """Get a free port for testing"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        s.listen(1)
        port = s.getsockname()[1]
    return port


@pytest.fixture
def test_data_dir():
    """Path to test data directory"""
    return Path(__file__).parent / "test_data"


# ============================================================================
# Timeout and retry utilities  
# ============================================================================

@pytest.fixture
def wait_for_service():
    """Utility to wait for a service to become available"""
    async def _wait_for_service(host: str, port: int, timeout: float = 30.0) -> bool:
        """Wait for a TCP service to become available"""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), 
                    timeout=1.0
                )
                writer.close()
                await writer.wait_closed()
                return True
            except (ConnectionRefusedError, asyncio.TimeoutError, OSError):
                await asyncio.sleep(0.1)
                
        return False
    
    return _wait_for_service


# ============================================================================
# Test result collection (replaces custom TestReporter)
# ============================================================================

@pytest.fixture(autouse=True)
def setup_test_logging(request):
    """Set up per-test logging"""
    test_name = request.node.name
    print(f"=== Starting test: {test_name} ===")
    
    start_time = time.time()
    yield
    duration = time.time() - start_time
    
    print(f"=== Finished test: {test_name} ({duration:.2f}s) ===")


# ============================================================================
# Protocol matrix fixtures (replaces test selection logic)
# ============================================================================

@pytest.fixture(params=["http", "socks5"])
def proxy_protocol(request):
    """Parametrize tests across different proxy protocols"""
    return request.param


@pytest.fixture(params=["http", "https"])  
def target_protocol(request):
    """Parametrize tests across different target protocols"""
    return request.param


# ============================================================================  
# Cleanup and error handling
# ============================================================================

@pytest.fixture(autouse=True)
async def cleanup_connections():
    """Ensure clean state between tests"""
    yield
    # Close any lingering connections
    await asyncio.sleep(0.1)  # Allow connections to close gracefully


def pytest_configure(config):
    """Configure pytest with custom settings"""
    # Ensure reports directory exists (only if writable)
    try:
        reports_dir = Path("reports")
        reports_dir.mkdir(exist_ok=True)
    except OSError:
        # Skip if filesystem is read-only (like in Docker)
        pass


def pytest_collection_modifyitems(config, items):
    """Modify test collection to add automatic markers"""
    for item in items:
        # Auto-mark slow tests
        if "slow" in item.name or "performance" in item.name:
            item.add_marker(pytest.mark.slow)
            
        # Auto-mark integration tests  
        if "integration" in item.name or "e2e" in item.name:
            item.add_marker(pytest.mark.integration)
            
        # Auto-mark by protocol
        if "http" in item.name:
            item.add_marker(pytest.mark.http)
        if "socks" in item.name:
            item.add_marker(pytest.mark.socks)
        if "quic" in item.name:
            item.add_marker(pytest.mark.quic)


def pytest_runtest_setup(item):
    """Setup for each test"""
    # Skip tests based on environment
    if "SKIP_SLOW_TESTS" in os.environ and "slow" in [mark.name for mark in item.iter_markers()]:
        pytest.skip("Slow tests disabled")


def pytest_sessionfinish(session, exitstatus):
    """Session cleanup"""
    print(f"Test session finished with exit status: {exitstatus}")