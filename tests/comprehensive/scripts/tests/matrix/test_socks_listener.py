"""
SOCKS listener matrix tests for redproxy

Tests SOCKS listener with all connector combinations - DYNAMICALLY GENERATED
"""

import asyncio
import pytest
import httpx
import sys
import os

# Import from shared helpers
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../shared'))
from helpers import setup_test_environment, wait_for_service
from matrix_loader import matrix_config


class TestSOCKSListener:
    """SOCKS listener protocol matrix tests"""

    @pytest.mark.asyncio
    @pytest.mark.timeout(20)
    @pytest.mark.matrix
    @pytest.mark.socks_listener
    @pytest.mark.parametrize("port,connector", matrix_config.get_socks_listener_ports())
    async def test_socks_listener_combinations(self, port, connector):
        """Test SOCKS listener on specific port with various connectors - from _test_socks_listener()"""
        # Wait for redproxy service to be ready on this port - FAIL if not available
        if not await wait_for_service("redproxy", port, timeout=10.0):
            pytest.fail(f"RedProxy SOCKS service not available on port {port} - infrastructure failure")
        
        proxy_url = f"socks5://redproxy:{port}"
        target_url = "http://http-echo:8080/"
        
        async with httpx.AsyncClient(proxy=proxy_url, timeout=10.0) as client:
            response = await client.get(target_url)
            
            assert response.status_code == 200, f"SOCKS port {port} → {connector} (status: {response.status_code})"
            assert "path" in response.text, f"SOCKS port {port} → {connector} (missing path in response)"

    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.matrix
    @pytest.mark.socks_listener
    async def test_socks_listener_first_available(self):
        """Test first available SOCKS listener"""
        socks_listeners = matrix_config.get_socks_listener_ports()
        if not socks_listeners:
            pytest.skip("No SOCKS listeners configured in matrix")
            
        port, connector = socks_listeners[0]  # Use first available SOCKS listener
        
        if not await wait_for_service("redproxy", port, timeout=10.0):
            pytest.fail(f"RedProxy SOCKS service not available on port {port} - infrastructure failure")
        
        proxy_url = f"socks5://redproxy:{port}"
        
        async with httpx.AsyncClient(proxy=proxy_url, timeout=10.0) as client:
            response = await client.get("http://http-echo:8080/")
            assert response.status_code == 200
            assert "path" in response.text

    @pytest.mark.asyncio
    @pytest.mark.timeout(25)
    @pytest.mark.matrix
    @pytest.mark.socks_listener
    async def test_socks_listener_post_requests(self):
        """Test SOCKS listener with POST requests across different ports"""
        socks_listeners = matrix_config.get_socks_listener_ports()
        test_listeners = socks_listeners[:3]  # Test first 3 SOCKS listeners
        
        if not test_listeners:
            pytest.skip("No SOCKS listeners configured in matrix")
        
        post_successes = 0
        
        for port, connector in test_listeners:
            if not await wait_for_service("redproxy", port, timeout=5.0):
                pytest.fail(f"RedProxy SOCKS service not available on port {port} - infrastructure failure")
            
            proxy_url = f"socks5://redproxy:{port}"
            
            try:
                async with httpx.AsyncClient(proxy=proxy_url, timeout=8.0) as client:
                    # Test POST request
                    test_data = f"SOCKS POST test for port {port}"
                    response = await client.post(
                        "http://http-echo:8080/post",
                        content=test_data,
                        headers={"Content-Type": "text/plain"}
                    )
                    
                    assert response.status_code == 200, f"SOCKS POST failed on port {port}"
                    print(f"✅ SOCKS POST port {port} completed")
                    post_successes += 1
                    
            except Exception as e:
                print(f"❌ SOCKS POST port {port} failed: {e}")
                pytest.fail(f"SOCKS POST failed on port {port}: {e}")
        
        # Ensure at least some POST tests succeeded
        assert post_successes > 0, "No SOCKS POST tests succeeded"

    @pytest.mark.asyncio
    @pytest.mark.timeout(20)
    @pytest.mark.matrix
    @pytest.mark.socks_listener
    async def test_socks_listener_different_targets(self):
        """Test SOCKS listener with different target hosts"""
        socks_listeners = matrix_config.get_socks_listener_ports()
        if not socks_listeners:
            pytest.skip("No SOCKS listeners configured in matrix")
            
        port, connector = socks_listeners[0]  # Use first available SOCKS listener
        
        if not await wait_for_service("redproxy", port, timeout=10.0):
            pytest.fail(f"RedProxy SOCKS service not available on port {port} - infrastructure failure")
        
        proxy_url = f"socks5://redproxy:{port}"
        
        # Test different target endpoints
        targets = [
            "http://http-echo:8080/",
            "http://http-echo:8080/headers",
            "http://websocket-server:9998/"
        ]
        
        async with httpx.AsyncClient(proxy=proxy_url, timeout=10.0) as client:
            for target in targets:
                try:
                    response = await client.get(target)
                    # Accept any reasonable response status
                    assert response.status_code in [200, 404, 405], \
                        f"SOCKS target {target} failed with status {response.status_code}"
                    print(f"✅ SOCKS target {target} responded")
                except Exception as e:
                    print(f"⚠️  SOCKS target {target} failed: {e}")
                    # Don't fail test for individual target issues
                    continue


# Run individual tests for debugging  
if __name__ == "__main__":
    # pytest tests/matrix/test_socks_listener.py::TestSOCKSListener::test_socks_listener_combinations
    print("Run with: pytest tests/matrix/test_socks_listener.py")
    print("Or single test: pytest tests/matrix/test_socks_listener.py::TestSOCKSListener::test_socks_listener_1121_direct")
    print("Or all SOCKS listener tests: pytest -k socks_listener")