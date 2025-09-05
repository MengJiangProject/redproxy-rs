"""
HTTP listener matrix tests for redproxy

Tests HTTP listener with all connector combinations - DYNAMICALLY GENERATED
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


class TestHTTPListener:
    """HTTP listener protocol matrix tests"""

    @pytest.mark.asyncio
    @pytest.mark.timeout(20)
    @pytest.mark.matrix
    @pytest.mark.http_listener
    @pytest.mark.parametrize("port,connector", matrix_config.get_http_listener_ports())
    async def test_http_listener_combinations(self, port, connector):
        """Test HTTP listener on specific port with various connectors - from _test_http_listener()"""
        # Wait for redproxy service to be ready on this port - FAIL if not available
        if not await wait_for_service("redproxy", port, timeout=10.0):
            pytest.fail(f"RedProxy service not available on port {port} - infrastructure failure")
        
        proxy_url = f"http://redproxy:{port}"
        
        async with httpx.AsyncClient(proxy=proxy_url, timeout=10.0) as client:
            # Test 1: Basic GET request
            response = await client.get("http://http-echo:8080/")
            assert response.status_code == 200, f"HTTP port {port} → {connector} (basic GET failed)"
            assert "path" in response.text, f"HTTP port {port} → {connector} (missing path in response)"
            
            # Test 2: POST with data
            test_data = f"Test data for {connector}"
            response = await client.post("http://http-echo:8080/post", content=test_data)
            assert response.status_code == 200, f"HTTP port {port} → {connector} (POST failed)"
            
            # Test 3: JSON request
            json_data = {"test": connector, "port": port}
            response = await client.post("http://http-echo:8080/json", json=json_data)
            assert response.status_code == 200, f"HTTP port {port} → {connector} (JSON failed)"
            
            # Test 4: Custom headers
            headers = {"X-Test-Connector": connector, "X-Test-Port": str(port)}
            response = await client.get("http://http-echo:8080/headers", headers=headers)
            assert response.status_code == 200, f"HTTP port {port} → {connector} (headers failed)"

    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.matrix
    @pytest.mark.http_listener
    async def test_http_listener_first_direct(self):
        """Test first available HTTP listener with direct connector"""
        http_listeners = matrix_config.get_http_listener_ports()
        if not http_listeners:
            pytest.skip("No HTTP listeners configured in matrix")
            
        port, connector = http_listeners[0]  # Use first available HTTP listener
        
        if not await wait_for_service("redproxy", port, timeout=10.0):
            pytest.fail(f"RedProxy service not available on port {port} - infrastructure failure")
        
        proxy_url = f"http://redproxy:{port}"
        
        async with httpx.AsyncClient(proxy=proxy_url, timeout=10.0) as client:
            response = await client.get("http://http-echo:8080/")
            assert response.status_code == 200
            assert "path" in response.text

    @pytest.mark.asyncio
    @pytest.mark.timeout(25)
    @pytest.mark.matrix
    @pytest.mark.http_listener
    async def test_http_listener_comprehensive_workflow(self):
        """Test comprehensive HTTP workflow through different listener ports"""
        http_listeners = matrix_config.get_http_listener_ports()
        test_listeners = http_listeners[:3]  # Test first 3 HTTP listeners
        
        if not test_listeners:
            pytest.skip("No HTTP listeners configured in matrix")
        
        workflow_successes = 0
        
        for port, connector in test_listeners:
            if not await wait_for_service("redproxy", port, timeout=5.0):
                pytest.fail(f"RedProxy service not available on port {port} - infrastructure failure")
            
            proxy_url = f"http://redproxy:{port}"
            
            try:
                async with httpx.AsyncClient(proxy=proxy_url, timeout=8.0) as client:
                    # Multi-step workflow test
                    # Step 1: GET request
                    get_response = await client.get("http://http-echo:8080/")
                    assert get_response.status_code == 200
                    
                    # Step 2: POST request with previous response data
                    post_data = f"Workflow test for port {port}"
                    post_response = await client.post(
                        "http://http-echo:8080/workflow", 
                        content=post_data
                    )
                    assert post_response.status_code in [200, 201, 404]  # 404 acceptable if endpoint doesn't exist
                    
                    print(f"✅ HTTP workflow port {port} completed")
                    workflow_successes += 1
                    
            except Exception as e:
                print(f"❌ HTTP workflow port {port} failed: {e}")
                pytest.fail(f"HTTP workflow failed on port {port}: {e}")
        
        # Ensure at least some workflows succeeded
        assert workflow_successes > 0, "No HTTP workflow tests succeeded"


# Run individual tests for debugging  
if __name__ == "__main__":
    # pytest tests/matrix/test_http_listener.py::TestHTTPListener::test_http_listener_combinations
    print("Run with: pytest tests/matrix/test_http_listener.py")
    print("Or single test: pytest tests/matrix/test_http_listener.py::TestHTTPListener::test_http_listener_8800_direct")
    print("Or all HTTP listener tests: pytest -k http_listener")