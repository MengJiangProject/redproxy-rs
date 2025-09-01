"""
Request size limits tests for redproxy security

Tests proxy behavior with large requests and headers
"""

import pytest
import httpx
import sys
import os

# Import from shared helpers
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../shared'))
from helpers import setup_test_environment


class TestSizeLimits:
    """Request size limit security tests"""

    @pytest.mark.asyncio
    @pytest.mark.timeout(20)
    @pytest.mark.security
    @pytest.mark.size_limits
    async def test_large_header_handling(self):
        """Test handling of large headers - from test_request_size_limits()"""
        env = setup_test_environment()
        
        # Test with large headers (8KB header)
        large_headers = {"X-Large-Header": "A" * 8192}
        
        async with httpx.AsyncClient(proxy=env.http_proxy_url, timeout=15.0) as client:
            try:
                response = await client.get(env.get_echo_url(), headers=large_headers)
                
                # Should either work (200) or be rejected with appropriate error codes
                assert response.status_code in [200, 413, 414], \
                    f"Unexpected response to large request: {response.status_code}"
                    
            except httpx.RequestError:
                # Connection errors are acceptable for oversized requests
                pass

    @pytest.mark.asyncio
    @pytest.mark.timeout(25)
    @pytest.mark.security
    @pytest.mark.size_limits
    async def test_multiple_large_headers(self):
        """Test handling of multiple large headers"""
        env = setup_test_environment()
        
        # Multiple medium-large headers that add up to significant size
        large_headers = {
            f"X-Large-Header-{i}": "B" * 1024 for i in range(10)  # 10KB total
        }
        
        async with httpx.AsyncClient(proxy=env.http_proxy_url, timeout=15.0) as client:
            try:
                response = await client.get(env.get_echo_url(), headers=large_headers)
                
                # Should handle gracefully - either accept or reject with proper status
                assert response.status_code in [200, 413, 414, 431]  # 431 Request Header Fields Too Large
                    
            except httpx.RequestError:
                # Connection/request errors are acceptable for oversized headers
                pass

    @pytest.mark.asyncio
    @pytest.mark.timeout(30)
    @pytest.mark.security
    @pytest.mark.size_limits
    async def test_large_post_body(self):
        """Test handling of large POST request body"""
        env = setup_test_environment()
        
        # Create large POST body (1MB)
        large_body = "X" * (1024 * 1024)
        
        async with httpx.AsyncClient(proxy=env.http_proxy_url, timeout=20.0) as client:
            try:
                response = await client.post(
                    "http://http-echo:8080/post",
                    content=large_body,
                    headers={"Content-Type": "text/plain"}
                )
                
                # Should either work or be rejected with appropriate error
                assert response.status_code in [200, 413, 414, 500, 502, 503, 504], \
                    f"Unexpected response to large POST: {response.status_code}"
                    
            except (httpx.RequestError, httpx.TimeoutException):
                # Timeouts and connection errors are acceptable for large requests
                pass

    @pytest.mark.asyncio
    @pytest.mark.timeout(20)
    @pytest.mark.security
    @pytest.mark.size_limits
    async def test_extremely_long_url(self):
        """Test handling of extremely long URLs"""
        env = setup_test_environment()
        
        # Create very long URL path
        long_path = "/long/path/" + "segment/" * 1000  # Very long URL
        long_url = f"http://http-echo:8080{long_path}"
        
        async with httpx.AsyncClient(proxy=env.http_proxy_url, timeout=15.0) as client:
            try:
                response = await client.get(long_url)
                
                # Should either work or be rejected with appropriate error
                assert response.status_code in [200, 404, 414, 500, 502], \
                    f"Unexpected response to long URL: {response.status_code}"
                    
            except httpx.RequestError:
                # Request errors are acceptable for extremely long URLs
                pass


# Run individual tests for debugging  
if __name__ == "__main__":
    # pytest tests/security/test_size_limits.py::TestSizeLimits::test_large_header_handling
    print("Run with: pytest tests/security/test_size_limits.py")
    print("Or single test: pytest tests/security/test_size_limits.py::TestSizeLimits::test_large_header_handling") 
    print("Or all size limit tests: pytest -k size_limits")