"""
Error handling security tests for redproxy

Tests proxy behavior with invalid targets and error conditions
"""

import pytest
import httpx
import sys
import os

# Import from shared helpers
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../shared'))
from helpers import setup_test_environment


class TestErrorHandling:
    """Error handling and validation security tests"""

    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.security
    @pytest.mark.error_handling
    async def test_invalid_target_handling(self):
        """Test error handling with non-existent targets - from test_error_handling_security()"""
        env = setup_test_environment()
        
        # Test connection to non-existent server
        invalid_url = "http://nonexistent-server-12345.invalid:80/"
        
        async with httpx.AsyncClient(proxy=env.http_proxy_url, timeout=5.0) as client:
            try:
                response = await client.get(invalid_url)
                # HTTP error status codes (4xx, 5xx) are acceptable error handling
                if response.status_code >= 400:
                    # Properly handled invalid target with HTTP error response
                    assert True
                else:
                    pytest.fail(f"Should have failed for invalid target, got status {response.status_code}")
                    
            except (httpx.RequestError, httpx.TimeoutException):
                # Connection errors are also acceptable for invalid targets
                assert True

    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.security
    @pytest.mark.error_handling
    async def test_dns_resolution_failure(self):
        """Test handling of DNS resolution failures"""
        env = setup_test_environment()
        
        # Test with clearly non-resolvable domain
        dns_fail_url = "http://this.domain.definitely.does.not.exist.example/"
        
        async with httpx.AsyncClient(proxy=env.http_proxy_url, timeout=5.0) as client:
            try:
                response = await client.get(dns_fail_url)
                # Should get appropriate HTTP error response
                assert response.status_code >= 400
            except (httpx.RequestError, httpx.TimeoutException):
                # Network errors are acceptable for DNS failures
                assert True

    @pytest.mark.asyncio
    @pytest.mark.timeout(20)
    @pytest.mark.security
    @pytest.mark.error_handling
    async def test_connection_timeout_handling(self):
        """Test handling of connection timeouts"""
        env = setup_test_environment()
        
        # Use a non-routable IP address (should timeout)
        timeout_url = "http://10.255.255.1:80/"
        
        async with httpx.AsyncClient(proxy=env.http_proxy_url, timeout=5.0) as client:
            try:
                response = await client.get(timeout_url)
                # If we get a response, it should be an error status
                assert response.status_code >= 400
            except (httpx.RequestError, httpx.TimeoutException):
                # Timeout exceptions are expected and acceptable
                assert True


# Run individual tests for debugging  
if __name__ == "__main__":
    # pytest tests/security/test_error_handling.py::TestErrorHandling::test_invalid_target_handling
    print("Run with: pytest tests/security/test_error_handling.py")
    print("Or single test: pytest tests/security/test_error_handling.py::TestErrorHandling::test_invalid_target_handling")
    print("Or all error handling tests: pytest -k error_handling")