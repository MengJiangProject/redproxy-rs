"""
Basic security tests for redproxy

Tests basic connection security and authentication
"""

import asyncio
import pytest
import httpx
import sys
import os

# Import from shared helpers
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../shared'))
from helpers import setup_test_environment


class TestBasicSecurity:
    """Basic connection security tests"""

    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.security
    async def test_basic_connection_security(self):
        """Test basic connection security through HTTP proxy - from test_basic_security()"""
        env = setup_test_environment()
        
        # Test basic GET through HTTP proxy
        async with httpx.AsyncClient(proxy=env.http_proxy_url, timeout=10.0) as client:
            response = await client.get(env.get_echo_url())
            
            assert response.status_code == 200
            assert "path" in response.text
            
    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.security
    async def test_basic_connection_with_custom_headers(self):
        """Test basic connection with custom headers for security validation"""
        env = setup_test_environment()
        
        headers = {
            "X-Security-Test": "basic",
            "User-Agent": "RedProxy-Security-Test/1.0"
        }
        
        async with httpx.AsyncClient(proxy=env.http_proxy_url, timeout=10.0) as client:
            response = await client.get(env.get_echo_url(), headers=headers)
            
            assert response.status_code == 200
            assert "path" in response.text


# Run individual tests for debugging  
if __name__ == "__main__":
    # pytest tests/security/test_basic.py::TestBasicSecurity::test_basic_connection_security
    print("Run with: pytest tests/security/test_basic.py")
    print("Or single test: pytest tests/security/test_basic.py::TestBasicSecurity::test_basic_connection_security")
    print("Or all basic security tests: pytest -k basic")