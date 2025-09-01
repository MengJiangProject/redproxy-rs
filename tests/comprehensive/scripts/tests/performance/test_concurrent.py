"""
Concurrent connection performance tests for redproxy

Tests proxy behavior under concurrent load from multiple clients
"""

import asyncio
import pytest
import httpx
import sys
import os

# Import from shared helpers
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../shared'))
from helpers import setup_test_environment


class TestConcurrentConnections:
    """Concurrent connection performance tests"""

    @pytest.mark.asyncio
    @pytest.mark.timeout(45)
    @pytest.mark.performance
    @pytest.mark.concurrent
    async def test_concurrent_http_connections(self):
        """Test concurrent HTTP connections - from test_concurrent_http_connections()"""
        env = setup_test_environment()
        concurrent_count = 20
        
        async def single_http_test():
            try:
                async with httpx.AsyncClient(proxy=env.http_proxy_url, timeout=10.0) as client:
                    response = await client.get(env.get_echo_url())
                    return response.status_code == 200
            except:
                return False
        
        start_time = asyncio.get_event_loop().time()
        
        # Run concurrent requests
        tasks = [single_http_test() for _ in range(concurrent_count)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        end_time = asyncio.get_event_loop().time()
        duration = end_time - start_time
        
        # Count successes (excluding exceptions)
        successes = sum(1 for r in results if r is True)
        success_rate = successes / concurrent_count
        rps = concurrent_count / duration
        
        print(f"Results: {successes}/{concurrent_count} succeeded ({success_rate*100:.1f}%)")
        print(f"Duration: {duration:.2f}s ({rps:.1f} req/s)")
        
        # Allow 10% failure under high concurrency
        assert success_rate >= 0.9, f"Only {success_rate*100:.1f}% success rate"

    @pytest.mark.asyncio
    @pytest.mark.timeout(60)
    @pytest.mark.performance
    @pytest.mark.concurrent
    async def test_concurrent_socks_connections(self):
        """Test concurrent SOCKS connections - from test_concurrent_socks_connections()"""
        env = setup_test_environment()
        concurrent_count = 15  # SOCKS can be more sensitive
        
        async def single_socks_test():
            try:
                # Use httpx with socks proxy support
                proxy_url = f"socks5://{env.redproxy_host}:{env.redproxy_socks_port}"
                async with httpx.AsyncClient(proxy=proxy_url, timeout=10.0) as client:
                    response = await client.get(env.get_echo_url())
                    return response.status_code == 200
            except:
                return False
        
        start_time = asyncio.get_event_loop().time()
        
        # Run concurrent requests
        tasks = [single_socks_test() for _ in range(concurrent_count)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        end_time = asyncio.get_event_loop().time()
        duration = end_time - start_time
        
        # Count successes (excluding exceptions)
        successes = sum(1 for r in results if r is True)
        success_rate = successes / concurrent_count
        rps = concurrent_count / duration
        
        print(f"SOCKS Results: {successes}/{concurrent_count} succeeded ({success_rate*100:.1f}%)")
        print(f"Duration: {duration:.2f}s ({rps:.1f} req/s)")
        
        # SOCKS can be more sensitive, allow 20% failure
        assert success_rate >= 0.8, f"Only {success_rate*100:.1f}% success rate for SOCKS"

    @pytest.mark.asyncio
    @pytest.mark.timeout(30)
    @pytest.mark.performance
    @pytest.mark.concurrent
    @pytest.mark.parametrize("concurrent_count", [5, 10, 15])
    async def test_concurrent_connections_scaling(self, concurrent_count):
        """Test concurrent connections at different scales"""
        env = setup_test_environment()
        
        async def single_request():
            try:
                async with httpx.AsyncClient(proxy=env.http_proxy_url, timeout=8.0) as client:
                    response = await client.get(env.get_echo_url())
                    return response.status_code == 200
            except:
                return False
        
        # Run concurrent requests
        tasks = [single_request() for _ in range(concurrent_count)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        successes = sum(1 for r in results if r is True)
        success_rate = successes / concurrent_count
        
        print(f"Scale {concurrent_count}: {successes}/{concurrent_count} succeeded ({success_rate*100:.1f}%)")
        
        # Lower scale should have higher success rates
        min_success_rate = 0.9 if concurrent_count <= 10 else 0.8
        assert success_rate >= min_success_rate, \
            f"Scaling test failed at {concurrent_count} concurrent: {success_rate*100:.1f}% success rate"


# Run individual tests for debugging  
if __name__ == "__main__":
    # pytest tests/performance/test_concurrent.py::TestConcurrentConnections::test_concurrent_http_connections
    print("Run with: pytest tests/performance/test_concurrent.py")
    print("Or single test: pytest tests/performance/test_concurrent.py::TestConcurrentConnections::test_concurrent_http_connections")
    print("Or all concurrent tests: pytest -k concurrent")