"""
Connection limits and stress testing for redproxy performance

Tests proxy behavior under high connection load and concurrent access
"""

import asyncio
import pytest
import httpx
import sys
import os

# Import from shared helpers
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../shared'))
from helpers import setup_test_environment


class TestConnectionLimits:
    """Connection handling and stress testing"""

    @pytest.mark.asyncio
    @pytest.mark.timeout(30)
    @pytest.mark.performance
    @pytest.mark.concurrent
    async def test_concurrent_connections_stress(self):
        """Test connection handling under concurrent stress - from test_connection_limits()"""
        env = setup_test_environment()
        
        async def single_request():
            try:
                async with httpx.AsyncClient(proxy=env.http_proxy_url, timeout=10.0) as client:
                    response = await client.get(env.get_echo_url())
                    return response.status_code == 200
            except:
                return False
        
        # Test 20 concurrent connections
        tasks = [single_request() for _ in range(20)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        success_count = sum(1 for r in results if r is True)
        
        # Allow some failures under stress (15/20 = 75% success rate minimum)
        assert success_count >= 15, f"Only {success_count}/20 connections succeeded"

    @pytest.mark.asyncio
    @pytest.mark.timeout(45)
    @pytest.mark.performance
    @pytest.mark.concurrent
    async def test_sequential_connection_cleanup(self):
        """Test that connections are properly cleaned up in sequence"""
        env = setup_test_environment()
        
        # Make many sequential requests to test cleanup
        success_count = 0
        
        for i in range(50):
            try:
                async with httpx.AsyncClient(proxy=env.http_proxy_url, timeout=5.0) as client:
                    response = await client.get(env.get_echo_url(f"/cleanup/{i}"))
                    if response.status_code == 200:
                        success_count += 1
            except:
                pass
        
        # Should have high success rate for sequential requests
        success_rate = success_count / 50
        assert success_rate >= 0.9, f"Sequential cleanup test: only {success_rate*100:.1f}% success rate"

    @pytest.mark.asyncio
    @pytest.mark.timeout(60)
    @pytest.mark.performance
    @pytest.mark.sustained
    @pytest.mark.slow
    async def test_sustained_connection_load(self):
        """Test sustained connection load over extended time"""
        env = setup_test_environment()
        
        # Run sustained load for 30 seconds
        start_time = asyncio.get_event_loop().time()
        end_time = start_time + 30
        
        success_count = 0
        total_count = 0
        
        while asyncio.get_event_loop().time() < end_time:
            try:
                async with httpx.AsyncClient(proxy=env.http_proxy_url, timeout=5.0) as client:
                    response = await client.get(env.get_echo_url())
                    total_count += 1
                    if response.status_code == 200:
                        success_count += 1
                        
                # Small delay to avoid overwhelming
                await asyncio.sleep(0.1)
                
            except:
                total_count += 1
        
        if total_count > 0:
            success_rate = success_count / total_count
            assert success_rate >= 0.8, f"Sustained load: only {success_rate*100:.1f}% success rate over {total_count} requests"


# Run individual tests for debugging  
if __name__ == "__main__":
    # pytest tests/performance/test_connection_limits.py::TestConnectionLimits::test_concurrent_connections_stress
    print("Run with: pytest tests/performance/test_connection_limits.py")
    print("Or single test: pytest tests/performance/test_connection_limits.py::TestConnectionLimits::test_concurrent_connections_stress")
    print("Or all connection limit tests: pytest -k concurrent")