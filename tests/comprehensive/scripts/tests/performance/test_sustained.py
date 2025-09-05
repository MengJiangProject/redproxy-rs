"""
Sustained load performance tests for redproxy

Tests proxy behavior under sustained load over extended periods
"""

import asyncio
import pytest
import httpx
import statistics
import time
import sys
import os

# Import from shared helpers
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../shared'))
from helpers import setup_test_environment


class TestSustainedLoad:
    """Sustained load performance tests"""

    @pytest.mark.asyncio
    @pytest.mark.timeout(120)  # 2 minutes timeout
    @pytest.mark.performance
    @pytest.mark.sustained
    @pytest.mark.slow
    async def test_sustained_load_30_seconds(self):
        """Test sustained load over 30 seconds - from test_sustained_load()"""
        env = setup_test_environment()
        duration_seconds = 30
        
        request_count = 0
        success_count = 0
        start_time = time.time()
        response_times = []
        
        while time.time() - start_time < duration_seconds:
            try:
                req_start = time.time()
                async with httpx.AsyncClient(proxy=env.http_proxy_url, timeout=10.0) as client:
                    response = await client.get(env.get_echo_url())
                    req_end = time.time()
                    
                    request_count += 1
                    if response.status_code == 200:
                        success_count += 1
                        response_times.append(req_end - req_start)
                
                # Small delay to avoid overwhelming
                await asyncio.sleep(0.1)
                
            except Exception:
                request_count += 1
        
        total_duration = time.time() - start_time
        success_rate = success_count / request_count if request_count > 0 else 0
        avg_rps = request_count / total_duration
        
        if response_times:
            avg_response_time = statistics.mean(response_times)
            p95_response_time = statistics.quantiles(response_times, n=20)[18] if len(response_times) >= 20 else avg_response_time
            
            print(f"Requests: {request_count} ({success_count} successful, {success_rate*100:.1f}%)")
            print(f"Average RPS: {avg_rps:.1f}")
            print(f"Response times - Avg: {avg_response_time*1000:.0f}ms, P95: {p95_response_time*1000:.0f}ms")
            
            assert success_rate >= 0.95, f"Low success rate: {success_rate*100:.1f}%"
            assert avg_response_time < 2.0, f"High average response time: {avg_response_time*1000:.0f}ms"
        else:
            pytest.fail("No successful requests in sustained load test")

    @pytest.mark.asyncio
    @pytest.mark.timeout(80)
    @pytest.mark.performance
    @pytest.mark.sustained
    @pytest.mark.slow
    async def test_sustained_load_with_connection_reuse(self):
        """Test sustained load with HTTP connection reuse - from test_connection_reuse()"""
        env = setup_test_environment()
        
        start_time = time.time()
        
        async with httpx.AsyncClient(proxy=env.http_proxy_url, timeout=10.0) as client:
            # Make multiple requests with the same client (should reuse connections)
            requests = []
            for i in range(10):
                requests.append(client.get(env.get_echo_url(f"/reuse/{i}")))
            
            responses = await asyncio.gather(*requests)
            
        end_time = time.time()
        duration = end_time - start_time
        
        # All requests should succeed
        success_count = sum(1 for r in responses if r.status_code == 200)
        
        print(f"Connection reuse: {success_count}/10 requests succeeded in {duration:.2f}s")
        
        assert success_count >= 9, f"Connection reuse failed: only {success_count}/10 succeeded"
        assert duration < 5.0, f"Connection reuse too slow: {duration:.2f}s"

    @pytest.mark.asyncio
    @pytest.mark.timeout(60)
    @pytest.mark.performance
    @pytest.mark.sustained
    @pytest.mark.slow
    @pytest.mark.parametrize("duration_seconds", [10, 20])
    async def test_sustained_load_varying_duration(self, duration_seconds):
        """Test sustained load over varying durations"""
        env = setup_test_environment()
        
        request_count = 0
        success_count = 0
        start_time = time.time()
        
        while time.time() - start_time < duration_seconds:
            try:
                async with httpx.AsyncClient(proxy=env.http_proxy_url, timeout=8.0) as client:
                    response = await client.get(env.get_echo_url(f"/sustained/{request_count}"))
                    request_count += 1
                    if response.status_code == 200:
                        success_count += 1
                
                # Faster cycle for shorter tests
                sleep_time = 0.05 if duration_seconds <= 10 else 0.1
                await asyncio.sleep(sleep_time)
                
            except Exception:
                request_count += 1
        
        total_duration = time.time() - start_time
        success_rate = success_count / request_count if request_count > 0 else 0
        avg_rps = request_count / total_duration
        
        print(f"Sustained {duration_seconds}s: {success_count}/{request_count} ({success_rate*100:.1f}%) at {avg_rps:.1f} RPS")
        
        # Shorter tests should have higher success rates
        min_success_rate = 0.98 if duration_seconds <= 10 else 0.95
        assert success_rate >= min_success_rate, \
            f"Sustained load ({duration_seconds}s) failed: {success_rate*100:.1f}% success rate"


# Run individual tests for debugging  
if __name__ == "__main__":
    # pytest tests/performance/test_sustained.py::TestSustainedLoad::test_sustained_load_30_seconds
    print("Run with: pytest tests/performance/test_sustained.py")
    print("Or single test: pytest tests/performance/test_sustained.py::TestSustainedLoad::test_sustained_load_30_seconds")
    print("Or all sustained tests: pytest -k sustained")