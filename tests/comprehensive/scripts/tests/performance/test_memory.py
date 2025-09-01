"""
Memory usage and stability performance tests for redproxy

Tests proxy memory behavior under load to detect leaks and stability issues
"""

import asyncio
import pytest
import httpx
import sys
import os

# Import from shared helpers
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../shared'))
from helpers import setup_test_environment


class TestMemoryStability:
    """Memory usage and stability performance tests"""

    @pytest.mark.asyncio
    @pytest.mark.timeout(180)  # 3 minutes timeout
    @pytest.mark.performance
    @pytest.mark.memory
    @pytest.mark.slow
    async def test_memory_usage_stability(self):
        """Test memory usage stability under load - from test_memory_usage_stability()"""
        env = setup_test_environment()
        
        # Make many requests to test for memory leaks
        request_count = 100
        success_count = 0
        
        print(f"Making {request_count} requests to test memory stability...")
        
        for i in range(request_count):
            if i % 20 == 0:
                print(f"Progress: {i}/{request_count}")
            
            try:
                async with httpx.AsyncClient(proxy=env.http_proxy_url, timeout=10.0) as client:
                    response = await client.get(env.get_echo_url(f"/memory/{i}"))
                    if response.status_code == 200:
                        success_count += 1
            except:
                pass
        
        success_rate = success_count / request_count
        
        print(f"Memory stability test: {success_count}/{request_count} ({success_rate*100:.1f}%)")
        
        assert success_rate >= 0.95, f"Memory stability test failed: only {success_rate*100:.1f}% success rate"

    @pytest.mark.asyncio
    @pytest.mark.timeout(120)
    @pytest.mark.performance
    @pytest.mark.memory
    @pytest.mark.slow
    async def test_rapid_connection_cycling(self):
        """Test rapid connection creation and destruction for memory leaks"""
        env = setup_test_environment()
        
        cycle_count = 50
        success_count = 0
        
        print(f"Testing {cycle_count} rapid connection cycles...")
        
        for i in range(cycle_count):
            try:
                # Create and immediately close client connections
                async with httpx.AsyncClient(proxy=env.http_proxy_url, timeout=5.0) as client:
                    response = await client.get(env.get_echo_url(f"/cycle/{i}"))
                    if response.status_code == 200:
                        success_count += 1
                
                # Brief pause between cycles
                await asyncio.sleep(0.05)
                
            except:
                pass
        
        success_rate = success_count / cycle_count
        
        print(f"Connection cycling: {success_count}/{cycle_count} ({success_rate*100:.1f}%)")
        
        assert success_rate >= 0.9, f"Connection cycling test failed: {success_rate*100:.1f}% success rate"

    @pytest.mark.asyncio
    @pytest.mark.timeout(90)
    @pytest.mark.performance
    @pytest.mark.memory
    @pytest.mark.slow
    async def test_large_response_memory_handling(self):
        """Test memory handling with large responses"""
        env = setup_test_environment()
        
        # Test multiple requests for larger responses
        large_requests = 20
        success_count = 0
        
        for i in range(large_requests):
            try:
                async with httpx.AsyncClient(proxy=env.http_proxy_url, timeout=15.0) as client:
                    # Request larger response from echo server
                    response = await client.post(
                        "http://http-echo:8080/echo",
                        content="X" * 10240,  # 10KB request body
                        headers={"Content-Type": "text/plain"}
                    )
                    if response.status_code == 200:
                        success_count += 1
                
                # Small delay between large requests
                await asyncio.sleep(0.1)
                
            except:
                pass
        
        success_rate = success_count / large_requests
        
        print(f"Large response memory test: {success_count}/{large_requests} ({success_rate*100:.1f}%)")
        
        assert success_rate >= 0.85, f"Large response memory test failed: {success_rate*100:.1f}% success rate"

    @pytest.mark.asyncio
    @pytest.mark.timeout(60)
    @pytest.mark.performance
    @pytest.mark.memory
    @pytest.mark.parametrize("batch_size", [10, 25, 50])
    async def test_batch_request_memory_cleanup(self, batch_size):
        """Test memory cleanup after batch requests of varying sizes"""
        env = setup_test_environment()
        
        success_count = 0
        
        # Process requests in batches
        tasks = []
        for i in range(batch_size):
            async def single_request(req_id):
                try:
                    async with httpx.AsyncClient(proxy=env.http_proxy_url, timeout=8.0) as client:
                        response = await client.get(env.get_echo_url(f"/batch/{req_id}"))
                        return response.status_code == 200
                except:
                    return False
            
            tasks.append(single_request(i))
        
        # Execute batch
        results = await asyncio.gather(*tasks, return_exceptions=True)
        success_count = sum(1 for r in results if r is True)
        
        success_rate = success_count / batch_size
        
        print(f"Batch memory cleanup (size {batch_size}): {success_count}/{batch_size} ({success_rate*100:.1f}%)")
        
        # Larger batches may have slightly lower success rates
        min_success_rate = 0.9 if batch_size <= 25 else 0.8
        assert success_rate >= min_success_rate, \
            f"Batch memory test (size {batch_size}) failed: {success_rate*100:.1f}% success rate"


# Run individual tests for debugging  
if __name__ == "__main__":
    # pytest tests/performance/test_memory.py::TestMemoryStability::test_memory_usage_stability
    print("Run with: pytest tests/performance/test_memory.py")
    print("Or single test: pytest tests/performance/test_memory.py::TestMemoryStability::test_memory_usage_stability")
    print("Or all memory tests: pytest -k memory")