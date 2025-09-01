"""
Throughput and latency performance tests for redproxy

Tests proxy throughput characteristics and response latency
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


class TestThroughput:
    """Throughput and latency performance tests"""

    @pytest.mark.asyncio
    @pytest.mark.timeout(60)
    @pytest.mark.performance
    @pytest.mark.throughput
    async def test_basic_throughput_measurement(self):
        """Test basic throughput measurement over fixed request count"""
        env = setup_test_environment()
        request_count = 50
        
        start_time = time.time()
        success_count = 0
        response_times = []
        
        for i in range(request_count):
            try:
                req_start = time.time()
                async with httpx.AsyncClient(proxy=env.http_proxy_url, timeout=10.0) as client:
                    response = await client.get(env.get_echo_url(f"/throughput/{i}"))
                    req_end = time.time()
                    
                    if response.status_code == 200:
                        success_count += 1
                        response_times.append(req_end - req_start)
                        
            except:
                pass
        
        total_time = time.time() - start_time
        
        if response_times:
            avg_response_time = statistics.mean(response_times)
            throughput = success_count / total_time
            
            print(f"Throughput: {success_count}/{request_count} requests in {total_time:.2f}s")
            print(f"RPS: {throughput:.1f}, Avg latency: {avg_response_time*1000:.1f}ms")
            
            success_rate = success_count / request_count
            assert success_rate >= 0.95, f"Low throughput success rate: {success_rate*100:.1f}%"
            assert avg_response_time < 1.0, f"High average latency: {avg_response_time*1000:.1f}ms"
        else:
            pytest.fail("No successful requests for throughput measurement")

    @pytest.mark.asyncio
    @pytest.mark.timeout(45)
    @pytest.mark.performance
    @pytest.mark.throughput
    async def test_parallel_throughput_measurement(self):
        """Test throughput with parallel request execution"""
        env = setup_test_environment()
        parallel_count = 10
        
        async def measure_parallel_batch():
            tasks = []
            start_time = time.time()
            
            for i in range(parallel_count):
                async def single_request(req_id):
                    try:
                        req_start = time.time()
                        async with httpx.AsyncClient(proxy=env.http_proxy_url, timeout=8.0) as client:
                            response = await client.get(env.get_echo_url(f"/parallel/{req_id}"))
                            req_end = time.time()
                            return (response.status_code == 200, req_end - req_start)
                    except:
                        return (False, 0)
                
                tasks.append(single_request(i))
            
            results = await asyncio.gather(*tasks)
            end_time = time.time()
            
            successes = [r for r in results if r[0]]
            response_times = [r[1] for r in results if r[0]]
            
            return len(successes), response_times, end_time - start_time
        
        success_count, response_times, duration = await measure_parallel_batch()
        
        if response_times:
            avg_response_time = statistics.mean(response_times)
            parallel_throughput = success_count / duration
            
            print(f"Parallel throughput: {success_count}/{parallel_count} in {duration:.2f}s")
            print(f"Parallel RPS: {parallel_throughput:.1f}, Avg latency: {avg_response_time*1000:.1f}ms")
            
            success_rate = success_count / parallel_count
            assert success_rate >= 0.9, f"Low parallel throughput: {success_rate*100:.1f}% success"
            assert avg_response_time < 1.5, f"High parallel latency: {avg_response_time*1000:.1f}ms"
        else:
            pytest.fail("No successful parallel requests")

    @pytest.mark.asyncio
    @pytest.mark.timeout(90)
    @pytest.mark.performance
    @pytest.mark.throughput
    @pytest.mark.parametrize("request_size", [1024, 4096, 8192])
    async def test_throughput_with_varying_request_sizes(self, request_size):
        """Test throughput with varying request body sizes"""
        env = setup_test_environment()
        request_count = 20
        
        # Create request body of specified size
        request_body = "X" * request_size
        
        start_time = time.time()
        success_count = 0
        response_times = []
        
        for i in range(request_count):
            try:
                req_start = time.time()
                async with httpx.AsyncClient(proxy=env.http_proxy_url, timeout=15.0) as client:
                    response = await client.post(
                        "http://http-echo:8080/echo",
                        content=request_body,
                        headers={"Content-Type": "text/plain"}
                    )
                    req_end = time.time()
                    
                    if response.status_code == 200:
                        success_count += 1
                        response_times.append(req_end - req_start)
                        
            except:
                pass
        
        total_time = time.time() - start_time
        
        if response_times:
            avg_response_time = statistics.mean(response_times)
            throughput = success_count / total_time
            
            print(f"Size {request_size}B: {success_count}/{request_count} in {total_time:.2f}s")
            print(f"RPS: {throughput:.1f}, Avg latency: {avg_response_time*1000:.1f}ms")
            
            success_rate = success_count / request_count
            # Larger requests may have slightly lower success rates and higher latency
            min_success_rate = 0.9 if request_size <= 4096 else 0.8
            max_latency = 2.0 if request_size <= 4096 else 3.0
            
            assert success_rate >= min_success_rate, \
                f"Low throughput for {request_size}B: {success_rate*100:.1f}% success"
            assert avg_response_time < max_latency, \
                f"High latency for {request_size}B: {avg_response_time*1000:.1f}ms"
        else:
            pytest.fail(f"No successful requests for {request_size}B throughput test")

    @pytest.mark.asyncio
    @pytest.mark.timeout(30)
    @pytest.mark.performance
    @pytest.mark.throughput
    async def test_latency_consistency(self):
        """Test latency consistency across multiple requests"""
        env = setup_test_environment()
        request_count = 30
        
        response_times = []
        
        for i in range(request_count):
            try:
                start_time = time.time()
                async with httpx.AsyncClient(proxy=env.http_proxy_url, timeout=8.0) as client:
                    response = await client.get(env.get_echo_url(f"/latency/{i}"))
                    end_time = time.time()
                    
                    if response.status_code == 200:
                        response_times.append(end_time - start_time)
                        
            except:
                pass
        
        if len(response_times) >= 20:  # Need enough samples
            avg_latency = statistics.mean(response_times)
            latency_stddev = statistics.stdev(response_times)
            min_latency = min(response_times)
            max_latency = max(response_times)
            
            print(f"Latency consistency: {len(response_times)} samples")
            print(f"Avg: {avg_latency*1000:.1f}ms, StdDev: {latency_stddev*1000:.1f}ms")
            print(f"Min: {min_latency*1000:.1f}ms, Max: {max_latency*1000:.1f}ms")
            
            # Check for reasonable consistency
            assert avg_latency < 1.0, f"High average latency: {avg_latency*1000:.1f}ms"
            assert latency_stddev < 0.5, f"High latency variance: {latency_stddev*1000:.1f}ms"
            assert max_latency < 2.0, f"Excessive max latency: {max_latency*1000:.1f}ms"
        else:
            pytest.fail(f"Not enough samples for latency consistency: {len(response_times)}")


# Run individual tests for debugging  
if __name__ == "__main__":
    # pytest tests/performance/test_throughput.py::TestThroughput::test_basic_throughput_measurement
    print("Run with: pytest tests/performance/test_throughput.py")
    print("Or single test: pytest tests/performance/test_throughput.py::TestThroughput::test_basic_throughput_measurement")
    print("Or all throughput tests: pytest -k throughput")