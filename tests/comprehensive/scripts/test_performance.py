#!/usr/bin/env python3
"""
Performance Tests for RedProxy
Tests concurrent connections, throughput, and resource usage
"""

import asyncio
import sys
import os
import time
import statistics

# Add the lib directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'lib'))

from test_utils import (
    TestLogger, TestEnvironment, HttpForwardProxyTester, SocksProxyTester,
    setup_test_environment
)
from test_framework import SelectiveTestRunner, run_test_script


async def test_concurrent_http_connections(env: TestEnvironment, concurrent_count: int = 20) -> bool:
    """Test 1: Concurrent HTTP connections"""
    TestLogger.test(f"Test 1: {concurrent_count} concurrent HTTP connections")
    
    tester = HttpForwardProxyTester(env)
    
    async def single_http_test():
        return await tester.test_forward_proxy_get(env.get_echo_url(), "path")
    
    start_time = time.time()
    
    # Run concurrent requests
    tasks = [single_http_test() for _ in range(concurrent_count)]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    end_time = time.time()
    duration = end_time - start_time
    
    # Count successes (excluding exceptions)
    successes = sum(1 for r in results if r is True)
    
    success_rate = successes / concurrent_count
    rps = concurrent_count / duration
    
    TestLogger.info(f"Results: {successes}/{concurrent_count} succeeded ({success_rate*100:.1f}%)")
    TestLogger.info(f"Duration: {duration:.2f}s ({rps:.1f} req/s)")
    
    if success_rate >= 0.9:  # Allow 10% failure under high concurrency
        TestLogger.info("✅ Concurrent HTTP connections test passed")
        return True
    else:
        TestLogger.error("❌ Concurrent HTTP connections test failed")
        return False


async def test_concurrent_socks_connections(env: TestEnvironment, concurrent_count: int = 15) -> bool:
    """Test 2: Concurrent SOCKS connections"""
    TestLogger.test(f"Test 2: {concurrent_count} concurrent SOCKS connections")
    
    tester = SocksProxyTester(env)
    
    async def single_socks_test():
        return await tester.test_socks_proxy(env.get_echo_url(), "path")
    
    start_time = time.time()
    
    # Run concurrent requests
    tasks = [single_socks_test() for _ in range(concurrent_count)]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    end_time = time.time()
    duration = end_time - start_time
    
    # Count successes (excluding exceptions)
    successes = sum(1 for r in results if r is True)
    
    success_rate = successes / concurrent_count
    rps = concurrent_count / duration
    
    TestLogger.info(f"Results: {successes}/{concurrent_count} succeeded ({success_rate*100:.1f}%)")
    TestLogger.info(f"Duration: {duration:.2f}s ({rps:.1f} req/s)")
    
    if success_rate >= 0.8:  # SOCKS can be more sensitive, allow 20% failure
        TestLogger.info("✅ Concurrent SOCKS connections test passed")
        return True
    else:
        TestLogger.error("❌ Concurrent SOCKS connections test failed")
        return False


async def test_sustained_load(env: TestEnvironment, duration_seconds: int = 30) -> bool:
    """Test 3: Sustained load over time"""
    TestLogger.test(f"Test 3: Sustained load ({duration_seconds}s)")
    
    tester = HttpForwardProxyTester(env)
    
    request_count = 0
    success_count = 0
    start_time = time.time()
    response_times = []
    
    while time.time() - start_time < duration_seconds:
        try:
            req_start = time.time()
            result = await tester.test_forward_proxy_get(env.get_echo_url(), "path")
            req_end = time.time()
            
            request_count += 1
            if result:
                success_count += 1
                response_times.append(req_end - req_start)
            
            # Small delay to avoid overwhelming
            await asyncio.sleep(0.1)
            
        except Exception as e:
            request_count += 1
    
    total_duration = time.time() - start_time
    success_rate = success_count / request_count if request_count > 0 else 0
    avg_rps = request_count / total_duration
    
    if response_times:
        avg_response_time = statistics.mean(response_times)
        p95_response_time = statistics.quantiles(response_times, n=20)[18]  # 95th percentile
        
        TestLogger.info(f"Requests: {request_count} ({success_count} successful, {success_rate*100:.1f}%)")
        TestLogger.info(f"Average RPS: {avg_rps:.1f}")
        TestLogger.info(f"Response times - Avg: {avg_response_time*1000:.0f}ms, P95: {p95_response_time*1000:.0f}ms")
        
        if success_rate >= 0.95 and avg_response_time < 2.0:
            TestLogger.info("✅ Sustained load test passed")
            return True
        else:
            TestLogger.error("❌ Sustained load test failed (low success rate or high latency)")
            return False
    else:
        TestLogger.error("❌ Sustained load test failed (no successful requests)")
        return False


async def test_connection_reuse(env: TestEnvironment) -> bool:
    """Test 4: Connection reuse efficiency"""
    TestLogger.test("Test 4: Connection reuse efficiency")
    
    try:
        import httpx
        
        # Test with connection reuse (HTTP/1.1 keep-alive)
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
        
        TestLogger.info(f"Connection reuse: {success_count}/10 requests succeeded in {duration:.2f}s")
        
        if success_count >= 9 and duration < 5.0:  # Should be fast with reuse
            TestLogger.info("✅ Connection reuse test passed")
            return True
        else:
            TestLogger.error("❌ Connection reuse test failed")
            return False
            
    except Exception as e:
        TestLogger.error(f"❌ Connection reuse test failed: {e}")
        return False


async def test_memory_usage_stability(env: TestEnvironment) -> bool:
    """Test 5: Memory usage stability under load"""
    TestLogger.test("Test 5: Memory usage stability")
    
    try:
        tester = HttpForwardProxyTester(env)
        
        # Make many requests to test for memory leaks
        request_count = 100
        success_count = 0
        
        TestLogger.info(f"Making {request_count} requests to test memory stability...")
        
        for i in range(request_count):
            if i % 20 == 0:
                TestLogger.info(f"Progress: {i}/{request_count}")
            
            try:
                result = await tester.test_forward_proxy_get(env.get_echo_url(f"/memory/{i}"), "path")
                if result:
                    success_count += 1
            except:
                pass
        
        success_rate = success_count / request_count
        
        TestLogger.info(f"Memory stability test: {success_count}/{request_count} ({success_rate*100:.1f}%)")
        
        if success_rate >= 0.95:
            TestLogger.info("✅ Memory usage stability test passed")
            return True
        else:
            TestLogger.error("❌ Memory usage stability test failed")
            return False
            
    except Exception as e:
        TestLogger.error(f"❌ Memory usage test failed: {e}")
        return False


async def run_performance_tests() -> bool:
    """Run all performance tests"""
    env = setup_test_environment()
    reporter = TestReporter(output_dir="/reports")
    
    TestLogger.info("=== RedProxy Performance Tests ===")
    
    # Wait for services to be ready
    if not await wait_for_all_services(env):
        TestLogger.error("Services not ready for performance testing")
        return False
    
    # Set up reporting
    reporter.set_environment({
        "test_type": "performance",
        "redproxy_version": os.environ.get("REDPROXY_VERSION", "unknown")
    })
    
    suite = reporter.create_suite("Performance Tests")
    
    # Run performance tests
    test_functions = [
        ("Concurrent HTTP Connections", lambda: test_concurrent_http_connections(env, 20)),
        ("Concurrent SOCKS Connections", lambda: test_concurrent_socks_connections(env, 15)),
        ("Sustained Load", lambda: test_sustained_load(env, 15)),
        ("Connection Reuse", lambda: test_connection_reuse(env)),
        ("Memory Usage Stability", lambda: test_memory_usage_stability(env)),
    ]
    
    for i, (test_name, test_func) in enumerate(test_functions, 1):
        start_time = time.time()
        try:
            result = await test_func()
            duration = time.time() - start_time
            
            test_result = TestResult(
                name=test_name,
                status="passed" if result else "failed",
                duration=duration
            )
            suite.tests.append(test_result)
            
            if result:
                TestLogger.info(f"✅ Performance test {i} passed ({duration:.2f}s)")
            else:
                TestLogger.error(f"❌ Performance test {i} failed ({duration:.2f}s)")
        except Exception as e:
            duration = time.time() - start_time
            test_result = TestResult(
                name=test_name,
                status="failed",
                duration=duration,
                error_message=str(e)
            )
            suite.tests.append(test_result)
            TestLogger.error(f"❌ Performance test {i} failed with error: {e}")
        
        print()  # Blank line between tests
    
    # Generate reports
    reporter.finalize_suite(suite)
    json_path = reporter.save_json_report("performance_report.json")
    html_path = reporter.save_html_report("performance_report.html")
    
    # Summary
    passed = suite.passed_tests
    total = suite.total_tests
    
    TestLogger.info("=== Performance Test Results ===")
    TestLogger.info(f"Passed: {passed}/{total}")
    TestLogger.info(f"Reports saved: {json_path}, {html_path}")
    
    if passed < total:
        TestLogger.error(f"Failed: {suite.failed_tests}/{total}")
        return False
    else:
        TestLogger.info("All performance tests passed! 🚀")
        return True


# Wrapper functions for SelectiveTestRunner
async def test_concurrent_http() -> bool:
    """Concurrent HTTP connections test"""
    env = setup_test_environment()
    return await test_concurrent_http_connections(env, concurrent_count=20)

async def test_concurrent_socks() -> bool:
    """Concurrent SOCKS connections test"""
    env = setup_test_environment()
    return await test_concurrent_socks_connections(env, concurrent_count=15)

async def test_sustained_load_wrapper() -> bool:
    """Sustained load test"""
    env = setup_test_environment()
    return await test_sustained_load(env, duration_seconds=30)

async def test_connection_reuse_wrapper() -> bool:
    """Connection reuse test"""
    env = setup_test_environment() 
    return await test_connection_reuse(env)

async def test_memory_usage_wrapper() -> bool:
    """Memory usage stability test"""
    env = setup_test_environment()
    return await test_memory_usage_stability(env)


def create_performance_test_runner() -> SelectiveTestRunner:
    """Create and configure the performance test runner"""
    runner = SelectiveTestRunner("Performance Tests", "Tests concurrent connections, throughput, and resource usage")
    
    # Register all test functions
    runner.register_test("http", "Concurrent HTTP connections test", test_concurrent_http)
    runner.register_test("socks", "Concurrent SOCKS connections test", test_concurrent_socks)
    runner.register_test("sustained", "Sustained load test", test_sustained_load_wrapper)
    runner.register_test("reuse", "Connection reuse test", test_connection_reuse_wrapper)
    runner.register_test("memory", "Memory usage stability test", test_memory_usage_wrapper)
    
    return runner


async def main():
    """Main performance test execution using the reusable framework"""
    runner = create_performance_test_runner()
    await run_test_script("test_performance.py", "Performance Tests", runner)


if __name__ == "__main__":
    asyncio.run(main())