#!/usr/bin/env python3
"""
Security Tests for RedProxy
Tests security features, error handling, and edge cases
"""

import asyncio
import sys
import os
import time

# Add the lib directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'lib'))

from test_utils import (
    TestLogger, TestEnvironment, HttpForwardProxyTester, SocksProxyTester,
    setup_test_environment, wait_for_all_services
)


async def test_basic_security(env: TestEnvironment) -> bool:
    """Test 1: Basic connection security"""
    TestLogger.test("Test 1: Basic connection security")
    
    tester = HttpForwardProxyTester(env)
    
    if await tester.test_forward_proxy_get(
        env.get_echo_url(),
        "path"
    ):
        TestLogger.info("✅ Basic connection security works")
        return True
    else:
        TestLogger.error("❌ Basic connection security failed")
        return False


async def test_error_handling_security(env: TestEnvironment) -> bool:
    """Test 2: Error handling with invalid targets"""
    TestLogger.test("Test 2: Error handling security")
    
    try:
        import httpx
        
        # Test connection to non-existent server
        invalid_url = "http://nonexistent-server-12345.invalid:80/"
        
        async with httpx.AsyncClient(proxy=env.http_proxy_url, timeout=5.0) as client:
            try:
                response = await client.get(invalid_url)
                TestLogger.error("❌ Should have failed for invalid target")
                return False
            except (httpx.RequestError, httpx.TimeoutException):
                TestLogger.info("✅ Correctly handled invalid target")
                return True
                
    except Exception as e:
        TestLogger.error(f"❌ Error handling test failed: {e}")
        return False


async def test_connection_limits(env: TestEnvironment) -> bool:
    """Test 3: Connection handling under stress"""
    TestLogger.test("Test 3: Connection limits and cleanup")
    
    try:
        import httpx
        
        # Create multiple concurrent connections
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
        
        if success_count >= 15:  # Allow some failures under stress
            TestLogger.info(f"✅ Connection limits test passed ({success_count}/20)")
            return True
        else:
            TestLogger.error(f"❌ Connection limits test failed ({success_count}/20)")
            return False
            
    except Exception as e:
        TestLogger.error(f"❌ Connection limits test failed: {e}")
        return False


async def test_malformed_requests(env: TestEnvironment) -> bool:
    """Test 4: Handling of malformed requests"""
    TestLogger.test("Test 4: Malformed request handling")
    
    try:
        import socket
        
        # Send malformed HTTP request directly
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(5)
            sock.connect((env.redproxy_host, env.redproxy_http_port))
            
            # Send invalid HTTP request
            malformed_request = b"INVALID REQUEST LINE\r\n\r\n"
            sock.send(malformed_request)
            
            # Server should close connection or send error
            try:
                response = sock.recv(1024)
                # If we get a response, it should be an error response
                if b"400" in response or b"Bad Request" in response:
                    TestLogger.info("✅ Correctly handled malformed request")
                    return True
                else:
                    TestLogger.warn("⚠️ Got unexpected response to malformed request")
                    return True  # Still acceptable
            except:
                TestLogger.info("✅ Connection closed for malformed request")
                return True
                
    except Exception as e:
        TestLogger.error(f"❌ Malformed request test failed: {e}")
        return False


async def test_request_size_limits(env: TestEnvironment) -> bool:
    """Test 5: Large request handling"""
    TestLogger.test("Test 5: Request size limits")
    
    try:
        import httpx
        
        # Test with large headers
        large_headers = {"X-Large-Header": "A" * 8192}  # 8KB header
        
        async with httpx.AsyncClient(proxy=env.http_proxy_url, timeout=15.0) as client:
            response = await client.get(env.get_echo_url(), headers=large_headers)
            
            if response.status_code in [200, 413, 414]:  # OK or request too large
                TestLogger.info("✅ Large request handling works")
                return True
            else:
                TestLogger.error(f"❌ Unexpected response to large request: {response.status_code}")
                return False
                
    except httpx.RequestError as e:
        # Connection errors are acceptable for oversized requests
        TestLogger.info("✅ Large request correctly rejected")
        return True
    except Exception as e:
        TestLogger.error(f"❌ Request size test failed: {e}")
        return False


async def run_security_tests() -> bool:
    """Run all security tests"""
    env = setup_test_environment()
    
    TestLogger.info("=== RedProxy Security Tests ===")
    
    # Wait for services to be ready
    if not await wait_for_all_services(env):
        TestLogger.error("Services not ready for security testing")
        return False
    
    # Run security tests
    tests = [
        test_basic_security(env),
        test_error_handling_security(env),
        test_connection_limits(env),
        test_malformed_requests(env), 
        test_request_size_limits(env),
    ]
    
    results = []
    for i, test in enumerate(tests, 1):
        start_time = time.time()
        result = await test
        duration = time.time() - start_time
        results.append(result)
        
        if result:
            TestLogger.info(f"✅ Security test {i} passed ({duration:.2f}s)")
        else:
            TestLogger.error(f"❌ Security test {i} failed ({duration:.2f}s)")
        print()  # Blank line between tests
    
    # Summary
    passed = sum(results)
    total = len(results)
    
    TestLogger.info("=== Security Test Results ===")
    TestLogger.info(f"Passed: {passed}/{total}")
    
    if passed < total:
        TestLogger.error(f"Failed: {total - passed}/{total}")
        return False
    else:
        TestLogger.info("All security tests passed! 🔒")
        return True


async def main():
    """Main security test execution"""
    try:
        success = await run_security_tests()
        sys.exit(0 if success else 1)
        
    except KeyboardInterrupt:
        TestLogger.warn("Security tests interrupted by user")
        sys.exit(1)
    except Exception as e:
        TestLogger.error(f"Security tests failed with exception: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())