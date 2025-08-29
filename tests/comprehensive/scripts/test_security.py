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
    setup_test_environment
)
from test_reporter import TestReporter, TestResult
from test_framework import SelectiveTestRunner, run_test_script


async def test_basic_security() -> bool:
    """Test 1: Basic connection security"""
    TestLogger.test("Basic connection security")
    
    env = setup_test_environment()
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


async def test_error_handling_security() -> bool:
    """Test 2: Error handling with invalid targets"""
    TestLogger.test("Error handling security")
    
    env = setup_test_environment()
    
    try:
        import httpx
        
        # Test connection to non-existent server
        invalid_url = "http://nonexistent-server-12345.invalid:80/"
        
        async with httpx.AsyncClient(proxy=env.http_proxy_url, timeout=5.0) as client:
            try:
                response = await client.get(invalid_url)
                # HTTP error status codes (4xx, 5xx) are acceptable error handling
                if response.status_code >= 400:
                    TestLogger.info(f"✅ Correctly handled invalid target with HTTP {response.status_code}")
                    return True
                else:
                    TestLogger.error(f"❌ Should have failed for invalid target, got status {response.status_code}")
                    TestLogger.error(f"Response body: {response.text[:200]}")
                    return False
            except (httpx.RequestError, httpx.TimeoutException) as e:
                TestLogger.info(f"✅ Correctly handled invalid target: {type(e).__name__}")
                return True
                
    except Exception as e:
        TestLogger.error(f"❌ Error handling test failed: {e}")
        return False


async def test_connection_limits() -> bool:
    """Test 3: Connection handling under stress"""
    TestLogger.test("Connection limits and cleanup")
    
    env = setup_test_environment()
    
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


async def test_malformed_requests() -> bool:
    """Test 4: Handling of malformed requests"""
    TestLogger.test("Malformed request handling")
    
    env = setup_test_environment()
    
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
                response_str = response.decode('utf-8', errors='replace')
                TestLogger.info(f"Received response: {repr(response_str[:200])}")
                
                # Empty response means connection was closed - this indicates a bug
                # HTTP servers should send proper 400 Bad Request responses, not silently close
                if len(response) == 0:
                    TestLogger.error("❌ Connection closed without HTTP error response (bug: should send 400 Bad Request)")
                    return False
                
                # If we get a response, it should be a proper HTTP error response
                if b"400" in response or b"Bad Request" in response or b"HTTP/1.1 400" in response:
                    TestLogger.info("✅ Correctly handled malformed request with 400 error")
                    return True
                elif b"405" in response or b"Method Not Allowed" in response:
                    TestLogger.info("✅ Correctly handled malformed request with 405 error") 
                    return True
                elif b"HTTP/1.1" in response and (b"4" in response or b"5" in response):
                    TestLogger.info("✅ Correctly handled malformed request with HTTP error")
                    return True
                else:
                    TestLogger.error(f"❌ Got unexpected response to malformed request: {repr(response_str[:200])}")
                    return False
            except ConnectionResetError:
                TestLogger.info("✅ Connection reset for malformed request")
                return True
            except Exception as e:
                TestLogger.info(f"✅ Connection error for malformed request: {e}")
                return True
                
    except Exception as e:
        TestLogger.error(f"❌ Malformed request test failed: {e}")
        return False


async def test_request_size_limits() -> bool:
    """Test 5: Large request handling"""
    TestLogger.test("Request size limits")
    
    env = setup_test_environment()
    
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


def create_security_test_runner() -> SelectiveTestRunner:
    """Create and configure the security test runner"""
    runner = SelectiveTestRunner("Security Tests", "Tests security features, error handling, and edge cases")
    
    # Register all test functions
    runner.register_test("basic", "Basic connection security", test_basic_security)
    runner.register_test("errors", "Error handling with invalid targets", test_error_handling_security)
    runner.register_test("limits", "Connection limits testing", test_connection_limits)
    runner.register_test("malformed", "Malformed request handling", test_malformed_requests)
    runner.register_test("sizes", "Request size limits testing", test_request_size_limits)
    
    return runner


async def main():
    """Main security test execution using the reusable framework"""
    runner = create_security_test_runner()
    await run_test_script("test_security.py", "Security Tests", runner)


if __name__ == "__main__":
    asyncio.run(main())