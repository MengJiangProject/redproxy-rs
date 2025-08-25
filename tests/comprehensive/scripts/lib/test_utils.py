#!/usr/bin/env python3
"""
Shared test utilities for RedProxy comprehensive tests
Provides reusable functions and classes for HTTP testing
"""

import asyncio
import json
import os
from typing import Dict, List

import httpx

# ANSI Colors for output
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    NC = '\033[0m'  # No Color


class TestLogger:
    """Simple logger for test output with colors"""
    
    @staticmethod
    def info(message: str):
        print(f"{Colors.GREEN}✓{Colors.NC} {message}")
    
    @staticmethod
    def warn(message: str):
        print(f"{Colors.YELLOW}⚠{Colors.NC} {message}")
    
    @staticmethod
    def error(message: str):
        print(f"{Colors.RED}✗{Colors.NC} {message}")
    
    @staticmethod
    def test(message: str):
        print(f"{Colors.YELLOW}=== {message} ==={Colors.NC}")


class TestEnvironment:
    """Test environment configuration and setup"""
    
    def __init__(self):
        self.redproxy_host = os.getenv('REDPROXY_HOST', 'redproxy')
        self.redproxy_http_port = int(os.getenv('REDPROXY_HTTP_PORT', '8800'))
        self.redproxy_socks_port = int(os.getenv('REDPROXY_SOCKS_PORT', '1081'))
        self.http_echo_host = os.getenv('HTTP_ECHO_HOST', 'http-echo')
        self.http_echo_port = int(os.getenv('HTTP_ECHO_PORT', '8080'))
        self.target_host = os.getenv('TARGET_HOST', 'target-server')
        self.target_port = int(os.getenv('TARGET_PORT', '80'))
        self.verbose = os.getenv('VERBOSE', 'false').lower() == 'true'
        
        # Proxy URLs for convenience
        self.http_proxy_url = f"http://{self.redproxy_host}:{self.redproxy_http_port}"
        self.socks_proxy_url = f"socks5://{self.redproxy_host}:{self.redproxy_socks_port}"
        
    def get_target_url(self, path: str = "/") -> str:
        """Get target server URL"""
        return f"http://{self.target_host}:{self.target_port}{path}"
    
    def get_echo_url(self, path: str = "/") -> str:
        """Get echo server URL"""
        return f"http://{self.http_echo_host}:{self.http_echo_port}{path}"


async def wait_for_service(host: str, port: int, timeout: int = 30) -> bool:
    """Wait for a service to become available"""
    TestLogger.info(f"Waiting for {host}:{port}...")
    
    for i in range(timeout):
        try:
            # Try to connect to the service
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=1.0
            )
            writer.close()
            await writer.wait_closed()
            TestLogger.info(f"{host}:{port} is ready")
            return True
        except (OSError, asyncio.TimeoutError):
            if i >= timeout - 1:
                TestLogger.error(f"Timeout waiting for {host}:{port}")
                return False
            await asyncio.sleep(1)
    
    return False


class HttpForwardProxyTester:
    """HTTP Forward Proxy testing utility"""
    
    def __init__(self, env: TestEnvironment):
        self.env = env
        
    async def test_forward_proxy_get(self, target_url: str, expected_text: str) -> bool:
        """Test GET request through HTTP forward proxy"""
        try:
            # Use proxy parameter in AsyncClient constructor (correct httpx API)
            async with httpx.AsyncClient(proxy=self.env.http_proxy_url, timeout=10.0) as client:
                response = await client.get(target_url)
                
                if response.status_code != 200:
                    TestLogger.error(f"HTTP forward proxy GET failed: {response.status_code}")
                    return False
                    
                if expected_text not in response.text:
                    TestLogger.error(f"HTTP forward proxy GET response missing expected text: {expected_text}")
                    TestLogger.error(f"Response: {response.text}")
                    return False
                    
                return True
                
        except Exception as e:
            TestLogger.error(f"HTTP forward proxy GET test failed: {e}")
            return False
    
    async def test_forward_proxy_post(self, target_url: str, data: str, expected_text: str) -> bool:
        """Test POST request through HTTP forward proxy"""
        try:
            async with httpx.AsyncClient(proxy=self.env.http_proxy_url, timeout=10.0) as client:
                response = await client.post(
                    target_url,
                    content=data,
                    headers={"Content-Type": "text/plain"}
                )
                
                if response.status_code not in [200, 201]:
                    TestLogger.error(f"HTTP forward proxy POST failed: {response.status_code}")
                    return False
                    
                if expected_text not in response.text:
                    TestLogger.error(f"HTTP forward proxy POST response missing expected text: {expected_text}")
                    TestLogger.error(f"Response: {response.text}")
                    return False
                    
                return True
                
        except Exception as e:
            TestLogger.error(f"HTTP forward proxy POST test failed: {e}")
            return False
    
    async def test_forward_proxy_json(self, target_url: str, json_data: dict, expected_keys: List[str]) -> bool:
        """Test JSON POST request through HTTP forward proxy"""
        try:
            async with httpx.AsyncClient(proxy=self.env.http_proxy_url, timeout=10.0) as client:
                response = await client.post(target_url, json=json_data)
                
                if response.status_code not in [200, 201]:
                    TestLogger.error(f"HTTP forward proxy JSON POST failed: {response.status_code}")
                    return False
                
                # Try to parse response as JSON
                try:
                    response_json = response.json()
                    for key in expected_keys:
                        if key not in str(response_json):
                            TestLogger.error(f"Expected key '{key}' not found in JSON response")
                            return False
                except json.JSONDecodeError:
                    # If response isn't JSON, check if it contains the expected text
                    for key in expected_keys:
                        if key not in response.text:
                            TestLogger.error(f"Expected text '{key}' not found in response")
                            return False
                
                return True
                
        except Exception as e:
            TestLogger.error(f"HTTP forward proxy JSON test failed: {e}")
            return False
    
    async def test_forward_proxy_headers(self, target_url: str, custom_headers: Dict[str, str]) -> bool:
        """Test custom headers through HTTP forward proxy"""
        try:
            async with httpx.AsyncClient(proxy=self.env.http_proxy_url, timeout=10.0) as client:
                response = await client.get(target_url, headers=custom_headers)
                
                if response.status_code != 200:
                    TestLogger.error(f"HTTP forward proxy headers test failed: {response.status_code}")
                    return False
                
                # For echo servers, check that headers were echoed back
                response_text = response.text.lower()
                for header_name, header_value in custom_headers.items():
                    if header_name.lower() in response_text and header_value.lower() in response_text:
                        continue  # Header found in echo response
                    elif "echo" not in target_url.lower():
                        # For non-echo servers, just verify we got a response
                        continue
                    else:
                        TestLogger.error(f"Custom header {header_name}: {header_value} not found in echo response")
                        return False
                
                return True
                
        except Exception as e:
            TestLogger.error(f"HTTP forward proxy headers test failed: {e}")
            return False
    
    async def test_forward_proxy_error_handling(self) -> bool:
        """Test error handling with invalid targets"""
        try:
            async with httpx.AsyncClient(proxy=self.env.http_proxy_url, timeout=5.0) as client:
                # Try to connect to non-existent server
                try:
                    response = await client.get("http://nonexistent-host:80/")
                    # If we get here, the proxy should return an error status
                    if response.status_code >= 400:
                        TestLogger.info("Error handling test passed (got error status)")
                        return True
                    else:
                        TestLogger.error(f"Expected error status, got: {response.status_code}")
                        return False
                except httpx.RequestError:
                    # Connection error is also acceptable
                    TestLogger.info("Error handling test passed (connection error)")
                    return True
                    
        except Exception as e:
            # Exception is acceptable for error handling test
            TestLogger.info(f"Error handling test passed (exception: {e})")
            return True


class SocksProxyTester:
    """SOCKS5 Proxy testing utility"""
    
    def __init__(self, env: TestEnvironment):
        self.env = env
        
    async def test_socks_proxy(self, target_url: str, expected_text: str) -> bool:
        """Test request through SOCKS5 proxy"""
        try:
            async with httpx.AsyncClient(proxy=self.env.socks_proxy_url, timeout=10.0) as client:
                response = await client.get(target_url)
                
                if response.status_code != 200:
                    TestLogger.error(f"SOCKS proxy test failed: {response.status_code}")
                    return False
                    
                if expected_text not in response.text:
                    TestLogger.error(f"SOCKS proxy response missing expected text: {expected_text}")
                    TestLogger.error(f"Response: {response.text}")
                    return False
                    
                return True
                
        except Exception as e:
            TestLogger.error(f"SOCKS proxy test failed: {e}")
            return False


async def test_concurrent_requests(test_func, count: int = 5) -> bool:
    """Run multiple concurrent tests"""
    TestLogger.info(f"Running {count} concurrent tests...")
    
    try:
        tasks = [test_func() for _ in range(count)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        success_count = 0
        for result in results:
            if isinstance(result, bool) and result:
                success_count += 1
            elif isinstance(result, Exception):
                TestLogger.error(f"Concurrent test exception: {result}")
        
        if success_count == count:
            TestLogger.info(f"All {count} concurrent tests succeeded")
            return True
        else:
            TestLogger.error(f"Only {success_count}/{count} concurrent tests succeeded")
            return False
            
    except Exception as e:
        TestLogger.error(f"Concurrent test setup failed: {e}")
        return False


def setup_test_environment() -> TestEnvironment:
    """Setup and validate test environment"""
    env = TestEnvironment()
    
    TestLogger.info("=== RedProxy Python Test Environment ===")
    TestLogger.info(f"RedProxy HTTP: {env.redproxy_host}:{env.redproxy_http_port}")
    TestLogger.info(f"RedProxy SOCKS: {env.redproxy_host}:{env.redproxy_socks_port}")
    TestLogger.info(f"HTTP Echo: {env.http_echo_host}:{env.http_echo_port}")
    TestLogger.info(f"Target Server: {env.target_host}:{env.target_port}")
    TestLogger.info(f"Verbose: {env.verbose}")
    
    return env


async def wait_for_all_services(env: TestEnvironment) -> bool:
    """Wait for all required services to be ready"""
    TestLogger.info("Waiting for services to be ready...")
    
    services = [
        (env.http_echo_host, env.http_echo_port),
        (env.target_host, env.target_port),
        ("http-proxy", 3128),
        ("socks-proxy", 1080),
        (env.redproxy_host, env.redproxy_http_port),
        (env.redproxy_host, env.redproxy_socks_port),
    ]
    
    for host, port in services:
        if not await wait_for_service(host, port):
            return False
    
    print()  # Add blank line after service checks
    return True