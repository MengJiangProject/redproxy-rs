"""
Shared test helper functions for pytest tests

Pure implementation - no legacy dependencies
"""

import asyncio
import socket
from typing import List, Optional


class TestEnvironment:
    """Test environment configuration"""
    def __init__(self):
        self.redproxy_host = "redproxy"
        self.redproxy_http_port = 8800
        self.redproxy_socks_port = 1081  # Base config SOCKS port
        self.http_proxy_url = f"http://{self.redproxy_host}:{self.redproxy_http_port}"
        self.socks_proxy_url = f"socks5://{self.redproxy_host}:{self.redproxy_socks_port}"
        
    def get_echo_url(self, path: str = "/") -> str:
        """Get echo server URL with optional path"""
        return f"http://http-echo:8080{path}"


def setup_test_environment() -> TestEnvironment:
    """Set up test environment configuration"""
    return TestEnvironment()


async def wait_for_service(host: str, port: int, timeout: float = 30.0) -> bool:
    """Wait for a TCP service to become available"""
    start_time = asyncio.get_event_loop().time()
    
    while asyncio.get_event_loop().time() - start_time < timeout:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), 
                timeout=1.0
            )
            writer.close()
            await writer.wait_closed()
            return True
        except (ConnectionRefusedError, asyncio.TimeoutError, OSError):
            await asyncio.sleep(0.1)
            
    return False


async def read_http_response(reader: asyncio.StreamReader, timeout: float = 10.0) -> str:
    """Read a complete HTTP response - from your existing code"""
    response = ""
    
    # Read status line and headers with connection closure detection
    while True:
        line = await asyncio.wait_for(reader.readline(), timeout=timeout)
        if not line:  # Server closed connection
            break
        response += line.decode()
        if line == b"\r\n":
            break
    
    # Try to read some body content
    try:
        body_data = await asyncio.wait_for(reader.read(1024), timeout=5.0)
        if body_data:  # Only add if we got data
            response += body_data.decode()
    except asyncio.TimeoutError:
        pass
    
    return response


async def send_request_with_timeout(request: str, host: str = "redproxy", port: int = 8800, timeout: float = 10.0) -> str:
    """Send HTTP request with timeout and return response - from your existing code"""
    reader, writer = await asyncio.open_connection(host, port)
    
    try:
        # Send request
        writer.write(request.encode())
        await writer.drain()
        
        # Read response with timeout
        response = await asyncio.wait_for(read_http_response(reader), timeout=timeout)
        return response
        
    finally:
        writer.close()
        await writer.wait_closed()


def parse_http_status_code(response: str) -> int:
    """Parse HTTP status code from response status line - from your existing code"""
    try:
        # Find the first line (status line)
        lines = response.split('\r\n')
        if not lines:
            return 0
        
        status_line = lines[0]
        
        # Parse status line: "HTTP/1.1 200 OK"
        parts = status_line.split(' ', 2)
        if len(parts) < 2:
            return 0
        
        # Extract status code (second part)
        return int(parts[1])
        
    except (ValueError, IndexError):
        return 0


async def validate_http_request(test_name: str, request: str, 
                               expected_statuses: Optional[List[int]] = None, 
                               timeout: float = 10.0,
                               host: str = "redproxy",
                               port: int = 8800) -> bool:
    """Generic HTTP request test with timeout and status validation - from your existing code"""
    if expected_statuses is None:
        expected_statuses = []  # Accept any response
        
    try:
        response = await send_request_with_timeout(request, host, port, timeout)
        
        # Parse the actual status code from response
        actual_status = parse_http_status_code(response)
        
        # If no expected statuses specified, any valid HTTP response is success
        if not expected_statuses:
            if actual_status > 0:
                print(f"{test_name}: Received HTTP {actual_status} response")
                return True
            else:
                print(f"{test_name}: Invalid response format: {response[:100]}")
                return False
        
        # Check for expected status codes
        if actual_status in expected_statuses:
            print(f"{test_name}: Correctly returned {actual_status}")
            return True
        
        print(f"{test_name}: Expected {expected_statuses}, got {actual_status}: {response[:100]}")
        return False
        
    except asyncio.TimeoutError:
        print(f"{test_name}: Request timed out after {timeout}s")
        return False
    except Exception as e:
        print(f"{test_name}: Failed with exception: {e}")
        return False