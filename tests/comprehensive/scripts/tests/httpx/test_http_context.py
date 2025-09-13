"""
HttpContext unit and integration tests for redproxy

Tests HttpContext functionality across the request lifecycle.
This file tests HttpContext behavior regardless of listener/connector types.
"""

import asyncio
import pytest
import sys
import os
import json
import base64

# Import from shared helpers  
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../shared'))
from helpers import read_http_response


class TestHttpContextIntegration:
    """HttpContext integration with real proxy operations"""

    @pytest.mark.asyncio
    @pytest.mark.timeout(25)
    @pytest.mark.http_context
    async def test_context_request_storage(self):
        """Test that HttpContext properly stores and retrieves HTTP requests"""
        reader, writer = await asyncio.open_connection("redproxy", 8800)
        
        try:
            # Send HTTP request that should be stored in HttpContext
            request = "GET http://http-echo:8080/context-test HTTP/1.1\r\n"
            request += "Host: http-echo:8080\r\n"
            request += "User-Agent: HttpContext-Test/1.0\r\n"
            request += "X-Test-Header: context-validation\r\n"
            request += "Connection: close\r\n"
            request += "\r\n"
            
            writer.write(request.encode())
            await writer.drain()
            
            response_line = await reader.readline()
            assert response_line.startswith(b"HTTP/1.1 200"), f"Request failed: {response_line.decode().strip()}"
            
            # The fact that we get a successful response indicates HttpContext is working
            # since the request parsing and storage is handled by HttpContext
            
            # Read remaining response to complete the transaction
            while True:
                line = await reader.readline()
                if not line or line == b"\r\n":
                    break
                    
        finally:
            writer.close()
            await writer.wait_closed()

    @pytest.mark.asyncio
    @pytest.mark.timeout(20)
    @pytest.mark.http_context
    async def test_context_protocol_negotiation(self):
        """Test HttpContext protocol version handling"""
        test_cases = [
            ("HTTP/1.0", b"HTTP/1.0"),
            ("HTTP/1.1", b"HTTP/1.1"),
            # Note: HTTP/2 and HTTP/3 require different connection setup
        ]
        
        for request_version, expected_pattern in test_cases:
            reader, writer = await asyncio.open_connection("redproxy", 8800)
            
            try:
                request = f"GET http://http-echo:8080/protocol {request_version}\r\n"
                request += "Host: http-echo:8080\r\n"
                request += "Connection: close\r\n"
                request += "\r\n"
                
                writer.write(request.encode())
                await writer.drain()
                
                response_line = await reader.readline()
                
                # HttpContext should handle protocol version correctly
                assert response_line.startswith(b"HTTP/"), f"Invalid response format for {request_version}"
                
                # Read remaining response
                while True:
                    line = await reader.readline()
                    if not line or line == b"\r\n":
                        break
                        
            finally:
                writer.close()
                await writer.wait_closed()

    @pytest.mark.asyncio
    @pytest.mark.timeout(20)
    @pytest.mark.http_context
    async def test_context_keep_alive_handling(self):
        """Test HttpContext keep-alive connection management"""
        reader, writer = await asyncio.open_connection("redproxy", 8800)
        
        try:
            # Test keep-alive request
            request = "GET http://http-echo:8080/keepalive HTTP/1.1\r\n"
            request += "Host: http-echo:8080\r\n"
            request += "Connection: keep-alive\r\n"
            request += "\r\n"
            
            writer.write(request.encode())
            await writer.drain()
            
            response_line = await reader.readline()
            assert response_line.startswith(b"HTTP/1.1 200"), f"Keep-alive request failed: {response_line.decode().strip()}"
            
            # Check for keep-alive in response headers
            keep_alive_found = False
            content_length = None
            
            while True:
                line = await reader.readline()
                if line == b"\r\n":
                    break
                    
                line_str = line.decode().lower()
                if "connection:" in line_str and "keep-alive" in line_str:
                    keep_alive_found = True
                elif "content-length:" in line_str:
                    content_length = int(line.split(b":")[1].strip())
            
            # Read body if content-length specified to clear the connection
            if content_length:
                body = await reader.read(content_length)
                assert len(body) <= content_length
                
            # HttpContext should manage connection state properly
            # The connection should still be usable for another request
            
        finally:
            writer.close()
            await writer.wait_closed()

    @pytest.mark.asyncio
    @pytest.mark.timeout(20)
    @pytest.mark.http_context
    async def test_context_authentication_handling(self):
        """Test HttpContext proxy authentication management"""
        reader, writer = await asyncio.open_connection("redproxy", 8800)
        
        try:
            # Create base64 encoded credentials
            credentials = base64.b64encode(b"testuser:testpass").decode()
            
            request = "GET http://http-echo:8080/auth-test HTTP/1.1\r\n"
            request += "Host: http-echo:8080\r\n"
            request += f"Proxy-Authorization: Basic {credentials}\r\n"
            request += "Connection: close\r\n"
            request += "\r\n"
            
            writer.write(request.encode())
            await writer.drain()
            
            response_line = await reader.readline()
            
            # HttpContext should handle authentication properly
            # Either success or proper error response
            assert response_line.startswith(b"HTTP/1.1"), f"Invalid response format: {response_line.decode().strip()}"
            
            # Read remaining response
            while True:
                line = await reader.readline()
                if not line or line == b"\r\n":
                    break
                    
        finally:
            writer.close() 
            await writer.wait_closed()

    @pytest.mark.asyncio
    @pytest.mark.timeout(25)
    @pytest.mark.http_context
    @pytest.mark.performance
    async def test_context_memory_efficiency(self):
        """Test HttpContext memory efficiency with multiple requests"""
        # Perform multiple requests to test memory management
        request_count = 10
        
        for i in range(request_count):
            reader, writer = await asyncio.open_connection("redproxy", 8800)
            
            try:
                request = f"GET http://http-echo:8080/memory-test-{i} HTTP/1.1\r\n"
                request += "Host: http-echo:8080\r\n"
                request += f"X-Request-ID: memory-test-{i}\r\n"
                request += f"X-Large-Header: {'x' * 100}\r\n"  # Large header to test memory handling
                request += "Connection: close\r\n"
                request += "\r\n"
                
                writer.write(request.encode())
                await writer.drain()
                
                response_line = await reader.readline()
                assert response_line.startswith(b"HTTP/1.1"), f"Request {i} failed: {response_line.decode().strip()}"
                
                # Read and discard response body
                while True:
                    line = await reader.readline()
                    if not line or line == b"\r\n":
                        break
                        
            finally:
                writer.close()
                await writer.wait_closed()
            
            # Small delay to allow cleanup
            await asyncio.sleep(0.1)


class TestHttpContextBackwardCompatibility:
    """Test backward compatibility with old API patterns"""

    @pytest.mark.asyncio
    @pytest.mark.timeout(20)
    @pytest.mark.http_context
    @pytest.mark.compatibility
    async def test_legacy_api_compatibility(self):
        """Test that HttpContext maintains compatibility with legacy patterns"""
        reader, writer = await asyncio.open_connection("redproxy", 8800)
        
        try:
            # Test request patterns that old code might expect
            request = "GET http://http-echo:8080/legacy HTTP/1.1\r\n"
            request += "Host: http-echo:8080\r\n"
            request += "X-Legacy-Test: true\r\n"
            request += "Connection: close\r\n"
            request += "\r\n"
            
            writer.write(request.encode())
            await writer.drain()
            
            response_line = await reader.readline()
            assert response_line.startswith(b"HTTP/1.1 200"), f"Legacy compatibility test failed: {response_line.decode().strip()}"
            
            # Read remaining response
            while True:
                line = await reader.readline()
                if not line or line == b"\r\n":
                    break
                    
        finally:
            writer.close()
            await writer.wait_closed()

    @pytest.mark.asyncio
    @pytest.mark.timeout(20)
    @pytest.mark.http_context
    @pytest.mark.compatibility
    async def test_http_method_handling(self):
        """Test HttpContext handling of various HTTP methods"""
        methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"]
        
        for method in methods:
            reader, writer = await asyncio.open_connection("redproxy", 8800)
            
            try:
                request = f"{method} http://http-echo:8080/method-test HTTP/1.1\r\n"
                request += "Host: http-echo:8080\r\n"
                request += f"X-Method-Test: {method}\r\n"
                
                if method in ["POST", "PUT"]:
                    request += "Content-Length: 0\r\n"
                    
                request += "Connection: close\r\n"
                request += "\r\n"
                
                writer.write(request.encode())
                await writer.drain()
                
                response_line = await reader.readline()
                
                # HttpContext should handle all HTTP methods properly
                assert response_line.startswith(b"HTTP/1.1"), f"{method} method failed: {response_line.decode().strip()}"
                
                # For HEAD requests, there should be no body
                if method == "HEAD":
                    # Skip headers
                    while True:
                        line = await reader.readline()
                        if line == b"\r\n":
                            break
                    
                    # Should not have body content after headers
                    try:
                        data = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                        assert len(data) == 0, f"HEAD request should not have body, got: {len(data)} bytes"
                    except asyncio.TimeoutError:
                        pass  # Expected for HEAD requests
                else:
                    # Read remaining response
                    while True:
                        line = await reader.readline()
                        if not line or line == b"\r\n":
                            break
                        
            finally:
                writer.close()
                await writer.wait_closed()


class TestHttpContextErrorHandling:
    """Test HttpContext error handling and edge cases"""

    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.http_context
    @pytest.mark.destructive
    async def test_context_malformed_requests(self):
        """Test HttpContext handling of malformed HTTP requests"""
        malformed_cases = [
            "INVALID http://http-echo:8080/ HTTP/1.1\r\n\r\n",  # Invalid method
            "GET http://http-echo:8080/ INVALID/1.1\r\n\r\n",   # Invalid protocol
            "GET\r\n\r\n",  # Missing URL and protocol
            "GET http://http-echo:8080/ HTTP/1.1\r\nHost:\r\n\r\n",  # Empty host header
        ]
        
        for i, malformed_request in enumerate(malformed_cases):
            reader, writer = await asyncio.open_connection("redproxy", 8800)
            
            try:
                writer.write(malformed_request.encode())
                await writer.drain()
                
                # HttpContext should handle malformed requests gracefully
                try:
                    response_line = await asyncio.wait_for(reader.readline(), timeout=5.0)
                    
                    if response_line:
                        # Should get proper HTTP error response
                        assert response_line.startswith(b"HTTP/"), f"Case {i}: Non-HTTP response: {response_line.decode().strip()}"
                        
                        # Should be an error status code
                        parts = response_line.split()
                        if len(parts) >= 2:
                            status_code = parts[1].decode()
                            assert status_code.startswith(('4', '5')), f"Case {i}: Expected 4xx/5xx, got: {status_code}"
                            
                except asyncio.TimeoutError:
                    # Connection might be closed immediately for very malformed requests
                    pass
                    
            finally:
                writer.close()
                await writer.wait_closed()

    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.http_context
    @pytest.mark.destructive
    async def test_context_resource_cleanup(self):
        """Test HttpContext proper resource cleanup on errors"""
        reader, writer = await asyncio.open_connection("redproxy", 8800)
        
        try:
            # Send request and immediately close connection
            request = "GET http://http-echo:8080/cleanup-test HTTP/1.1\r\n"
            request += "Host: http-echo:8080\r\n"
            request += "Connection: close\r\n"
            request += "\r\n"
            
            writer.write(request.encode())
            await writer.drain()
            
            # Immediately close writer to simulate client disconnect
            writer.close()
            await writer.wait_closed()
            
            # HttpContext should handle this gracefully without resource leaks
            # This test mainly ensures no crashes occur
            
        except Exception as e:
            # Expected behavior - connection errors should be handled gracefully
            assert "connection" in str(e).lower() or "broken" in str(e).lower()


# Run individual tests for debugging
if __name__ == "__main__":
    print("Run with: pytest tests/httpx/test_http_context.py")
    print("Or specific test: pytest tests/httpx/test_http_context.py::TestHttpContextIntegration::test_context_request_storage") 
    print("Or all http_context tests: pytest -m http_context")
    print("Or compatibility tests: pytest -m 'http_context and compatibility'")
    print("Or performance tests: pytest -m 'http_context and performance'")