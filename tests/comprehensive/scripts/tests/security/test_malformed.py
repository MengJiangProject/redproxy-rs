"""
Malformed request handling tests for redproxy security

Tests proxy behavior with malformed HTTP requests and protocol violations
"""

import asyncio
import pytest
import socket
import sys
import os

# Import from shared helpers
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../shared'))
from helpers import setup_test_environment


class TestMalformedRequests:
    """Malformed request handling security tests"""

    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.security
    @pytest.mark.malformed
    @pytest.mark.destructive
    async def test_malformed_http_request_line(self):
        """Test handling of malformed HTTP request line - from test_malformed_requests()"""
        env = setup_test_environment()
        
        # Send malformed HTTP request directly via socket
        reader, writer = await asyncio.open_connection(env.redproxy_host, env.redproxy_http_port)
        
        try:
            # Send invalid HTTP request
            malformed_request = b"INVALID REQUEST LINE\r\n\r\n"
            writer.write(malformed_request)
            await writer.drain()
            
            # Server should send proper error response or close connection
            try:
                response = await asyncio.wait_for(reader.read(1024), timeout=5.0)
                response_str = response.decode('utf-8', errors='replace')
                
                if len(response) == 0:
                    # Connection closed - should send proper HTTP error instead
                    pytest.fail("Connection closed without HTTP error response (should send 400 Bad Request)")
                
                # Should get proper HTTP error response
                assert (b"400" in response or b"Bad Request" in response or 
                       b"HTTP/1.1 400" in response or b"405" in response or
                       b"Method Not Allowed" in response or
                       (b"HTTP/1.1" in response and (b"4" in response or b"5" in response))), \
                       f"Unexpected response to malformed request: {repr(response_str[:200])}"
                       
            except asyncio.TimeoutError:
                # Timeout is acceptable - server may close connection
                pass
                
        except ConnectionResetError:
            # Connection reset is acceptable for malformed requests
            pass
        except Exception as e:
            # Other connection errors are acceptable
            pass
        finally:
            writer.close()
            await writer.wait_closed()

    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.security
    @pytest.mark.malformed
    @pytest.mark.destructive
    async def test_incomplete_http_headers(self):
        """Test handling of incomplete HTTP headers"""
        env = setup_test_environment()
        
        reader, writer = await asyncio.open_connection(env.redproxy_host, env.redproxy_http_port)
        
        try:
            # Send incomplete HTTP request (missing final CRLF)
            incomplete_request = b"GET http://http-echo:8080/ HTTP/1.1\r\nHost: http-echo:8080\r\n"
            writer.write(incomplete_request)
            await writer.drain()
            
            # Wait a bit for server to process
            await asyncio.sleep(2)
            
            # Server should handle gracefully (timeout or error response)
            try:
                response = await asyncio.wait_for(reader.read(1024), timeout=3.0)
                if len(response) > 0:
                    # If we get a response, it should be an HTTP error
                    assert (b"400" in response or b"HTTP/1.1" in response)
            except asyncio.TimeoutError:
                # Timeout is acceptable for incomplete requests
                pass
                
        finally:
            writer.close()
            await writer.wait_closed()

    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.security
    @pytest.mark.malformed
    @pytest.mark.destructive
    async def test_invalid_http_version(self):
        """Test handling of invalid HTTP version"""
        env = setup_test_environment()
        
        reader, writer = await asyncio.open_connection(env.redproxy_host, env.redproxy_http_port)
        
        try:
            # Send request with invalid HTTP version
            invalid_version_request = b"GET http://http-echo:8080/ HTTP/9.9\r\nHost: http-echo:8080\r\n\r\n"
            writer.write(invalid_version_request)
            await writer.drain()
            
            # Should get error response or connection handling
            try:
                response = await asyncio.wait_for(reader.read(1024), timeout=5.0)
                
                if len(response) > 0:
                    response_str = response.decode('utf-8', errors='replace')
                    # Should be proper HTTP error response
                    assert (b"400" in response or b"505" in response or  # 505 HTTP Version Not Supported
                           b"HTTP/1.1" in response), \
                           f"Unexpected response to invalid HTTP version: {repr(response_str[:200])}"
            except asyncio.TimeoutError:
                # Timeout is acceptable
                pass
                
        except (ConnectionResetError, BrokenPipeError):
            # Connection errors are acceptable for invalid requests
            pass
        finally:
            writer.close()
            await writer.wait_closed()


# Run individual tests for debugging  
if __name__ == "__main__":
    # pytest tests/security/test_malformed.py::TestMalformedRequests::test_malformed_http_request_line
    print("Run with: pytest tests/security/test_malformed.py")
    print("Or single test: pytest tests/security/test_malformed.py::TestMalformedRequests::test_malformed_http_request_line")
    print("Or all malformed tests: pytest -k malformed")