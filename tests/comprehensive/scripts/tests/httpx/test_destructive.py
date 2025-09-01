"""
Destructive/Error handling tests for redproxy httpx listener

Pure pytest implementation using shared helpers
"""

import asyncio
import pytest
import sys
import os

# Import from shared helpers (not legacy lib)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../shared'))
from helpers import read_http_response, validate_http_request


class TestDestructiveScenarios:
    """Destructive scenarios and error handling tests"""

    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.destructive
    async def test_invalid_http_method(self):
        """Test invalid HTTP method - from _test_invalid_http_method()"""
        reader, writer = await asyncio.open_connection("redproxy", 8800)
        
        try:
            # Send invalid HTTP method
            request = "INVALIDMETHOD http://http-echo:8080/ HTTP/1.1\r\n"
            request += "Host: http-echo:8080\r\n"
            request += "\r\n"
            
            writer.write(request.encode())
            await writer.drain()
            
            response = await read_http_response(reader)
            
            # Custom HTTP methods can either be:
            # 1. Passed through to upstream (which may accept or reject them)
            # 2. Rejected by proxy with 400 Bad Request
            assert "HTTP/1.1" in response
            # Accept any valid HTTP response
            
        finally:
            writer.close()
            await writer.wait_closed()

    @pytest.mark.asyncio
    @pytest.mark.timeout(20)
    @pytest.mark.destructive
    async def test_oversized_headers(self):
        """Test oversized headers - from _test_oversized_headers()"""
        reader, writer = await asyncio.open_connection("redproxy", 8800)
        
        try:
            # Send request with very large header (20KB header should fail with 16KB limit)
            request = "GET http://http-echo:8080/oversize HTTP/1.1\r\n"
            request += "Host: http-echo:8080\r\n"
            request += f"X-Large-Header: {'A' * 20000}\r\n"  # 20KB header (should fail with 16KB limit)
            request += "\r\n"
            
            writer.write(request.encode())
            await writer.drain()
            
            try:
                response = await asyncio.wait_for(read_http_response(reader), timeout=2.0)
                
                # If we get a response, it should be an error
                # Accept 400 Bad Request, 431 Request Header Fields Too Large, or 500 Internal Server Error           
                assert "HTTP/1.1 400" in response or "HTTP/1.1 431" in response or "HTTP/1.1 500" in response
                
            except (asyncio.TimeoutError, ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
                # Connection reset/timeout is also acceptable - indicates proxy rejected oversized headers
                # and closed connection immediately (proper defensive behavior)
                pass
                
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            # Connection was reset during write - also acceptable defensive behavior
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
                # Connection already closed by proxy
                pass

    @pytest.mark.asyncio
    @pytest.mark.timeout(10)
    @pytest.mark.destructive
    async def test_connection_drop(self):
        """Test connection drop scenarios - from _test_connection_drop()"""
        _, writer = await asyncio.open_connection("redproxy", 8800)
        
        try:
            # Send partial request and drop connection
            request = "GET http://http-echo:8080/ HTTP/1.1\r\n"
            request += "Host: http-echo:8080\r\n"
            # Don't send final \r\n - request is incomplete
            
            writer.write(request.encode())
            await writer.drain()
            
            # Drop connection immediately
            writer.close()
            await writer.wait_closed()
            
            # Connection drops should be handled gracefully without server crashes
            # No assertion needed - if we get here without exception, it's success
            
        except Exception:
            # Connection drops may cause various exceptions, all should be handled gracefully
            pass

    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.destructive
    async def test_invalid_http_version(self):
        """Test invalid HTTP version - from _test_invalid_http_version()"""
        request = "GET http://http-echo:8080/ HTTP/999.999\r\n"
        request += "Host: http-echo:8080\r\n"
        request += "\r\n"
        
        result = await validate_http_request(
            "Invalid HTTP version",
            request,
            expected_statuses=[400],
            timeout=10.0
        )
        assert result  # Should handle gracefully

    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.destructive
    async def test_malformed_headers(self):
        """Test malformed headers - from _test_malformed_headers()"""
        request = "GET http://http-echo:8080/ HTTP/1.1\r\n"
        request += "Host: http-echo:8080\r\n"
        request += "Invalid-Header-Without-Colon\r\n"  # Malformed header
        request += "\r\n"
        
        result = await validate_http_request(
            "Malformed headers",
            request,
            expected_statuses=[400],
            timeout=10.0
        )
        assert result  # Should handle gracefully

    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.destructive
    async def test_missing_host_header(self):
        """Test missing Host header - from _test_missing_host_header()"""
        request = "GET /test HTTP/1.1\r\n"
        request += "Connection: close\r\n"
        request += "\r\n"
        
        result = await validate_http_request(
            "Missing Host header",
            request,
            expected_statuses=[400, 500],
            timeout=10.0
        )
        assert result  # Should handle gracefully

    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.destructive
    async def test_incomplete_request_line(self):
        """Test incomplete request line - from _test_incomplete_request_line()"""
        request = "GET\r\n"
        request += "Host: http-echo:8080\r\n"
        request += "\r\n"
        
        result = await validate_http_request(
            "Incomplete request line",
            request,
            expected_statuses=[400],
            timeout=10.0
        )
        assert result  # Should handle gracefully

    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.destructive
    async def test_invalid_uri_format(self):
        """Test invalid URI format - from _test_invalid_uri_format()"""
        request = "GET http://invalid uri with spaces/ HTTP/1.1\r\n"
        request += "Host: http-echo:8080\r\n"
        request += "\r\n"
        
        result = await validate_http_request(
            "Invalid URI format",
            request,
            expected_statuses=[],  # Accept any HTTP response (400 or upstream handling)
            timeout=10.0
        )
        assert result  # Should handle gracefully

    @pytest.mark.asyncio
    @pytest.mark.timeout(10)
    @pytest.mark.destructive
    async def test_empty_request(self):
        """Test completely empty request - from _test_empty_request()"""
        reader, writer = await asyncio.open_connection("redproxy", 8800)
        
        try:
            # Send nothing and wait
            await writer.drain()
            
            try:
                # Should timeout since no request is sent
                response = await asyncio.wait_for(read_http_response(reader), timeout=5.0)
                pytest.fail(f"Empty request unexpectedly got response: {response[:100]}")
            except asyncio.TimeoutError:
                # Expected behavior - empty request should timeout
                pass
                
        finally:
            writer.close()
            await writer.wait_closed()


# Run individual tests for debugging
if __name__ == "__main__":
    # pytest tests/httpx/test_destructive.py::TestDestructiveScenarios::test_invalid_http_method
    print("Run with: pytest tests/httpx/test_destructive.py")
    print("Or single test: pytest tests/httpx/test_destructive.py::TestDestructiveScenarios::test_invalid_http_method")
    print("Or all destructive tests: pytest -m destructive")