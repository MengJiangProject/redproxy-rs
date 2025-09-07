"""
HTTP Keep-Alive connection tests for redproxy httpx listener

Pure pytest implementation using shared helpers
"""

import asyncio
import pytest
import httpx
import sys
import os

# Import from shared helpers (not legacy lib)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../shared'))
from helpers import read_http_response


class TestHTTPKeepAlive:
    """HTTP/1.1 Keep-Alive connection tests"""

    @pytest.mark.asyncio
    @pytest.mark.timeout(30)
    @pytest.mark.http
    async def test_multiple_requests_same_connection(self):
        """Test multiple requests on same connection - from _test_multiple_requests_same_connection()"""
        reader, writer = await asyncio.open_connection("redproxy", 8800)
        
        try:
            # First request
            request1 = "GET http://http-echo:8080/_test_multiple_requests_same_connection/1 HTTP/1.1\r\n"
            request1 += "Host: http-echo:8080\r\n"
            request1 += "Connection: keep-alive\r\n"
            request1 += "\r\n"
            
            writer.write(request1.encode())
            await writer.drain()
            
            # Read first response
            response1 = await read_http_response(reader)
            assert "HTTP/1.1 200" in response1
            
            # Second request on same connection
            request2 = "GET http://http-echo:8080/_test_multiple_requests_same_connection/2 HTTP/1.1\r\n"
            request2 += "Host: http-echo:8080\r\n"
            request2 += "Connection: close\r\n"
            request2 += "\r\n"
            
            writer.write(request2.encode())
            await writer.drain()
            
            # Read second response
            response2 = await read_http_response(reader)
            assert "HTTP/1.1 200" in response2
            
        finally:
            writer.close()
            await writer.wait_closed()

    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.http
    async def test_explicit_keep_alive(self):
        """Test explicit Connection: keep-alive header - from _test_explicit_keep_alive()"""
        async with httpx.AsyncClient(proxy="http://redproxy:8800", timeout=10.0) as client:
            headers = {"Connection": "keep-alive"}
            response = await client.get("http://http-echo:8080/", headers=headers)
            
            assert response.status_code == 200

    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.http
    async def test_explicit_connection_close(self):
        """Test explicit Connection: close header - from _test_explicit_connection_close()"""
        async with httpx.AsyncClient(proxy="http://redproxy:8800", timeout=10.0) as client:
            headers = {"Connection": "close"}
            response = await client.get("http://http-echo:8080/", headers=headers)
            
            assert response.status_code == 200


# Run individual tests for debugging
if __name__ == "__main__":
    # pytest tests/httpx/test_keepalive.py::TestHTTPKeepAlive::test_multiple_requests_same_connection
    print("Run with: pytest tests/httpx/test_keepalive.py")
    print("Or single test: pytest tests/httpx/test_keepalive.py::TestHTTPKeepAlive::test_multiple_requests_same_connection")
    print("Or all keepalive tests: pytest -k keepalive")