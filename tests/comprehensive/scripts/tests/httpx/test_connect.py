"""
HTTP CONNECT tunneling tests for redproxy httpx listener

Pure pytest implementation using shared helpers
"""

import asyncio
import pytest
import sys
import os

# Import from shared helpers (not legacy lib)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../shared'))
from helpers import read_http_response


class TestHTTPConnect:
    """HTTP CONNECT tunneling tests"""

    @pytest.mark.asyncio
    @pytest.mark.timeout(30)
    @pytest.mark.connect
    async def test_basic_connect_tunnel(self):
        """Test basic HTTP CONNECT tunnel to echo server - from _test_basic_connect()"""
        reader, writer = await asyncio.open_connection("redproxy", 8800)
        
        try:
            # Send CONNECT request
            connect_request = "CONNECT http-echo:8080 HTTP/1.1\r\n"
            connect_request += "Host: http-echo:8080\r\n"
            connect_request += "\r\n"
            
            writer.write(connect_request.encode())
            await writer.drain()
            
            # Read CONNECT response
            response_line = await reader.readline()
            assert response_line.startswith(b"HTTP/1.1 200"), f"CONNECT failed: {response_line.decode().strip()}"
            
            # Skip headers
            while True:
                line = await reader.readline()
                if line == b"\r\n":
                    break
            
            # Send HTTP request through tunnel
            http_request = "GET / HTTP/1.1\r\n"
            http_request += "Host: http-echo:8080\r\n"
            http_request += "Connection: close\r\n"
            http_request += "\r\n"
            
            writer.write(http_request.encode())
            await writer.drain()
            
            # Read response
            response_data = b""
            try:
                while True:
                    data = await asyncio.wait_for(reader.read(1024), timeout=5.0)
                    if not data:
                        break
                    response_data += data
            except asyncio.TimeoutError:
                pass
            
            response_str = response_data.decode()
            assert "HTTP/1.1 200" in response_str
            assert "path" in response_str
            
        finally:
            writer.close()
            await writer.wait_closed()

    @pytest.mark.asyncio
    @pytest.mark.timeout(20)
    @pytest.mark.connect
    async def test_connect_to_test_server(self):
        """Test CONNECT to test server - from _test_connect_to_test_server()"""
        reader, writer = await asyncio.open_connection("redproxy", 8800)
        
        try:
            connect_request = "CONNECT test-runner:9999 HTTP/1.1\r\n"
            connect_request += "Host: test-runner:9999\r\n"
            connect_request += "\r\n"
            
            writer.write(connect_request.encode())
            await writer.drain()
            
            response_line = await reader.readline()
            
            # Should succeed or fail gracefully
            assert response_line.startswith(b"HTTP/1.1 200") or any(code in response_line for code in [b"502", b"503"])
            
        finally:
            writer.close()
            await writer.wait_closed()

    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.connect 
    async def test_connect_invalid_target(self):
        """Test CONNECT with invalid target - from _test_connect_invalid_target()"""
        reader, writer = await asyncio.open_connection("redproxy", 8800)
        
        try:
            connect_request = "CONNECT nonexistent-host.invalid:80 HTTP/1.1\r\n"
            connect_request += "Host: nonexistent-host.invalid:80\r\n"
            connect_request += "\r\n"
            
            writer.write(connect_request.encode())
            await writer.drain()
            
            response_line = await reader.readline()
            
            # Should get error response
            assert any(code in response_line for code in [b"502", b"503", b"500", b"400"]), \
                f"Expected error for invalid CONNECT: {response_line.decode().strip()}"
                
        finally:
            writer.close()
            await writer.wait_closed()

    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.connect
    @pytest.mark.destructive
    async def test_connect_malformed_request(self):
        """Test CONNECT with malformed request - from _test_connect_malformed_request()"""
        reader, writer = await asyncio.open_connection("redproxy", 8800)
        
        try:
            # Send malformed CONNECT request
            malformed_request = "CONNECT\r\n"  # Missing target and HTTP version
            malformed_request += "\r\n"
            
            writer.write(malformed_request.encode())
            await writer.drain()
            
            response_line = await reader.readline()
            
            # Should get error response
            assert any(code in response_line for code in [b"400", b"502", b"503"]), \
                f"Malformed CONNECT should return error: {response_line.decode().strip()}"
                
        finally:
            writer.close()
            await writer.wait_closed()


# Run individual tests for debugging
if __name__ == "__main__":
    # pytest tests/httpx/test_connect.py::TestHTTPConnect::test_basic_connect_tunnel
    print("Run with: pytest tests/httpx/test_connect.py")
    print("Or single test: pytest tests/httpx/test_connect.py::TestHTTPConnect::test_basic_connect_tunnel")
    print("Or all connect tests: pytest -m connect")