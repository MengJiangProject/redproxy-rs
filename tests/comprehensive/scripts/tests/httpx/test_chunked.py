"""
Chunked Transfer Encoding tests for redproxy httpx listener

Pure pytest implementation using shared helpers
"""

import asyncio
import pytest
import sys
import os

# Import from shared helpers (not legacy lib)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../shared'))
from helpers import read_http_response


class TestChunkedEncoding:
    """Chunked Transfer Encoding tests"""

    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.http  
    async def test_receive_chunked_from_test_server(self):
        """Test receiving chunked response from test server - from _test_receive_chunked_from_test_server()"""
        reader, writer = await asyncio.open_connection("redproxy", 8800)
        
        try:
            # Request chunked response from websocket-server:9998
            request = "GET http://websocket-server:9998/chunked HTTP/1.1\r\n"
            request += "Host: websocket-server:9998\r\n"
            request += "Connection: close\r\n"
            request += "\r\n"
            
            writer.write(request.encode())
            await writer.drain()
            
            # Read chunked response
            response_data = b""
            try:
                while True:
                    data = await asyncio.wait_for(reader.read(1024), timeout=5.0)
                    if not data:
                        break
                    response_data += data
            except asyncio.TimeoutError:
                pass
            
            response = response_data.decode()
            print(f"Chunked response: {response[:200]}...")  # Debug output
            # Check for chunked encoding header and verify the chunks contain expected data
            assert "Transfer-Encoding: chunked" in response
            # Verify chunked data contains the expected content (chunked format preserved by proxy)
            assert "6\r\nHello " in response and "8\r\nchunked " in response and "6\r\nworld!" in response
        finally:
            writer.close()
            await writer.wait_closed()

    @pytest.mark.asyncio
    @pytest.mark.timeout(20)
    @pytest.mark.http
    async def test_send_chunked_request(self):
        """Test sending chunked request - from _test_send_chunked_request()"""
        reader, writer = await asyncio.open_connection("redproxy", 8800)
        
        try:
            # Send chunked request to echo server
            request = "POST http://http-echo:8080/chunked HTTP/1.1\r\n"
            request += "Host: http-echo:8080\r\n"
            request += "Transfer-Encoding: chunked\r\n"
            request += "\r\n"
            
            writer.write(request.encode())
            
            # Send chunks
            chunk1 = "Hello "
            writer.write(f"{len(chunk1):x}\r\n{chunk1}\r\n".encode())
            
            chunk2 = "World!"
            writer.write(f"{len(chunk2):x}\r\n{chunk2}\r\n".encode())
            
            # Terminating chunk
            writer.write(b"0\r\n\r\n")
            await writer.drain()
            
            # Read response
            response = await read_http_response(reader)
            
            # Should get some HTTP 200 response
            assert response.startswith("HTTP/1.1 200")
            
        finally:
            writer.close()
            await writer.wait_closed()

    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.http
    @pytest.mark.destructive
    async def test_malformed_chunked_request(self):
        """Test malformed chunked request handling - from _test_malformed_chunked_request()"""
        reader, writer = await asyncio.open_connection("redproxy", 8800)
        
        try:
            # Send malformed chunked request to websocket-server
            request = "POST http://websocket-server:9998/malformed_chunked HTTP/1.1\r\n"
            request += "Host: websocket-server:9998\r\n"
            request += "Transfer-Encoding: chunked\r\n"
            request += "\r\n"
            
            writer.write(request.encode())
            
            # Send invalid chunk (bad size)
            writer.write(b"INVALID_HEX\r\ndata\r\n")
            writer.write(b"0\r\n\r\n")
            await writer.drain()
            
            # Should get some response or handle gracefully
            response = await read_http_response(reader)
            print(f"Malformed chunked response: {response[:200]}...")  # Debug output
            # For malformed chunked requests, connection may be dropped (empty response is acceptable)
            # or we get an HTTP error response - both indicate graceful handling
            assert response == "" or "HTTP/1.1" in response
            
        finally:
            writer.close()
            await writer.wait_closed()


# Run individual tests for debugging
if __name__ == "__main__":
    # pytest tests/httpx/test_chunked.py::TestChunkedEncoding::test_send_chunked_request
    print("Run with: pytest tests/httpx/test_chunked.py")
    print("Or single test: pytest tests/httpx/test_chunked.py::TestChunkedEncoding::test_send_chunked_request")
    print("Or all chunked tests: pytest -k chunked")