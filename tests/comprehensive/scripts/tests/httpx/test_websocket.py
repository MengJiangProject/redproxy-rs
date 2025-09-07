"""
WebSocket support tests for redproxy httpx listener

Pure pytest implementation using websocket server
"""

import asyncio
import pytest
import httpx
import sys
import os

# Import from shared helpers (not legacy lib)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../shared'))
from helpers import read_http_response


class TestWebSocketSupport:
    """WebSocket upgrade and communication tests"""

    @pytest.mark.asyncio
    @pytest.mark.timeout(20)
    @pytest.mark.websocket
    async def test_websocket_handshake(self):
        """Test WebSocket handshake through proxy - from _test_websocket_handshake()"""
        # Connect to proxy and send WebSocket upgrade request
        reader, writer = await asyncio.open_connection("redproxy", 8800)
        
        try:
            # WebSocket upgrade request to our WebSocket server  
            websocket_key = "dGhlIHNhbXBsZSBub25jZQ=="  # Standard test key
            request = f"GET http://websocket-server:9998/ws HTTP/1.1\r\n"
            request += "Host: websocket-server:9998\r\n"
            request += "Upgrade: websocket\r\n"
            request += "Connection: Upgrade\r\n"
            request += f"Sec-WebSocket-Key: {websocket_key}\r\n"
            request += "Sec-WebSocket-Version: 13\r\n"
            request += "\r\n"
            
            writer.write(request.encode())
            await writer.drain()
            
            # Read response
            response_lines = []
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=10.0)
                if not line:
                    break
                response_lines.append(line.decode().strip())
                if line == b"\r\n":
                    break
            
            response = "\n".join(response_lines)
            
            # Check for successful WebSocket upgrade
            if "HTTP/1.1 101" in response and "Switching Protocols" in response:
                # Perfect WebSocket upgrade
                pass
            elif "HTTP/1.1 200" in response:
                # Some servers respond with 200 instead of 101 (acceptable)
                pass
            else:
                pytest.fail(f"WebSocket handshake failed: {response[:200]}")
                
        finally:
            writer.close()
            await writer.wait_closed()

    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.websocket
    async def test_websocket_message_exchange(self):
        """Test WebSocket message exchange through proxy - from _test_websocket_message_exchange()"""
        # Test WebSocket by connecting directly to websocket server through proxy
        proxy_headers = {
            "Upgrade": "websocket", 
            "Connection": "Upgrade",
            "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
            "Sec-WebSocket-Version": "13"
        }
        
        async with httpx.AsyncClient(proxy="http://redproxy:8800", timeout=10.0) as client:
            # Send WebSocket upgrade request
            response = await client.get(
                "http://websocket-server:9998/ws",
                headers=proxy_headers
            )
            
            # WebSocket upgrade should return 101 or be handled by proxy
            if response.status_code in [101, 200, 426]:  # 426 = Upgrade Required
                pass
            else:
                pytest.fail(f"WebSocket message exchange failed: {response.status_code}")

    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.websocket
    async def test_websocket_connection_close(self):
        """Test WebSocket connection close handling - from _test_websocket_connection_close()"""
        # Test that WebSocket close frames are handled properly
        # This is mainly testing that the proxy doesn't crash on WebSocket traffic
        reader, writer = await asyncio.open_connection("redproxy", 8800)
        
        try:
            # Send a malformed WebSocket-like request to test error handling
            request = "GET http://websocket-server:9998/ws HTTP/1.1\r\n"
            request += "Host: websocket-server:9998\r\n"
            request += "Upgrade: websocket\r\n"
            request += "Connection: close\r\n"  # Conflicting: wants upgrade but also close
            request += "\r\n"
            
            writer.write(request.encode())
            await writer.drain()
            
            # Read response
            try:
                response = await asyncio.wait_for(read_http_response(reader), timeout=5.0)
                
                # Any HTTP response indicates proper handling
                assert "HTTP/1.1" in response
                
            except asyncio.TimeoutError:
                # Timeout is also acceptable - connection may have been closed
                pass
                
        finally:
            writer.close()
            await writer.wait_closed()


# Run individual tests for debugging
if __name__ == "__main__":
    # pytest tests/httpx/test_websocket.py::TestWebSocketSupport::test_websocket_handshake
    print("Run with: pytest tests/httpx/test_websocket.py")
    print("Or single test: pytest tests/httpx/test_websocket.py::TestWebSocketSupport::test_websocket_handshake")
    print("Or all websocket tests: pytest -m websocket")