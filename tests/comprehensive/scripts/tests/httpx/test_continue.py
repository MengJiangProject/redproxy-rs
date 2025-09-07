"""
HTTP 100 Continue tests for redproxy httpx listener

Pure pytest implementation using websocket server endpoints
"""

import asyncio
import pytest
import httpx
import sys
import os

# Import from shared helpers (not legacy lib)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../shared'))
from helpers import read_http_response


class TestHTTP100Continue:
    """HTTP 100 Continue response handling tests"""

    @pytest.mark.asyncio
    @pytest.mark.timeout(20)
    @pytest.mark.http
    async def test_100_continue_with_websocket_server(self):
        """Test 100 Continue with websocket server - from _test_100_continue_with_test_server()"""
        # Connect to websocket server through proxy for 100-continue test
        reader, writer = await asyncio.open_connection("redproxy", 8800)
        
        try:
            # Send POST with Expect: 100-continue to websocket server
            test_payload = "Hello World from 100-continue test"
            request = f"POST http://websocket-server:9998/100-continue HTTP/1.1\r\n"
            request += "Host: websocket-server:9998\r\n"
            request += f"Content-Length: {len(test_payload)}\r\n"
            request += "Expect: 100-continue\r\n"
            request += "Content-Type: text/plain\r\n"
            request += "\r\n"
            
            writer.write(request.encode())
            await writer.drain()
            
            # Read response - might be 100 Continue first or direct response
            response_line = await reader.readline()
            
            if b"100" in response_line and b"Continue" in response_line:
                # Got 100 Continue, skip remaining headers and send body
                while True:
                    line = await reader.readline()
                    if line == b"\r\n":
                        break
                
                # Send the actual payload
                writer.write(test_payload.encode())
                await writer.drain()
                
                # Read the final response
                final_response = await read_http_response(reader)
                
                # Validate we got a proper response with our payload information
                assert "200" in final_response
                assert str(len(test_payload.encode())) in final_response
                
            else:
                # Direct response without 100 Continue (aiohttp behavior)
                # Read the rest of the response
                remaining = await read_http_response(reader)
                full_response = response_line.decode() + remaining
                
                # Should still be a valid 200 response
                assert "HTTP/1.1 200" in full_response
            
        finally:
            writer.close()
            await writer.wait_closed()

    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.http
    async def test_post_with_expect_header(self):
        """Test POST with Expect header through proxy - from _test_post_with_expect_header()"""
        test_data = "Expect 100-continue payload test data"
        headers = {
            "Expect": "100-continue",
            "Content-Type": "text/plain"
        }
        
        async with httpx.AsyncClient(proxy="http://redproxy:8800", timeout=10.0) as client:
            response = await client.post(
                "http://websocket-server:9998/100-continue",
                content=test_data,
                headers=headers
            )
            
            if response.status_code == 200:
                # Verify the payload was transmitted correctly
                assert str(len(test_data.encode())) in response.text
            elif response.status_code == 417:
                # 417 Expectation Failed is a valid response to 100-continue
                pass
            elif response.status_code in [400, 501]:
                # 400 Bad Request or 501 Not Implemented are also acceptable
                pass
            else:
                pytest.fail(f"Unexpected status for POST with Expect: {response.status_code}")


# Run individual tests for debugging  
if __name__ == "__main__":
    # pytest tests/httpx/test_continue.py::TestHTTP100Continue::test_100_continue_with_websocket_server
    print("Run with: pytest tests/httpx/test_continue.py")
    print("Or single test: pytest tests/httpx/test_continue.py::TestHTTP100Continue::test_100_continue_with_websocket_server")
    print("Or all continue tests: pytest -k continue")