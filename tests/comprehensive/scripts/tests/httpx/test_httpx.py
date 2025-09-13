"""
HttpX Component Isolation Test Suite for redproxy

Reorganizes httpx tests into 3 scenarios for proper component isolation:
- Port 8800: HttpX Listener + Direct Connector - validates listener works with non-HttpX backend
- Port 8801: HttpX Listener + HttpX Connector - validates full HttpX pipeline special cases  
- Port 8802: Reverse Listener + HttpX Connector - validates connector works with non-HttpX frontend

Common test patterns are reused across scenarios. Component-specific functionality is tested separately.
"""

import asyncio
import pytest
import sys
import os
import httpx
import base64

# Import from shared helpers
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../shared'))
from helpers import read_http_response


def build_http_request(method: str = "GET", path: str = "/test", headers: dict = None, body: bytes = None, use_absolute_uri: bool = True):
    """Build HTTP request with proper URI format - eliminates port-based conditionals"""
    headers = headers or {}
    
    if use_absolute_uri:
        # Forward proxy: absolute URI required
        request = f"{method} http://http-echo:8080{path} HTTP/1.1\r\n"
        request += "Host: http-echo:8080\r\n"
    else:
        # Reverse proxy: relative URI with Host header
        request = f"{method} {path} HTTP/1.1\r\n"
        request += "Host: http-echo\r\n"
    
    # Add Content-Length if body is provided
    if body is not None:
        headers["Content-Length"] = str(len(body))
    
    # Add additional headers
    for name, value in headers.items():
        request += f"{name}: {value}\r\n"
    
    request += "Connection: close\r\n"
    request += "\r\n"
    
    # Add body if provided
    if body is not None:
        request = request.encode() + body
        return request
    else:
        return request


class HttpXTestPatterns:
    """Reusable test patterns that work across all tiers"""
    
    @staticmethod
    async def test_basic_get_request(port: int, path: str = "/test", use_absolute_uri: bool = True):
        """Basic GET request pattern - reusable across all tiers"""
        reader, writer = await asyncio.open_connection("redproxy", port)
        try:
            # Use helper function - eliminates port-based conditionals
            request = build_http_request("GET", path, use_absolute_uri=use_absolute_uri)
            
            writer.write(request.encode())
            await writer.drain()
            
            response_line = await reader.readline()
            assert response_line.startswith(b"HTTP/1.1 200"), f"GET request failed: {response_line.decode().strip()}"
            
        finally:
            writer.close()
            await writer.wait_closed()
    
    @staticmethod
    async def test_post_request_with_body(port: int, use_absolute_uri: bool = True):
        """POST request with body pattern - reusable across all tiers"""
        reader, writer = await asyncio.open_connection("redproxy", port)
        try:
            body = b'{"test": "data"}'
            
            # Use helper function - eliminates port-based conditionals
            request = build_http_request("POST", "/post-test", 
                                       {"Content-Type": "application/json"}, 
                                       body, use_absolute_uri=use_absolute_uri)
            
            if isinstance(request, bytes):
                writer.write(request)
            else:
                writer.write(request.encode())
            await writer.drain()
            
            response_line = await reader.readline()
            assert response_line.startswith(b"HTTP/1.1 200"), f"POST request failed: {response_line.decode().strip()}"
            
        finally:
            writer.close()
            await writer.wait_closed()
    
    @staticmethod
    async def test_chunked_encoding(port: int, use_absolute_uri: bool = True):
        """Chunked encoding pattern - reusable across all tiers"""
        reader, writer = await asyncio.open_connection("redproxy", port)
        try:
            # Use helper function - eliminates port-based conditionals  
            request_headers = build_http_request("POST", "/chunked-test", 
                                                {"Transfer-Encoding": "chunked"}, 
                                                use_absolute_uri=use_absolute_uri)
            
            # Send chunked data
            chunk1 = b"Hello "
            chunk2 = b"World!"
            
            writer.write(request_headers.encode() if isinstance(request_headers, str) else request_headers)
            writer.write(f"{len(chunk1):x}\r\n".encode())
            writer.write(chunk1 + b"\r\n")
            writer.write(f"{len(chunk2):x}\r\n".encode())
            writer.write(chunk2 + b"\r\n")
            writer.write(b"0\r\n\r\n")  # End chunks
            await writer.drain()
            
            response_line = await reader.readline()
            assert response_line.startswith(b"HTTP/1.1 200"), f"Chunked request failed: {response_line.decode().strip()}"
            
        finally:
            writer.close()
            await writer.wait_closed()
    
    @staticmethod
    async def test_malformed_request_handling(port: int, use_absolute_uri: bool = True):
        """Malformed request handling pattern - reusable across all tiers"""
        malformed_cases = [
            "INVALID-METHOD /test HTTP/1.1\r\n\r\n",
            "GET /test INVALID-VERSION\r\n\r\n",
            "GET\r\n\r\n",  # Missing URL and version
        ]
        
        for i, malformed_request in enumerate(malformed_cases):
            reader, writer = await asyncio.open_connection("redproxy", port)
            try:
                writer.write(malformed_request.encode())
                await writer.drain()
                
                try:
                    response_line = await asyncio.wait_for(reader.readline(), timeout=5.0)
                    if response_line:
                        assert response_line.startswith(b"HTTP/"), f"Case {i}: Non-HTTP response: {response_line.decode().strip()}"
                        status_code = response_line.split()[1].decode() if len(response_line.split()) > 1 else "000"
                        assert status_code.startswith(('4', '5')), f"Case {i}: Expected 4xx/5xx, got: {status_code}"
                except asyncio.TimeoutError:
                    # Connection might be closed immediately for severely malformed requests
                    pass
                    
            finally:
                writer.close()
                await writer.wait_closed()
    
    @staticmethod
    async def test_proxy_authentication_required(port: int, use_absolute_uri: bool = True):
        """Test proxy authentication required (407) response pattern"""
        reader, writer = await asyncio.open_connection("redproxy", port)
        try:
            # Use explicit parameter instead of port-based conditional
            request = build_http_request(
                method="GET", 
                path="/test",
                headers={"Connection": "close"},
                use_absolute_uri=use_absolute_uri
            )
            
            writer.write(request.encode())
            await writer.drain()
            
            response_line = await reader.readline()
            # Should get 407 Proxy Authentication Required (if auth is enabled)
            # or 200 OK (if auth is disabled) 
            status_line = response_line.decode().strip()
            assert response_line.startswith(b"HTTP/1.1"), f"Invalid response format: {status_line}"
            
            # Parse status code
            status_code = response_line.split()[1].decode() if len(response_line.split()) > 1 else "000"
            assert status_code in ["200", "407"], f"Expected 200 or 407, got: {status_code}"
            
        finally:
            writer.close()
            await writer.wait_closed()
    
    @staticmethod
    async def test_proxy_authentication_success(port: int, username: str = "testuser", password: str = "testpass", use_absolute_uri: bool = True):
        """Test successful proxy authentication pattern"""
        reader, writer = await asyncio.open_connection("redproxy", port)
        try:
            # Create Basic authentication header
            credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
            
            # Use helper function - eliminates port-based conditionals
            request = build_http_request("GET", "/test", {
                "Proxy-Authorization": f"Basic {credentials}"
            }, use_absolute_uri=use_absolute_uri)
            
            writer.write(request.encode())
            await writer.drain()
            
            response_line = await reader.readline()
            status_line = response_line.decode().strip()
            assert response_line.startswith(b"HTTP/1.1"), f"Invalid response format: {status_line}"
            
            # Should succeed if credentials are correct or auth is disabled
            status_code = response_line.split()[1].decode() if len(response_line.split()) > 1 else "000"
            assert status_code in ["200", "407"], f"Expected 200 or 407, got: {status_code}"
            
        finally:
            writer.close()
            await writer.wait_closed()
    
    @staticmethod
    async def test_proxy_authentication_failure(port: int, use_absolute_uri: bool = True):
        """Test proxy authentication failure with invalid credentials pattern"""
        reader, writer = await asyncio.open_connection("redproxy", port)
        try:
            # Create Basic authentication header with invalid credentials
            credentials = base64.b64encode("invalid:credentials".encode()).decode()
            
            # Use explicit parameter instead of port-based conditional
            request = build_http_request(
                method="GET", 
                path="/test",
                headers={
                    f"Proxy-Authorization": f"Basic {credentials}",
                    "Connection": "close"
                },
                use_absolute_uri=use_absolute_uri
            )
            
            writer.write(request.encode())
            await writer.drain()
            
            response_line = await reader.readline()
            status_line = response_line.decode().strip()
            assert response_line.startswith(b"HTTP/1.1"), f"Invalid response format: {status_line}"
            
            # Should get 407 if auth is enabled, or 200 if auth is disabled
            status_code = response_line.split()[1].decode() if len(response_line.split()) > 1 else "000"
            assert status_code in ["200", "407"], f"Expected 200 or 407, got: {status_code}"
            
        finally:
            writer.close()
            await writer.wait_closed()
    
    @staticmethod
    async def test_connect_with_authentication(port: int, username: str = "testuser", password: str = "testpass", use_absolute_uri: bool = True):
        """Test CONNECT method with proxy authentication pattern"""
        reader, writer = await asyncio.open_connection("redproxy", port)
        try:
            # Create Basic authentication header
            credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
            
            # CONNECT requests work the same way for forward proxies
            # Reverse proxies don't typically handle CONNECT
            # CONNECT method not applicable for reverse proxies
            if not use_absolute_uri:
                pytest.skip("CONNECT not applicable for reverse proxy tests")
            
            request = "CONNECT http-echo:8080 HTTP/1.1\r\n"
            request += "Host: http-echo:8080\r\n"
            request += f"Proxy-Authorization: Basic {credentials}\r\n"
            request += "\r\n"
            
            writer.write(request.encode())
            await writer.drain()
            
            response_line = await reader.readline()
            status_line = response_line.decode().strip()
            assert response_line.startswith(b"HTTP/1.1"), f"Invalid response format: {status_line}"
            
            # Should succeed if credentials are correct or auth is disabled
            status_code = response_line.split()[1].decode() if len(response_line.split()) > 1 else "000"
            assert status_code in ["200", "407"], f"Expected 200 or 407, got: {status_code}"
            
        finally:
            writer.close()
            await writer.wait_closed()
    
    @staticmethod
    async def test_authentication_headers_handling(port: int, use_absolute_uri: bool = True):
        """Test various authentication header formats and edge cases"""
        test_cases = [
            # Valid Basic auth
            ("Basic " + base64.b64encode("user:pass".encode()).decode(), [200, 407]),
            # Invalid auth type (may pass if auth is disabled)
            ("Bearer token123", [200, 401, 407, 400]),
            # Malformed Basic auth (may pass if auth is disabled)
            ("Basic invalid-base64!!!", [200, 401, 407, 400]),
            # Empty auth header
            ("", [407, 200]),
        ]
        
        for auth_header, expected_codes in test_cases:
            reader, writer = await asyncio.open_connection("redproxy", port)
            try:
                # Use explicit parameter instead of port-based conditional
                headers = {}
                if auth_header:
                    headers["Proxy-Authorization"] = auth_header
                
                request = build_http_request("GET", "/test", headers, use_absolute_uri=use_absolute_uri)
                
                writer.write(request.encode())
                await writer.drain()
                
                response_line = await reader.readline()
                status_line = response_line.decode().strip()
                assert response_line.startswith(b"HTTP/1.1"), f"Invalid response format: {status_line}"
                
                # Parse status code
                status_code = int(response_line.split()[1].decode()) if len(response_line.split()) > 1 else 500
                assert status_code in expected_codes, f"For auth '{auth_header}', expected one of {expected_codes}, got: {status_code}"
                
            finally:
                writer.close()
                await writer.wait_closed()


class TestHttpXListener:
    """Tier 1: HttpX Listener + Direct Connector (Port 8800)
    
    Tests HttpX listener in isolation with direct connector to validate:
    - Listener request parsing works independently of connector type
    - Forward proxy features work with any backend
    - CONNECT tunneling (forward proxy specific)
    """
    
    # Common patterns
    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.httpx_listener
    async def test_basic_get_request(self):
        """Test basic GET request through HttpX listener + direct connector"""
        await HttpXTestPatterns.test_basic_get_request(8800, use_absolute_uri=True)
    
    @pytest.mark.asyncio
    @pytest.mark.timeout(15)  
    @pytest.mark.httpx_listener
    async def test_post_request_with_body(self):
        """Test POST request with body through HttpX listener + direct connector"""
        await HttpXTestPatterns.test_post_request_with_body(8800, use_absolute_uri=True)
        
    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.httpx_listener
    async def test_chunked_encoding(self):
        """Test chunked encoding through HttpX listener + direct connector"""
        await HttpXTestPatterns.test_chunked_encoding(8800, use_absolute_uri=True)
        
    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.httpx_listener
    async def test_malformed_request_handling(self):
        """Test malformed request handling in HttpX listener + direct connector"""
        await HttpXTestPatterns.test_malformed_request_handling(8800, use_absolute_uri=True)

    # Tier 1 specific: CONNECT tunneling (only forward proxy listeners)
    @pytest.mark.asyncio
    @pytest.mark.timeout(30)
    @pytest.mark.httpx_listener
    @pytest.mark.connect
    async def test_connect_tunneling(self):
        """Test HTTP CONNECT tunnel through HttpX listener + direct connector"""
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
            
            # Read tunneled response
            tunneled_response = await reader.readline()
            assert tunneled_response.startswith(b"HTTP/1.1 200"), f"Tunneled request failed: {tunneled_response.decode().strip()}"
            
        finally:
            writer.close()
            await writer.wait_closed()
        
    # Tier 1 specific: Forward proxy mode using httpx client
    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.httpx_listener
    @pytest.mark.httpx
    async def test_forward_proxy_get(self):
        """Test GET request through forward proxy using httpx client"""
        async with httpx.AsyncClient(proxy="http://redproxy:8800", timeout=10.0) as client:
            response = await client.get("http://http-echo:8080/")
            
            assert response.status_code == 200
            assert "path" in response.text

    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.httpx_listener
    @pytest.mark.httpx
    async def test_forward_proxy_post(self):
        """Test POST request through forward proxy using httpx client"""
        test_data = {"test": "data"}
        
        async with httpx.AsyncClient(proxy="http://redproxy:8800", timeout=10.0) as client:
            response = await client.post("http://http-echo:8080/post", json=test_data)
            
            assert response.status_code == 200

    # Tier 1 specific: HTTP methods support
    @pytest.mark.asyncio
    @pytest.mark.timeout(20)
    @pytest.mark.httpx_listener
    async def test_http_methods_support(self):
        """Test HttpX listener support for various HTTP methods with direct connector"""
        methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]
        
        for method in methods:
            reader, writer = await asyncio.open_connection("redproxy", 8800)
            
            try:
                request = f"{method} http://http-echo:8080/method-test HTTP/1.1\r\n"
                request += "Host: http-echo:8080\r\n"
                request += f"X-Test-Method: {method}\r\n"
                
                if method in ["POST", "PUT", "PATCH"]:
                    request += "Content-Length: 0\r\n"
                    
                request += "Connection: close\r\n"
                request += "\r\n"
                
                writer.write(request.encode())
                await writer.drain()
                
                response_line = await reader.readline()
                assert response_line.startswith(b"HTTP/1.1"), f"Method {method} failed: {response_line.decode().strip()}"
                
            finally:
                writer.close()
                await writer.wait_closed()

    # Advanced chunked encoding tests (HttpX listener specific)
    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.httpx_listener
    @pytest.mark.httpx
    async def test_receive_chunked_from_server(self):
        """Test receiving chunked response from server through HttpX listener + direct"""
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
            # Verify we got chunked response
            assert "HTTP/1.1 200" in response or "HTTP/1.0 200" in response
            
        finally:
            writer.close()
            await writer.wait_closed()

    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.httpx_listener
    @pytest.mark.httpx
    async def test_send_chunked_request(self):
        """Test sending chunked request through HttpX listener + direct"""
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
            response_line = await reader.readline()
            assert response_line.startswith(b"HTTP/1.1 200"), f"Chunked request failed: {response_line.decode().strip()}"
            
        finally:
            writer.close()
            await writer.wait_closed()

    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.httpx_listener
    @pytest.mark.httpx
    @pytest.mark.destructive
    async def test_malformed_chunked_request(self):
        """Test malformed chunked request handling through HttpX listener + direct"""
        reader, writer = await asyncio.open_connection("redproxy", 8800)
        
        try:
            # Send malformed chunked request
            request = "POST http://websocket-server:9998/malformed_chunked HTTP/1.1\r\n"
            request += "Host: websocket-server:9998\r\n"
            request += "Transfer-Encoding: chunked\r\n"
            request += "\r\n"
            
            writer.write(request.encode())
            
            # Send malformed chunk (invalid hex length)
            writer.write(b"INVALID_HEX\r\ndata\r\n")
            writer.write(b"0\r\n\r\n")
            await writer.drain()
            
            # Should handle malformed chunks gracefully
            try:
                response_line = await asyncio.wait_for(reader.readline(), timeout=5.0)
                if response_line:
                    # Should get error response or connection close
                    response_str = response_line.decode().strip()
                    if response_str.startswith("HTTP/"):
                        status_code = response_line.split()[1].decode() if len(response_line.split()) > 1 else "000"
                        assert status_code.startswith(('4', '5')), f"Expected error, got: {status_code}"
            except asyncio.TimeoutError:
                # Connection might be closed for malformed chunks
                pass
                
        finally:
            writer.close()
            await writer.wait_closed()

    # Enhanced Continue handling (HttpX listener specific)
    @pytest.mark.asyncio
    @pytest.mark.timeout(20)
    @pytest.mark.httpx_listener
    @pytest.mark.http_continue
    async def test_100_continue_with_websocket_server(self):
        """Test 100 Continue with websocket server through HttpX listener + direct"""
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
                
                # Send body after 100 continue
                writer.write(test_payload.encode())
                await writer.drain()
                
                # Read final response after sending body
                final_response = await reader.readline()
                assert final_response.startswith(b"HTTP/1.1 200"), f"Continue handling failed: {final_response.decode().strip()}"
            else:
                # Direct response without 100 Continue - also acceptable
                assert response_line.startswith(b"HTTP/1.1"), f"Invalid response: {response_line.decode().strip()}"
            
        finally:
            writer.close()
            await writer.wait_closed()

    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.httpx_listener
    @pytest.mark.http_continue
    async def test_post_with_expect_header(self):
        """Test POST with Expect header through HttpX listener + direct using httpx client"""
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

    # Enhanced Keep-Alive handling (HttpX listener specific) 
    @pytest.mark.asyncio
    @pytest.mark.timeout(30)
    @pytest.mark.httpx_listener
    @pytest.mark.httpx
    async def test_multiple_requests_same_connection(self):
        """Test multiple requests on same connection through HttpX listener + direct"""
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
            response1_line = await reader.readline()
            assert response1_line.startswith(b"HTTP/1.1 200"), f"First request failed: {response1_line.decode().strip()}"
            
            # Skip headers and body for first request
            content_length = None
            while True:
                line = await reader.readline()
                if line == b"\r\n":
                    break
                if line.lower().startswith(b"content-length:"):
                    content_length = int(line.split(b":")[1].strip())
            
            if content_length:
                await reader.read(content_length)
            
            # Second request on same connection
            request2 = "GET http://http-echo:8080/_test_multiple_requests_same_connection/2 HTTP/1.1\r\n"
            request2 += "Host: http-echo:8080\r\n"
            request2 += "Connection: close\r\n"
            request2 += "\r\n"
            
            writer.write(request2.encode())
            await writer.drain()
            
            # Read second response - should work if keep-alive works
            response2_line = await reader.readline()
            assert response2_line.startswith(b"HTTP/1.1 200"), "Keep-alive connection failed"
            
        finally:
            writer.close()
            await writer.wait_closed()

    # Destructive/Error handling tests (HttpX listener specific)
    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.httpx_listener
    @pytest.mark.destructive
    async def test_invalid_http_method(self):
        """Test invalid HTTP method through HttpX listener + direct"""
        reader, writer = await asyncio.open_connection("redproxy", 8800)
        
        try:
            # Send invalid HTTP method
            request = "INVALIDMETHOD http://http-echo:8080/ HTTP/1.1\r\n"
            request += "Host: http-echo:8080\r\n"
            request += "\r\n"
            
            writer.write(request.encode())
            await writer.drain()
            
            try:
                response_line = await asyncio.wait_for(reader.readline(), timeout=5.0)
                if response_line:
                    # Should get proper HTTP error from listener
                    assert response_line.startswith(b"HTTP/"), f"Non-HTTP response: {response_line.decode().strip()}"
                    status_code = response_line.split()[1].decode() if len(response_line.split()) > 1 else "000"
                    assert status_code.startswith(('4', '5')), f"Expected error, got: {status_code}"
            except asyncio.TimeoutError:
                # Connection might be closed immediately for invalid methods
                pass
                
        finally:
            writer.close()
            await writer.wait_closed()

    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.httpx_listener
    @pytest.mark.destructive
    async def test_oversized_headers(self):
        """Test oversized headers through HttpX listener + direct"""
        reader, writer = await asyncio.open_connection("redproxy", 8800)
        
        try:
            # Send request with very large header (20KB header should fail)
            request = "GET http://http-echo:8080/oversize HTTP/1.1\r\n"
            request += "Host: http-echo:8080\r\n"
            request += f"X-Large-Header: {'A' * 20000}\r\n"  # 20KB header
            request += "\r\n"
            
            writer.write(request.encode())
            await writer.drain()
            
            try:
                response_line = await asyncio.wait_for(reader.readline(), timeout=2.0)
                if response_line:
                    # Should get error response for oversized headers
                    response_str = response_line.decode().strip()
                    assert ("400" in response_str or "431" in response_str or "500" in response_str), f"Unexpected response: {response_str}"
            except (asyncio.TimeoutError, ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
                # Connection reset/timeout is acceptable - indicates defensive behavior
                pass
                
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            # Connection reset during write is acceptable defensive behavior
            pass
        finally:
            writer.close()
            await writer.wait_closed()

    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.httpx_listener
    @pytest.mark.destructive
    async def test_empty_request(self):
        """Test empty request through HttpX listener + direct"""
        reader, writer = await asyncio.open_connection("redproxy", 8800)
        
        try:
            # Send empty request (just CRLF)
            writer.write(b"\r\n")
            await writer.drain()
            
            try:
                response_line = await asyncio.wait_for(reader.readline(), timeout=5.0)
                if response_line:
                    # Should get error response for empty request
                    assert response_line.startswith(b"HTTP/"), f"Non-HTTP response: {response_line.decode().strip()}"
                    status_code = response_line.split()[1].decode() if len(response_line.split()) > 1 else "000"
                    assert status_code.startswith(('4', '5')), f"Expected error, got: {status_code}"
            except asyncio.TimeoutError:
                # Connection might be closed immediately for empty requests
                pass
                
        finally:
            writer.close()
            await writer.wait_closed()

    # WebSocket upgrade tests (HttpX listener specific)
    @pytest.mark.asyncio
    @pytest.mark.timeout(20)
    @pytest.mark.httpx_listener
    @pytest.mark.websocket
    async def test_websocket_handshake(self):
        """Test WebSocket handshake through HttpX listener + direct"""
        reader, writer = await asyncio.open_connection("redproxy", 8800)
        
        try:
            # WebSocket upgrade request to our WebSocket server
            import base64
            import secrets
            
            websocket_key = base64.b64encode(secrets.token_bytes(16)).decode()
            
            request = "GET /ws HTTP/1.1\r\n"
            request += "Host: websocket-server:9998\r\n"
            request += "Upgrade: websocket\r\n"
            request += "Connection: Upgrade\r\n"
            request += f"Sec-WebSocket-Key: {websocket_key}\r\n"
            request += "Sec-WebSocket-Version: 13\r\n"
            request += "\r\n"
            
            writer.write(request.encode())
            await writer.drain()
            
            # Read upgrade response
            response_line = await reader.readline()
            assert response_line.startswith(b"HTTP/1.1 101"), f"WebSocket upgrade failed: {response_line.decode().strip()}"
            
            # Verify upgrade headers
            upgrade_found = False
            connection_found = False
            
            while True:
                line = await reader.readline()
                if line == b"\r\n":
                    break
                line_str = line.decode().lower()
                if "upgrade: websocket" in line_str:
                    upgrade_found = True
                elif "connection: upgrade" in line_str:
                    connection_found = True
            
            assert upgrade_found and connection_found, "Missing WebSocket upgrade headers"
            
        finally:
            writer.close()
            await writer.wait_closed()

    # Authentication tests (HttpX listener specific)
    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.httpx_listener
    @pytest.mark.auth
    async def test_proxy_authentication_required(self):
        """Test proxy authentication required (407) response through HttpX listener + direct"""
        await HttpXTestPatterns.test_proxy_authentication_required(8800, use_absolute_uri=True)

    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.httpx_listener
    @pytest.mark.auth
    async def test_proxy_authentication_success(self):
        """Test successful proxy authentication through HttpX listener + direct"""
        await HttpXTestPatterns.test_proxy_authentication_success(8800, use_absolute_uri=True)

    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.httpx_listener
    @pytest.mark.auth
    async def test_proxy_authentication_failure(self):
        """Test proxy authentication failure through HttpX listener + direct"""
        await HttpXTestPatterns.test_proxy_authentication_failure(8800, use_absolute_uri=True)

    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.httpx_listener
    @pytest.mark.auth
    async def test_connect_with_authentication(self):
        """Test CONNECT method with proxy authentication through HttpX listener + direct"""
        await HttpXTestPatterns.test_connect_with_authentication(8800, use_absolute_uri=True)

    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.httpx_listener
    @pytest.mark.auth
    async def test_authentication_headers_handling(self):
        """Test various authentication header formats through HttpX listener + direct"""
        await HttpXTestPatterns.test_authentication_headers_handling(8800, use_absolute_uri=True)


class TestHttpXIntegration:
    """Tier 2: HttpX Listener + HttpX Connector Pipeline (Port 8801)
    
    Tests the full HttpX pipeline with special cases and optimizations:
    - Connection pooling through HttpX connector
    - Keep-alive chain management
    - HTTP context state tracking  
    - Continue handling (100-continue)
    """
    
    # Common patterns
    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.httpx_integration
    async def test_basic_get_request(self):
        """Test basic GET request through HttpX listener + HttpX connector"""
        await HttpXTestPatterns.test_basic_get_request(8801, use_absolute_uri=True)
    
    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.httpx_integration
    async def test_post_request_with_body(self):
        """Test POST request with body through HttpX listener + HttpX connector"""
        await HttpXTestPatterns.test_post_request_with_body(8801, use_absolute_uri=True)
        
    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.httpx_integration
    async def test_chunked_encoding(self):
        """Test chunked encoding through HttpX listener + HttpX connector"""
        await HttpXTestPatterns.test_chunked_encoding(8801, use_absolute_uri=True)
        
    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.httpx_integration
    async def test_malformed_request_handling(self):
        """Test malformed request handling in HttpX listener + HttpX connector"""
        await HttpXTestPatterns.test_malformed_request_handling(8801, use_absolute_uri=True)

    # Tier 2 specific: Connection pooling (HttpX connector feature)  
    @pytest.mark.asyncio
    @pytest.mark.timeout(30)
    @pytest.mark.httpx_integration
    @pytest.mark.connection_pooling
    async def test_connection_pooling(self):
        """Test HttpX connector connection pooling in full pipeline"""
        # Multiple sequential requests should reuse HttpX connector pool
        for i in range(3):
            reader, writer = await asyncio.open_connection("redproxy", 8801)
            try:
                request = f"GET http://http-echo:8080/pool-test-{i} HTTP/1.1\r\n"
                request += "Host: http-echo:8080\r\n"
                request += f"X-Pool-Test: {i}\r\n"
                request += "Connection: close\r\n"
                request += "\r\n"
                
                writer.write(request.encode())
                await writer.drain()
                
                response_line = await reader.readline()
                assert response_line.startswith(b"HTTP/1.1 200"), f"Pool test {i} failed: {response_line.decode().strip()}"
                
            finally:
                writer.close()
                await writer.wait_closed()
    
    # Tier 2 specific: Keep-alive chain management
    @pytest.mark.asyncio
    @pytest.mark.timeout(30)
    @pytest.mark.httpx_integration
    @pytest.mark.keepalive
    async def test_keepalive_chain_management(self):
        """Test keep-alive chain through HttpX listener + HttpX connector"""
        reader, writer = await asyncio.open_connection("redproxy", 8801)
        
        try:
            # First request with keep-alive
            request1 = "GET http://http-echo:8080/keepalive1 HTTP/1.1\r\n"
            request1 += "Host: http-echo:8080\r\n"
            request1 += "Connection: keep-alive\r\n"
            request1 += "\r\n"
            
            writer.write(request1.encode())
            await writer.drain()
            
            # Read first response
            response1_line = await reader.readline()
            assert response1_line.startswith(b"HTTP/1.1 200")
            
            # Skip headers and body for first request
            content_length = None
            while True:
                line = await reader.readline()
                if line == b"\r\n":
                    break
                if line.lower().startswith(b"content-length:"):
                    content_length = int(line.split(b":")[1].strip())
            
            if content_length:
                await reader.read(content_length)
            
            # Second request on same connection (tests both listener and connector keep-alive)
            request2 = "GET http://http-echo:8080/keepalive2 HTTP/1.1\r\n"
            request2 += "Host: http-echo:8080\r\n" 
            request2 += "Connection: close\r\n"
            request2 += "\r\n"
            
            writer.write(request2.encode())
            await writer.drain()
            
            # Read second response - should work if keep-alive chain works
            response2_line = await reader.readline()
            assert response2_line.startswith(b"HTTP/1.1 200"), "Keep-alive chain failed"
            
        finally:
            writer.close()
            await writer.wait_closed()

    # Tier 2 specific: Enhanced Continue handling (100-continue)
    @pytest.mark.asyncio
    @pytest.mark.timeout(20)
    @pytest.mark.httpx_integration
    @pytest.mark.http_continue
    async def test_100_continue_with_websocket_server(self):
        """Test 100 Continue with websocket server through HttpX pipeline"""
        reader, writer = await asyncio.open_connection("redproxy", 8801)
        
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
                
                # Send body after 100 continue
                writer.write(test_payload.encode())
                await writer.drain()
                
                # Read final response after sending body
                final_response = await reader.readline()
                assert final_response.startswith(b"HTTP/1.1 200"), f"Continue handling failed: {final_response.decode().strip()}"
            else:
                # Direct response without 100 Continue - also acceptable
                assert response_line.startswith(b"HTTP/1.1"), f"Invalid response: {response_line.decode().strip()}"
            
        finally:
            writer.close()
            await writer.wait_closed()

    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.httpx_integration
    @pytest.mark.http_continue
    async def test_post_with_expect_header(self):
        """Test POST with Expect header through HttpX pipeline using httpx client"""
        test_data = "Expect 100-continue payload test data"
        headers = {
            "Expect": "100-continue",
            "Content-Type": "text/plain"
        }
        
        async with httpx.AsyncClient(proxy="http://redproxy:8801", timeout=10.0) as client:
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

    # Enhanced Keep-Alive handling (HttpX listener + HttpX connector)
    @pytest.mark.asyncio
    @pytest.mark.timeout(30)
    @pytest.mark.httpx_integration
    @pytest.mark.httpx
    async def test_multiple_requests_same_connection(self):
        """Test multiple requests on same connection through HttpX listener + HttpX connector"""
        reader, writer = await asyncio.open_connection("redproxy", 8801)
        
        try:
            # First request
            request1 = "GET http://http-echo:8080/_test_multiple_requests_same_connection/1 HTTP/1.1\r\n"
            request1 += "Host: http-echo:8080\r\n"
            request1 += "Connection: keep-alive\r\n"
            request1 += "\r\n"
            
            writer.write(request1.encode())
            await writer.drain()
            
            # Read first response  
            response1_line = await reader.readline()
            assert response1_line.startswith(b"HTTP/1.1 200"), f"First request failed: {response1_line.decode().strip()}"
            
            # Skip headers and body for first request
            content_length = None
            while True:
                line = await reader.readline()
                if line == b"\r\n":
                    break
                if line.lower().startswith(b"content-length:"):
                    content_length = int(line.split(b":")[1].strip())
            
            if content_length:
                await reader.read(content_length)
            
            # Second request on same connection
            request2 = "GET http://http-echo:8080/_test_multiple_requests_same_connection/2 HTTP/1.1\r\n"
            request2 += "Host: http-echo:8080\r\n"
            request2 += "Connection: close\r\n"
            request2 += "\r\n"
            
            writer.write(request2.encode())
            await writer.drain()
            
            # Read second response - should work if keep-alive works in the full pipeline
            response2_line = await reader.readline()
            assert response2_line.startswith(b"HTTP/1.1 200"), "Keep-alive connection failed in HttpX pipeline"
            
        finally:
            writer.close()
            await writer.wait_closed()

    # Destructive/Error handling tests (HttpX listener + HttpX connector)
    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.httpx_integration
    @pytest.mark.destructive
    async def test_invalid_http_method(self):
        """Test invalid HTTP method through HttpX listener + HttpX connector"""
        reader, writer = await asyncio.open_connection("redproxy", 8801)
        
        try:
            # Send invalid HTTP method
            request = "INVALIDMETHOD http://http-echo:8080/ HTTP/1.1\r\n"
            request += "Host: http-echo:8080\r\n"
            request += "\r\n"
            
            writer.write(request.encode())
            await writer.drain()
            
            try:
                response_line = await asyncio.wait_for(reader.readline(), timeout=5.0)
                if response_line:
                    # Should get proper HTTP error from listener
                    assert response_line.startswith(b"HTTP/"), f"Non-HTTP response: {response_line.decode().strip()}"
                    status_code = response_line.split()[1].decode() if len(response_line.split()) > 1 else "000"
                    assert status_code.startswith(('4', '5')), f"Expected error, got: {status_code}"
            except asyncio.TimeoutError:
                # Connection might be closed immediately for invalid methods
                pass
                
        finally:
            writer.close()
            await writer.wait_closed()

    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.httpx_integration
    @pytest.mark.destructive
    async def test_oversized_headers(self):
        """Test oversized headers through HttpX listener + HttpX connector"""
        reader, writer = await asyncio.open_connection("redproxy", 8801)
        
        try:
            # Send request with very large header (20KB header should fail)
            request = "GET http://http-echo:8080/oversize HTTP/1.1\r\n"
            request += "Host: http-echo:8080\r\n"
            request += f"X-Large-Header: {'A' * 20000}\r\n"  # 20KB header
            request += "\r\n"
            
            writer.write(request.encode())
            await writer.drain()
            
            try:
                response_line = await asyncio.wait_for(reader.readline(), timeout=2.0)
                if response_line:
                    # Should get error response for oversized headers
                    response_str = response_line.decode().strip()
                    assert ("400" in response_str or "431" in response_str or "500" in response_str), f"Unexpected response: {response_str}"
            except (asyncio.TimeoutError, ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
                # Connection reset/timeout is acceptable - indicates defensive behavior
                pass
                
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            # Connection reset during write is acceptable defensive behavior
            pass
        finally:
            writer.close()
            await writer.wait_closed()

    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.httpx_integration
    @pytest.mark.destructive
    async def test_empty_request(self):
        """Test empty request through HttpX listener + HttpX connector"""
        reader, writer = await asyncio.open_connection("redproxy", 8801)
        
        try:
            # Send empty request (just CRLF)
            writer.write(b"\r\n")
            await writer.drain()
            
            try:
                response_line = await asyncio.wait_for(reader.readline(), timeout=5.0)
                if response_line:
                    # Should get error response for empty request
                    assert response_line.startswith(b"HTTP/"), f"Non-HTTP response: {response_line.decode().strip()}"
                    status_code = response_line.split()[1].decode() if len(response_line.split()) > 1 else "000"
                    assert status_code.startswith(('4', '5')), f"Expected error, got: {status_code}"
            except asyncio.TimeoutError:
                # Connection might be closed immediately for empty requests
                pass
                
        finally:
            writer.close()
            await writer.wait_closed()

    # WebSocket upgrade tests (HttpX listener + HttpX connector)
    @pytest.mark.asyncio
    @pytest.mark.timeout(20)
    @pytest.mark.httpx_integration
    @pytest.mark.websocket
    async def test_websocket_handshake(self):
        """Test WebSocket handshake through HttpX listener + HttpX connector"""
        reader, writer = await asyncio.open_connection("redproxy", 8801)
        
        try:
            # WebSocket upgrade request to our WebSocket server
            import base64
            import secrets
            
            websocket_key = base64.b64encode(secrets.token_bytes(16)).decode()
            
            request = "GET http://websocket-server:9998/ws HTTP/1.1\r\n"
            request += "Host: websocket-server:9998\r\n"
            request += "Upgrade: websocket\r\n"
            request += "Connection: Upgrade\r\n"
            request += f"Sec-WebSocket-Key: {websocket_key}\r\n"
            request += "Sec-WebSocket-Version: 13\r\n"
            request += "\r\n"
            
            writer.write(request.encode())
            await writer.drain()
            
            # Read upgrade response
            response_line = await reader.readline()
            assert response_line.startswith(b"HTTP/1.1 101"), f"WebSocket upgrade failed: {response_line.decode().strip()}"
            
            # Verify upgrade headers
            upgrade_found = False
            connection_found = False
            
            while True:
                line = await reader.readline()
                if line == b"\r\n":
                    break
                line_str = line.decode().lower()
                if "upgrade: websocket" in line_str:
                    upgrade_found = True
                elif "connection: upgrade" in line_str:
                    connection_found = True
            
            assert upgrade_found and connection_found, "Missing WebSocket upgrade headers"
            
        finally:
            writer.close()
            await writer.wait_closed()

    # Advanced chunked encoding tests (HttpX listener + HttpX connector)
    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.httpx_integration
    @pytest.mark.httpx
    async def test_receive_chunked_from_server(self):
        """Test receiving chunked response from server through HttpX listener + HttpX connector"""
        reader, writer = await asyncio.open_connection("redproxy", 8801)
        
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
            # Verify we got chunked response
            assert "HTTP/1.1 200" in response or "HTTP/1.0 200" in response
            
        finally:
            writer.close()
            await writer.wait_closed()

    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.httpx_integration
    @pytest.mark.httpx
    async def test_send_chunked_request(self):
        """Test sending chunked request through HttpX listener + HttpX connector"""
        reader, writer = await asyncio.open_connection("redproxy", 8801)
        
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
            response_line = await reader.readline()
            assert response_line.startswith(b"HTTP/1.1 200"), f"Chunked request failed: {response_line.decode().strip()}"
            
        finally:
            writer.close()
            await writer.wait_closed()

    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.httpx_integration
    @pytest.mark.httpx
    @pytest.mark.destructive
    async def test_malformed_chunked_request(self):
        """Test malformed chunked request handling through HttpX listener + HttpX connector"""
        reader, writer = await asyncio.open_connection("redproxy", 8801)
        
        try:
            # Send malformed chunked request
            request = "POST http://websocket-server:9998/malformed_chunked HTTP/1.1\r\n"
            request += "Host: websocket-server:9998\r\n"
            request += "Transfer-Encoding: chunked\r\n"
            request += "\r\n"
            
            writer.write(request.encode())
            
            # Send malformed chunk (invalid hex length)
            writer.write(b"INVALID_HEX\r\ndata\r\n")
            writer.write(b"0\r\n\r\n")
            await writer.drain()
            
            # Should handle malformed chunks gracefully
            try:
                response_line = await asyncio.wait_for(reader.readline(), timeout=5.0)
                if response_line:
                    # Should get error response or connection close
                    response_str = response_line.decode().strip()
                    if response_str.startswith("HTTP/"):
                        status_code = response_line.split()[1].decode() if len(response_line.split()) > 1 else "000"
                        assert status_code.startswith(('4', '5')), f"Expected error, got: {status_code}"
            except asyncio.TimeoutError:
                # Connection might be closed for malformed chunks
                pass
                
        finally:
            writer.close()
            await writer.wait_closed()

    # Authentication tests (HttpX listener + HttpX connector pipeline)
    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.httpx_integration
    @pytest.mark.auth
    async def test_proxy_authentication_required(self):
        """Test proxy authentication required (407) response through HttpX pipeline"""
        await HttpXTestPatterns.test_proxy_authentication_required(8801, use_absolute_uri=True)

    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.httpx_integration
    @pytest.mark.auth
    async def test_proxy_authentication_success(self):
        """Test successful proxy authentication through HttpX pipeline"""
        await HttpXTestPatterns.test_proxy_authentication_success(8801, use_absolute_uri=True)

    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.httpx_integration
    @pytest.mark.auth
    async def test_proxy_authentication_failure(self):
        """Test proxy authentication failure through HttpX pipeline"""
        await HttpXTestPatterns.test_proxy_authentication_failure(8801, use_absolute_uri=True)

    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.httpx_integration
    @pytest.mark.auth
    async def test_connect_with_authentication(self):
        """Test CONNECT method with proxy authentication through HttpX pipeline"""
        await HttpXTestPatterns.test_connect_with_authentication(8801, use_absolute_uri=True)

    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.httpx_integration
    @pytest.mark.auth
    async def test_authentication_headers_handling(self):
        """Test various authentication header formats through HttpX pipeline"""
        await HttpXTestPatterns.test_authentication_headers_handling(8801, use_absolute_uri=True)


class TestHttpXConnector:
    """Tier 3: Reverse Listener + HttpX Connector (Port 8802)
    
    Tests HttpX connector in isolation with reverse proxy listener to validate:
    - Connector pooling works regardless of frontend type
    - HttpX connector features work with non-HttpX listeners
    """
    
    # Common patterns (adapted for reverse proxy format)
    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.httpx_integration
    async def test_basic_get_request(self):
        """Test basic GET request through reverse listener + HttpX connector"""
        await HttpXTestPatterns.test_basic_get_request(8802, use_absolute_uri=False)
    
    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.httpx_integration
    async def test_post_request_with_body(self):
        """Test POST request with body through reverse listener + HttpX connector"""
        await HttpXTestPatterns.test_post_request_with_body(8802, use_absolute_uri=False)
        
    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.httpx_integration
    async def test_chunked_encoding(self):
        """Test chunked encoding through reverse listener + HttpX connector"""
        await HttpXTestPatterns.test_chunked_encoding(8802, use_absolute_uri=False)
        
    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.httpx_integration
    async def test_malformed_request_handling(self):
        """Test malformed request handling in reverse listener + HttpX connector"""
        await HttpXTestPatterns.test_malformed_request_handling(8802, use_absolute_uri=False)

    # Tier 3 specific: HttpX connector pooling from reverse proxy
    @pytest.mark.asyncio
    @pytest.mark.timeout(30)
    @pytest.mark.httpx_integration
    @pytest.mark.connection_pooling
    async def test_connector_pooling_from_reverse(self):
        """Test HttpX connector pooling when called from reverse proxy"""
        # Multiple requests to same reverse proxy should reuse HttpX connector pool
        for i in range(3):
            reader, writer = await asyncio.open_connection("redproxy", 8802)
            try:
                request = f"GET /reverse-pool-test-{i} HTTP/1.1\r\n"  # No full URL for reverse proxy
                request += "Host: http-echo\r\n"
                request += f"X-Reverse-Pool-Test: {i}\r\n"
                request += "Connection: close\r\n"
                request += "\r\n"
                
                writer.write(request.encode())
                await writer.drain()
                
                response_line = await reader.readline()
                assert response_line.startswith(b"HTTP/1.1 200"), f"Reverse pool test {i} failed: {response_line.decode().strip()}"
                
            finally:
                writer.close()
                await writer.wait_closed()

    # Tier 3 specific: Reverse proxy behavior validation
    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.httpx_integration
    async def test_reverse_proxy_request_format(self):
        """Test that reverse proxy request format works with HttpX connector"""
        reader, writer = await asyncio.open_connection("redproxy", 8802)
        
        try:
            # Reverse proxy uses relative paths, not full URLs
            request = "GET /reverse-format-test HTTP/1.1\r\n"
            request += "Host: http-echo\r\n"
            request += "X-Reverse-Test: format-validation\r\n"
            request += "Connection: close\r\n"
            request += "\r\n"
            
            writer.write(request.encode())
            await writer.drain()
            
            response_line = await reader.readline()
            assert response_line.startswith(b"HTTP/1.1 200"), f"Reverse proxy format failed: {response_line.decode().strip()}"
            
        finally:
            writer.close()
            await writer.wait_closed()

    # Authentication tests (Reverse listener + HttpX connector)
    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.httpx_integration
    @pytest.mark.auth
    async def test_proxy_authentication_required(self):
        """Test proxy authentication required (407) response through reverse + HttpX connector"""
        await HttpXTestPatterns.test_proxy_authentication_required(8802, use_absolute_uri=False)

    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.httpx_integration
    @pytest.mark.auth
    async def test_proxy_authentication_success(self):
        """Test successful proxy authentication through reverse + HttpX connector"""
        await HttpXTestPatterns.test_proxy_authentication_success(8802, use_absolute_uri=False)

    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.httpx_integration
    @pytest.mark.auth
    async def test_proxy_authentication_failure(self):
        """Test proxy authentication failure through reverse + HttpX connector"""
        await HttpXTestPatterns.test_proxy_authentication_failure(8802, use_absolute_uri=False)


    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.httpx_integration
    @pytest.mark.auth
    async def test_authentication_headers_handling(self):
        """Test various authentication header formats through reverse + HttpX connector"""
        await HttpXTestPatterns.test_authentication_headers_handling(8802, use_absolute_uri=False)

# Run individual tests for debugging
if __name__ == "__main__":
    print("HttpX Component Isolation Test Suite")
    print("Run with: pytest tests/httpx/test_httpx.py")
    print("")
    print("Component-specific runs:")
    print("  HttpX Listener + Direct:          pytest -m httpx_listener")
    print("  HttpX Listener + HttpX Connector: pytest -m httpx_connector")  
    print("  Reverse + HttpX Connector:        pytest -m httpx_integration")
    print("")
    print("Feature-specific runs:")
    print("  CONNECT tunneling:    pytest -m connect")
    print("  Connection pooling:   pytest -m connection_pooling")
    print("  Keep-alive handling:  pytest -m keepalive")
    print("  Continue handling:    pytest -m http_continue")
    print("  WebSocket upgrades:   pytest -m websocket")
    print("  Destructive tests:    pytest -m destructive")
    print("  Chunked encoding:     pytest -m chunked")