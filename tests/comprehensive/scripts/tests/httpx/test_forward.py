"""
HTTP Forward Proxy tests for redproxy httpx listener

Pure pytest implementation - no legacy dependencies
"""

import pytest
import httpx


class TestHTTPForward:
    """HTTP Forward Proxy tests"""

    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.http
    async def test_forward_proxy_get(self):
        """Test GET request through forward proxy - from _test_forward_proxy_get()"""
        async with httpx.AsyncClient(proxy="http://redproxy:8800", timeout=10.0) as client:
            response = await client.get("http://http-echo:8080/")
            
            assert response.status_code == 200
            assert "path" in response.text

    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.http
    async def test_forward_proxy_post(self):
        """Test POST request through forward proxy - from _test_forward_proxy_post()"""
        test_data = "Test POST data"
        async with httpx.AsyncClient(proxy="http://redproxy:8800", timeout=10.0) as client:
            response = await client.post(
                "http://http-echo:8080/post",
                content=test_data,
                headers={"Content-Type": "text/plain"}
            )
            
            assert response.status_code == 200

    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.http
    async def test_forward_proxy_head(self):
        """Test HEAD request through forward proxy - from _test_forward_proxy_head()"""
        async with httpx.AsyncClient(proxy="http://redproxy:8800", timeout=10.0) as client:
            response = await client.head("http://http-echo:8080/")
            
            assert response.status_code == 200
            assert len(response.content) == 0

    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.http
    async def test_forward_proxy_options(self):
        """Test OPTIONS request through forward proxy - from _test_forward_proxy_options()"""
        async with httpx.AsyncClient(proxy="http://redproxy:8800", timeout=10.0) as client:
            response = await client.options("http://http-echo:8080/")
            
            assert response.status_code in [200, 204, 405]

    @pytest.mark.asyncio
    @pytest.mark.timeout(10)
    @pytest.mark.http
    @pytest.mark.destructive
    async def test_forward_proxy_error_handling(self):
        """Test forward proxy error handling - from _test_forward_proxy_error_handling()"""
        async with httpx.AsyncClient(proxy="http://redproxy:8800", timeout=5.0) as client:
            try:
                response = await client.get("http://nonexistent-host.invalid/")
                # Should get error status or connection error
                assert response.status_code >= 400
            except httpx.RequestError:
                # Connection error is also acceptable
                pass

    @pytest.mark.asyncio
    @pytest.mark.timeout(10)
    @pytest.mark.http
    @pytest.mark.destructive
    async def test_forward_proxy_malformed_url(self):
        """Test forward proxy with malformed URL - from _test_forward_proxy_malformed_url()"""
        async with httpx.AsyncClient(proxy="http://redproxy:8800", timeout=5.0) as client:
            with pytest.raises(Exception):
                await client.get("invalid-url-format")


# Run individual tests for debugging
if __name__ == "__main__":
    # pytest tests/httpx/test_forward.py::TestHTTPForward::test_forward_proxy_get
    print("Run with: pytest tests/httpx/test_forward.py")
    print("Or single test: pytest tests/httpx/test_forward.py::TestHTTPForward::test_forward_proxy_get")
    print("Or all http tests: pytest -m http")