"""
Protocol combination matrix tests for redproxy

Tests comprehensive listener×connector combinations and advanced scenarios - DYNAMICALLY GENERATED
"""

import asyncio
import pytest
import httpx
import sys
import os

# Import from shared helpers
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../shared'))
from helpers import setup_test_environment, wait_for_service
from matrix_loader import matrix_config


class TestProtocolCombinations:
    """Comprehensive protocol combination matrix tests"""

    @pytest.mark.asyncio
    @pytest.mark.timeout(30)
    @pytest.mark.matrix
    @pytest.mark.protocol_combination
    async def test_http_to_multiple_backends(self):
        """Test HTTP listener routing to different backend connectors"""
        # Get actual HTTP listeners from matrix configuration
        http_listeners = matrix_config.get_http_listener_ports()
        if not http_listeners:
            pytest.skip("No HTTP listeners configured in matrix")
        
        # Use first 3 HTTP listeners for testing
        test_listeners = http_listeners[:3]
        target = "http://http-echo:8080/"
        
        results = []
        
        for port, connector in test_listeners:
            if not await wait_for_service("redproxy", port, timeout=5.0):
                pytest.fail(f"RedProxy HTTP service not available on port {port} - infrastructure failure")
            
            try:
                proxy_url = f"http://redproxy:{port}"
                async with httpx.AsyncClient(proxy=proxy_url, timeout=8.0) as client:
                    response = await client.get(target)
                    success = response.status_code == 200 and "path" in response.text
                    results.append((port, connector, success))
                    print(f"{'✅' if success else '❌'} HTTP:{port} → {connector}")
            except Exception as e:
                results.append((port, connector, False))
                print(f"❌ HTTP:{port} → {connector} failed: {e}")
        
        # Should have at least one successful combination
        successful = [r for r in results if r[2]]
        assert len(successful) > 0, f"No successful HTTP combinations: {results}"

    @pytest.mark.asyncio
    @pytest.mark.timeout(25)
    @pytest.mark.matrix
    @pytest.mark.protocol_combination
    async def test_socks_to_multiple_backends(self):
        """Test SOCKS listener routing to different backend connectors"""
        # Get actual SOCKS listeners from matrix configuration
        socks_listeners = matrix_config.get_socks_listener_ports()
        if not socks_listeners:
            pytest.skip("No SOCKS listeners configured in matrix")
        
        # Use first 3 SOCKS listeners for testing
        test_listeners = socks_listeners[:3]
        target = "http://http-echo:8080/"
        
        results = []
        
        for port, connector in test_listeners:
            if not await wait_for_service("redproxy", port, timeout=5.0):
                pytest.fail(f"RedProxy SOCKS service not available on port {port} - infrastructure failure")
            
            try:
                proxy_url = f"socks5://redproxy:{port}"
                async with httpx.AsyncClient(proxy=proxy_url, timeout=8.0) as client:
                    response = await client.get(target)
                    success = response.status_code == 200 and "path" in response.text
                    results.append((port, connector, success))
                    print(f"{'✅' if success else '❌'} SOCKS:{port} → {connector}")
            except Exception as e:
                results.append((port, connector, False))
                print(f"❌ SOCKS:{port} → {connector} failed: {e}")
        
        # Should have at least one successful combination
        successful = [r for r in results if r[2]]
        assert len(successful) > 0, f"No successful SOCKS combinations: {results}"

    @pytest.mark.asyncio
    @pytest.mark.timeout(20)
    @pytest.mark.matrix
    @pytest.mark.protocol_combination
    async def test_mixed_protocol_workflow(self):
        """Test mixed protocol workflow - HTTP and SOCKS in sequence"""
        # Step 1: HTTP request using first available HTTP listener
        http_listeners = matrix_config.get_http_listener_ports()
        if not http_listeners:
            pytest.skip("No HTTP listeners configured in matrix")
        
        http_port, http_connector = http_listeners[0]
        if not await wait_for_service("redproxy", http_port, timeout=10.0):
            pytest.fail(f"RedProxy HTTP service not available on port {http_port} - infrastructure failure")
        
        proxy_url = f"http://redproxy:{http_port}"
        async with httpx.AsyncClient(proxy=proxy_url, timeout=8.0) as client:
            http_response = await client.get("http://http-echo:8080/")
            assert http_response.status_code == 200, "HTTP step failed"
            print("✅ HTTP step completed")
        
        # Step 2: SOCKS request using first available SOCKS listener
        socks_listeners = matrix_config.get_socks_listener_ports()
        if not socks_listeners:
            pytest.skip("No SOCKS listeners configured in matrix")
        
        socks_port, socks_connector = socks_listeners[0]
        if not await wait_for_service("redproxy", socks_port, timeout=10.0):
            pytest.fail(f"RedProxy SOCKS service not available on port {socks_port} - infrastructure failure")
        
        proxy_url = f"socks5://redproxy:{socks_port}"
        async with httpx.AsyncClient(proxy=proxy_url, timeout=8.0) as client:
            socks_response = await client.get("http://http-echo:8080/")
            assert socks_response.status_code == 200, "SOCKS step failed"
            print("✅ SOCKS step completed")

    @pytest.mark.asyncio
    @pytest.mark.timeout(35)
    @pytest.mark.matrix
    @pytest.mark.protocol_combination
    @pytest.mark.slow
    async def test_comprehensive_matrix_sample(self):
        """Test comprehensive sample of the protocol matrix"""
        # Get actual listeners from matrix configuration
        http_listeners = matrix_config.get_http_listener_ports()
        socks_listeners = matrix_config.get_socks_listener_ports()
        
        # Sample of key protocol combinations to test - first 2 of each type
        matrix_combinations = []
        target = "http://http-echo:8080/"
        
        for port, connector in http_listeners[:2]:
            matrix_combinations.append(("http", port, target))
        
        for port, connector in socks_listeners[:2]:
            matrix_combinations.append(("socks5", port, target))
        
        if not matrix_combinations:
            pytest.skip("No HTTP or SOCKS listeners configured in matrix")
        
        results = {}
        
        for listener_type, port, target in matrix_combinations:
            test_key = f"{listener_type}:{port}"
            
            if not await wait_for_service("redproxy", port, timeout=3.0):
                pytest.fail(f"RedProxy {listener_type} service not available on port {port} - infrastructure failure")
            
            try:
                if listener_type == "http":
                    proxy_url = f"http://redproxy:{port}"
                elif listener_type == "socks5":
                    proxy_url = f"socks5://redproxy:{port}"
                else:
                    pytest.skip(f"Unsupported listener type: {listener_type}")
                    
                async with httpx.AsyncClient(proxy=proxy_url, timeout=6.0) as client:
                    response = await client.get(target)
                    success = response.status_code == 200
                    results[test_key] = success
                    print(f"{'✅' if success else '❌'} {test_key}")
                    
            except Exception as e:
                results[test_key] = False
                print(f"❌ {test_key} failed: {e}")
                # Continue with other tests rather than failing immediately
        
        # Calculate success rate
        total_tests = len(results)
        successful_tests = sum(1 for success in results.values() if success)
        success_rate = successful_tests / total_tests if total_tests > 0 else 0
        
        print(f"Matrix sample results: {successful_tests}/{total_tests} ({success_rate*100:.1f}%)")
        
        # Require at least 50% success rate for matrix sample
        assert success_rate >= 0.5, f"Low matrix success rate: {success_rate*100:.1f}% ({results})"

    @pytest.mark.asyncio
    @pytest.mark.timeout(15)
    @pytest.mark.matrix
    @pytest.mark.protocol_combination
    async def test_error_handling_across_protocols(self):
        """Test error handling consistency across different protocol combinations"""
        # Test invalid target handling across protocols
        invalid_target = "http://nonexistent-host-12345.invalid/"
        
        # Get first available HTTP and SOCKS listeners
        test_protocols = []
        
        http_listeners = matrix_config.get_http_listener_ports()
        if http_listeners:
            test_protocols.append(("http", http_listeners[0][0]))
        
        socks_listeners = matrix_config.get_socks_listener_ports()
        if socks_listeners:
            test_protocols.append(("socks5", socks_listeners[0][0]))
        
        if not test_protocols:
            pytest.skip("No HTTP or SOCKS listeners configured in matrix")
        
        for protocol, port in test_protocols:
            if not await wait_for_service("redproxy", port, timeout=5.0):
                pytest.fail(f"RedProxy {protocol} service not available on port {port} - infrastructure failure")
            
            try:
                if protocol == "http":
                    proxy_url = f"http://redproxy:{port}"
                else:
                    proxy_url = f"socks5://redproxy:{port}"
                    
                async with httpx.AsyncClient(proxy=proxy_url, timeout=5.0) as client:
                    try:
                        response = await client.get(invalid_target)
                        # Should get error status or exception
                        assert response.status_code >= 400, f"{protocol} should return error status"
                        print(f"✅ {protocol}:{port} error handling OK")
                    except (httpx.RequestError, httpx.TimeoutException):
                        # Network errors are acceptable for invalid targets
                        print(f"✅ {protocol}:{port} error handling OK (exception)")
                        
            except Exception as e:
                print(f"❌ {protocol}:{port} error test failed: {e}")
                pytest.fail(f"Error handling test failed for {protocol}:{port}: {e}")


# Run individual tests for debugging  
if __name__ == "__main__":
    # pytest tests/matrix/test_combinations.py::TestProtocolCombinations::test_http_to_multiple_backends
    print("Run with: pytest tests/matrix/test_combinations.py")
    print("Or single test: pytest tests/matrix/test_combinations.py::TestProtocolCombinations::test_mixed_protocol_workflow")
    print("Or all protocol combination tests: pytest -k protocol_combination")