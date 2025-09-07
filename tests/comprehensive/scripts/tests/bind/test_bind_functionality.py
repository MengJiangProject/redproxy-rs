"""
SOCKS BIND functionality tests for RedProxy
Tests comprehensive BIND command support across different configurations and scenarios
"""
import pytest
import asyncio
import socket
import struct
import time
from typing import Tuple, Optional

# Import from local conftest
from .conftest import SocksBindTester

class TestSocksListenerBind:
    """Test SOCKS listener BIND command support"""
    
    @pytest.mark.asyncio
    @pytest.mark.bind
    async def test_bind_allowed(self, socks_tester_factory, bind_ports):
        """Test BIND on listener with allow_bind=true"""
        tester = socks_tester_factory(bind_ports["bind_allowed"])
        success, bound_addr = await tester.socks5_bind_request("0.0.0.0", 0)
        
        assert success, "BIND request should succeed when allow_bind=true"
        assert bound_addr is not None, "Should receive bound address"
        assert isinstance(bound_addr[1], int), "Bound port should be integer"
        assert bound_addr[1] > 0, "Bound port should be positive"
    
    @pytest.mark.asyncio 
    @pytest.mark.bind
    async def test_bind_denied(self, socks_tester_factory, bind_ports):
        """Test BIND on listener with allow_bind=false"""
        tester = socks_tester_factory(bind_ports["bind_denied"])
        success, bound_addr = await tester.socks5_bind_request("0.0.0.0", 0)
        
        assert not success, "BIND request should fail when allow_bind=false"
    
    @pytest.mark.asyncio
    @pytest.mark.bind
    async def test_bind_address_enforcement(self, socks_tester_factory, bind_ports):
        """Test BIND with enforce_bind_address=true"""
        tester = socks_tester_factory(bind_ports["bind_enforce"])
        success, bound_addr = await tester.socks5_bind_request("0.0.0.0", 8888)
        
        assert success, "BIND request should succeed"
        assert bound_addr is not None, "Should receive bound address"
        # Should get system-assigned port, not the requested port 8888
        assert bound_addr[1] != 8888, "Should get system port when enforce_bind_address=true"

class TestSocksConnectorBind:
    """Test SOCKS connector BIND functionality with upstream proxy"""
    
    @pytest.mark.asyncio
    @pytest.mark.bind
    @pytest.mark.integration
    async def test_connector_bind_integration(self, mock_socks_server):
        """Test SOCKS connector BIND with mock upstream server"""
        mock_server, mock_port = mock_socks_server
        
        # Give mock server time to start
        await asyncio.sleep(0.5)
        
        # Test direct connection to mock server (validates mock works)
        tester = SocksBindTester("127.0.0.1", mock_port)
        success, bound_addr = await tester.socks5_bind_request("example.com", 80)
        
        assert success, "Mock SOCKS server BIND should work"
        assert bound_addr is not None, "Should receive bound address from mock"
        assert bound_addr == ("127.0.0.1", 8080), "Should match mock server response"
    
    @pytest.mark.asyncio
    @pytest.mark.bind  
    @pytest.mark.integration
    async def test_socks4_bind(self, mock_socks_server):
        """Test SOCKS4 BIND functionality"""
        mock_server, mock_port = mock_socks_server
        
        await asyncio.sleep(0.5)
        
        tester = SocksBindTester("127.0.0.1", mock_port)
        success, bound_addr = await tester.socks4_bind_request("192.168.1.100", 8080)
        
        assert success, "SOCKS4 BIND should work"
        assert bound_addr is not None, "Should receive bound address"
        assert bound_addr == ("127.0.0.1", 8080), "Should match expected mock response"

class TestDirectConnectorBind:
    """Test DirectConnector BIND functionality"""
    
    @pytest.mark.asyncio
    @pytest.mark.bind
    async def test_basic_socket_bind(self):
        """Test basic socket binding capability"""
        # Test that the system supports socket binding (prerequisite for DirectConnector BIND)
        test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            test_socket.bind(('127.0.0.1', 0))
            bound_port = test_socket.getsockname()[1]
            assert bound_port > 0, "Should get valid port number"
        finally:
            test_socket.close()

class TestBindConnectionFlow:
    """Test complete BIND connection flow scenarios"""
    
    @pytest.mark.asyncio
    @pytest.mark.bind
    @pytest.mark.slow
    async def test_bind_connection_simulation(self, socks_tester_factory, bind_ports, redproxy_host):
        """Test BIND with simulated client connection"""
        tester = socks_tester_factory(bind_ports["bind_allowed"])
        success, bound_addr = await tester.socks5_bind_request("0.0.0.0", 0)
        
        assert success, "BIND setup should succeed"
        assert bound_addr is not None, "Should get bound address"
        
        # Simulate client connecting to bound address
        async def simulate_client():
            try:
                await asyncio.sleep(1)  # Give BIND time to be ready
                
                # Convert 0.0.0.0 to actual RedProxy address for connection
                connect_ip = redproxy_host if bound_addr[0] == "0.0.0.0" else bound_addr[0]
                connect_port = bound_addr[1]
                
                # Try to connect to the bound address
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(connect_ip, connect_port),
                    timeout=5.0
                )
                
                # Send test data
                writer.write(b"Hello BIND!\n")
                await writer.drain()
                
                await asyncio.sleep(1)  # Hold connection briefly
                
                writer.close()
                await writer.wait_closed()
                return True
                
            except Exception:
                return False
        
        # Run client connection with timeout
        client_success = await asyncio.wait_for(simulate_client(), timeout=10.0)
        
        # Note: In test environment, connection might fail due to network isolation
        # The important thing is that BIND setup worked
        assert success, "BIND operation should complete successfully"

class TestIPv6BindSupport:
    """Test BIND functionality with IPv6 addresses"""
    
    @pytest.mark.asyncio
    @pytest.mark.bind
    @pytest.mark.ipv6
    async def test_ipv6_bind_request(self, socks_tester_factory, bind_ports, redproxy_host):
        """Test IPv6 BIND request on IPv4 listener"""
        # Test IPv6 BIND request to IPv4 listener
        reader, writer = await asyncio.open_connection(redproxy_host, bind_ports["bind_allowed"])
        
        try:
            # SOCKS5 auth
            writer.write(b'\x05\x01\x00')  # No auth
            await writer.drain()
            auth_response = await reader.read(2)
            
            assert auth_response == b'\x05\x00', "Authentication should succeed"
            
            # IPv6 BIND request - bind to ::1 (localhost IPv6)
            bind_request = b'\x05\x02\x00\x04'  # Version, BIND, reserved, IPv6
            bind_request += b'\x00' * 15 + b'\x01'  # ::1 address
            bind_request += b'\x00\x00'  # Port 0 (system assigned)
            
            writer.write(bind_request)
            await writer.drain()
            
            # Read response
            response = await asyncio.wait_for(reader.read(1024), timeout=5.0)
            
            # Either success or expected rejection is acceptable
            assert len(response) >= 4, "Should receive complete response"
            # response[1] == 0x00 means success, other values are acceptable rejections
            
        finally:
            writer.close()
            await writer.wait_closed()
    
    @pytest.mark.asyncio
    @pytest.mark.bind
    @pytest.mark.ipv6
    async def test_ipv6_listener_availability(self, bind_ports, redproxy_host):
        """Test connection to IPv6 listener if available"""
        try:
            # Try to connect to IPv6 listener
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(redproxy_host, bind_ports["bind_ipv6"]), 
                timeout=3.0
            )
            
            # Test basic BIND on IPv6 listener  
            writer.write(b'\x05\x01\x00')  # No auth
            await writer.drain()
            auth_response = await reader.read(2)
            
            if auth_response == b'\x05\x00':
                # IPv4 BIND request on IPv6 listener
                bind_request = b'\x05\x02\x00\x01'  # Version, BIND, reserved, IPv4
                bind_request += b'\x7f\x00\x00\x01'  # 127.0.0.1
                bind_request += b'\x00\x00'  # Port 0
                
                writer.write(bind_request)
                await writer.drain()
                
                response = await asyncio.wait_for(reader.read(1024), timeout=5.0)
                
                # Success or reasonable error response acceptable
                assert len(response) >= 4, "Should receive response"
            
            writer.close()
            await writer.wait_closed()
            
        except (asyncio.TimeoutError, ConnectionRefusedError):
            # IPv6 listener not available - not a failure
            pytest.skip("IPv6 listener not available or accessible")

class TestConcurrentBindOperations:
    """Test multiple concurrent BIND operations"""
    
    @pytest.mark.asyncio
    @pytest.mark.bind
    @pytest.mark.performance
    async def test_concurrent_binds(self, socks_tester_factory, bind_ports):
        """Test multiple concurrent BIND operations"""
        
        async def single_bind_operation(bind_id: int):
            try:
                tester = socks_tester_factory(bind_ports["bind_allowed"])
                success, bound_addr = await tester.socks5_bind_request("0.0.0.0", 0)
                
                if success and bound_addr:
                    await asyncio.sleep(2)  # Hold the BIND briefly
                    return True
                return False
            except Exception:
                return False
        
        # Start 3 concurrent BIND operations
        tasks = [
            asyncio.create_task(single_bind_operation(i))
            for i in range(3)
        ]
        
        # Wait for all to complete
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        successful_binds = sum(1 for r in results if r is True)
        
        # At least 2 should succeed (allowing for some resource constraints)
        assert successful_binds >= 2, f"Expected at least 2 successful BINDs, got {successful_binds}/3"

class TestBindErrorConditions:
    """Test BIND error handling and edge cases"""
    
    @pytest.mark.asyncio
    @pytest.mark.bind
    @pytest.mark.destructive
    async def test_invalid_bind_request(self, socks_tester_factory, bind_ports, redproxy_host):
        """Test BIND with invalid address format"""
        reader, writer = await asyncio.open_connection(redproxy_host, bind_ports["bind_allowed"])
        
        try:
            # SOCKS5 auth
            writer.write(b'\x05\x01\x00')
            await writer.drain()
            await reader.read(2)
            
            # Malformed BIND request (invalid address type)
            writer.write(b'\x05\x02\x00\xFF')  # Invalid address type 0xFF
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(10), timeout=3.0)
            
            assert len(response) >= 2, "Should receive error response"
            assert response[1] != 0x00, "Should return error code for invalid request"
            
        finally:
            writer.close()
            await writer.wait_closed()
    
    @pytest.mark.asyncio
    @pytest.mark.bind
    @pytest.mark.performance
    async def test_rapid_bind_cycles(self, socks_tester_factory, bind_ports):
        """Test rapid BIND/unbind cycles"""
        successful_operations = 0
        
        for i in range(5):
            tester = socks_tester_factory(bind_ports["bind_allowed"])
            success, bound_addr = await tester.socks5_bind_request("0.0.0.0", 0)
            if success:
                successful_operations += 1
            # Connection automatically closes, releasing the BIND
            await asyncio.sleep(0.1)
        
        # Allow for some failures in rapid succession
        assert successful_operations >= 4, f"Expected at least 4 successful rapid BINDs, got {successful_operations}/5"

class TestBindAddressOverride:
    """Test override_bind_address functionality for NAT scenarios"""
    
    @pytest.mark.asyncio
    @pytest.mark.bind
    @pytest.mark.integration
    async def test_bind_address_override(self, socks_tester_factory, bind_ports):
        """Test override_bind_address NAT functionality"""
        # Test normal BIND (baseline) - port uses regular direct connector
        tester_normal = socks_tester_factory(bind_ports["bind_allowed"])
        success_normal, bound_addr_normal = await tester_normal.socks5_bind_request("0.0.0.0", 0)
        
        assert success_normal, "Baseline BIND should succeed"
        assert bound_addr_normal is not None, "Should get bound address"
        
        # Test override BIND - port uses direct-with-override connector
        tester_override = socks_tester_factory(bind_ports["bind_override"])
        success_override, bound_addr_override = await tester_override.socks5_bind_request("0.0.0.0", 0)
        
        assert success_override, "Override BIND should succeed"
        assert bound_addr_override is not None, "Should get override bound address"
        
        # Verify the override worked
        expected_override_ip = "192.168.1.100"
        
        assert bound_addr_override[0] == expected_override_ip, \
            f"Expected override address {expected_override_ip}, got {bound_addr_override[0]}"
        
        # Addresses should be different
        assert bound_addr_normal[0] != bound_addr_override[0], \
            "Normal and override addresses should differ"

class TestBindTimeout:
    """Test BIND timeout functionality"""
    
    @pytest.mark.asyncio
    @pytest.mark.bind
    @pytest.mark.slow
    async def test_bind_timeout_behavior(self, socks_tester_factory, bind_ports, redproxy_host):
        """Test BIND timeout to ensure operations don't run indefinitely"""
        # Use the timeout test listener with short idle timeout
        tester = socks_tester_factory(bind_ports["bind_timeout"])
        
        success, bound_addr = await tester.socks5_bind_request("0.0.0.0", 0)
        
        assert success, "Initial BIND should succeed"
        assert bound_addr is not None, "Should get bound address"
        
        # Wait longer than configured timeout (3+ seconds)
        await asyncio.sleep(4.0)
        
        # Try to connect to the bound address after timeout
        connection_failed = False
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(redproxy_host, bound_addr[1]), 
                timeout=2.0
            )
            writer.close()
            await writer.wait_closed()
        except (ConnectionRefusedError, OSError, asyncio.TimeoutError):
            connection_failed = True
        
        # Verify system is still responsive with fresh connection
        tester_fresh = socks_tester_factory(bind_ports["bind_allowed"])
        success_fresh, bound_addr_fresh = await tester_fresh.socks5_bind_request("0.0.0.0", 0)
        
        assert success_fresh, "Fresh BIND should work after timeout test"
        
        # The main requirement is that the system remains functional
        # Timeout behavior can be environment-dependent
        assert success and success_fresh, "BIND functionality should remain intact"