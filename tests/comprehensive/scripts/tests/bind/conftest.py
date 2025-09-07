"""
BIND test suite pytest fixtures
Provides common setup for SOCKS BIND functionality testing
"""
import asyncio
import socket
import struct
import pytest
import pytest_asyncio
from typing import Tuple, Optional, Dict, Any

@pytest.fixture
def redproxy_host():
    """RedProxy service hostname in Docker network"""
    return "redproxy"

@pytest.fixture
def bind_ports():
    """SOCKS listener ports configured for BIND testing"""
    return {
        "bind_allowed": 1081,       # allow_bind=true, enforce_bind_address=false
        "bind_denied": 1082,        # allow_bind=false
        "bind_enforce": 1083,       # allow_bind=true, enforce_bind_address=true
        "bind_ipv6": 1084,         # IPv6 listener
        "bind_override": 1085,      # with override_bind_address
        "bind_timeout": 1086,       # with short timeout
    }

@pytest_asyncio.fixture
async def mock_socks_server():
    """Mock SOCKS server for testing connector BIND functionality"""
    server = MockSocksServer()
    port = await server.start()
    yield server, port
    await server.stop()

class SocksBindTester:
    """Helper class for SOCKS BIND protocol testing"""
    
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
    
    async def socks5_bind_request(self, target_host: str, target_port: int) -> Tuple[bool, Optional[Tuple[str, int]]]:
        """Perform SOCKS5 BIND request and return success status and bound address"""
        try:
            # Connect to SOCKS5 proxy
            reader, writer = await asyncio.open_connection(self.host, self.port)
            
            try:
                # SOCKS5 authentication negotiation
                auth_request = b'\x05\x01\x00'  # Version 5, 1 method, no auth
                writer.write(auth_request)
                await writer.drain()
                
                auth_response = await reader.read(2)
                if len(auth_response) != 2 or auth_response != b'\x05\x00':
                    return False, None
                
                # SOCKS5 BIND request
                bind_request = bytearray([0x05, 0x02, 0x00])  # Version, BIND command, reserved
                
                if target_host.replace('.', '').isdigit():
                    # IPv4 address
                    bind_request.append(0x01)  # IPv4 address type
                    bind_request.extend(socket.inet_aton(target_host))
                else:
                    # Domain name
                    bind_request.append(0x03)  # Domain name type
                    bind_request.append(len(target_host))
                    bind_request.extend(target_host.encode())
                
                bind_request.extend(struct.pack('>H', target_port))  # Port in network byte order
                
                writer.write(bind_request)
                await writer.drain()
                
                # Read BIND response (first response with bound address)
                response = await reader.read(1024)
                if len(response) < 6:
                    return False, None
                
                if response[0] != 0x05 or response[1] != 0x00:
                    return False, None
                
                # Parse bound address from response
                addr_type = response[3]
                if addr_type == 0x01:  # IPv4
                    if len(response) < 10:
                        return False, None
                    bound_ip = socket.inet_ntoa(response[4:8])
                    bound_port = struct.unpack('>H', response[8:10])[0]
                elif addr_type == 0x03:  # Domain name
                    domain_len = response[4]
                    if len(response) < 5 + domain_len + 2:
                        return False, None
                    bound_ip = response[5:5+domain_len].decode()
                    bound_port = struct.unpack('>H', response[5+domain_len:7+domain_len])[0]
                else:
                    return False, None
                
                return True, (bound_ip, bound_port)
                
            finally:
                writer.close()
                await writer.wait_closed()
                
        except Exception:
            return False, None
    
    async def socks4_bind_request(self, target_ip: str, target_port: int) -> Tuple[bool, Optional[Tuple[str, int]]]:
        """Perform SOCKS4 BIND request and return success status and bound address"""
        try:
            # Connect to SOCKS proxy
            reader, writer = await asyncio.open_connection(self.host, self.port)
            
            try:
                # SOCKS4 BIND request
                bind_request = bytearray([0x04, 0x02])  # Version 4, BIND command
                bind_request.extend(struct.pack('>H', target_port))  # Port
                bind_request.extend(socket.inet_aton(target_ip))  # IP address
                bind_request.append(0x00)  # Empty user ID
                
                writer.write(bind_request)
                await writer.drain()
                
                # Read BIND response
                response = await reader.read(8)
                if len(response) != 8:
                    return False, None
                
                if response[0] != 0x00 or response[1] != 0x5a:  # Request granted
                    return False, None
                
                # Parse bound address
                bound_port = struct.unpack('>H', response[2:4])[0]
                bound_ip = socket.inet_ntoa(response[4:8])
                
                return True, (bound_ip, bound_port)
                
            finally:
                writer.close()
                await writer.wait_closed()
                
        except Exception:
            return False, None

@pytest.fixture
def socks_tester_factory(redproxy_host):
    """Factory for creating SocksBindTester instances"""
    def _create_tester(port: int) -> SocksBindTester:
        return SocksBindTester(redproxy_host, port)
    return _create_tester

class MockSocksServer:
    """Mock SOCKS server for testing SOCKS connector BIND functionality"""
    
    def __init__(self, host: str = "0.0.0.0", port: int = 0):
        self.host = host
        self.port = port
        self.server = None
        self.actual_port = None
        self._client_tasks = set()
    
    async def start(self) -> int:
        """Start mock SOCKS server"""
        async def handle_client(reader, writer):
            task = None
            try:
                task = asyncio.current_task()
                self._client_tasks.add(task)
                await self._handle_socks_session(reader, writer)
            except Exception:
                pass
            finally:
                writer.close()
                await writer.wait_closed()
                if task and task in self._client_tasks:
                    self._client_tasks.discard(task)
        
        self.server = await asyncio.start_server(handle_client, self.host, self.port)
        self.actual_port = self.server.sockets[0].getsockname()[1]
        return self.actual_port
    
    async def _handle_socks_session(self, reader, writer):
        """Handle SOCKS protocol session"""
        version_data = await reader.read(1)
        if not version_data:
            return
        
        version = version_data[0]
        
        if version == 5:
            await self._handle_socks5(reader, writer, version_data)
        elif version == 4:
            await self._handle_socks4(reader, writer, version_data)
    
    async def _handle_socks5(self, reader, writer, first_byte):
        """Handle SOCKS5 protocol"""
        # Read rest of auth request
        auth_data = await reader.read(1)
        if not auth_data:
            return
        
        num_methods = auth_data[0]
        methods = await reader.read(num_methods)
        
        # Accept no auth
        writer.write(b'\x05\x00')
        await writer.drain()
        
        # Read BIND request
        request = await reader.read(4)  # VER CMD RSV ATYP
        if len(request) < 4 or request[1] != 0x02:  # Not BIND
            writer.write(b'\x05\x07' + b'\x00' * 8)  # Command not supported
            await writer.drain()
            return
        
        addr_type = request[3]
        if addr_type == 0x01:  # IPv4
            addr_data = await reader.read(6)  # 4 bytes IP + 2 bytes port
        elif addr_type == 0x03:  # Domain
            domain_len = (await reader.read(1))[0]
            addr_data = await reader.read(domain_len + 2)  # domain + port
        else:
            writer.write(b'\x05\x08' + b'\x00' * 8)  # Address type not supported
            await writer.drain()
            return
        
        # Send successful BIND response with mock bound address
        response = b'\x05\x00\x00\x01'  # Version, success, reserved, IPv4
        response += socket.inet_aton('127.0.0.1')  # Mock bound IP
        response += struct.pack('>H', 8080)  # Mock bound port
        
        writer.write(response)
        await writer.drain()
        
        # Simulate waiting for connection (send second response after delay)
        await asyncio.sleep(1)
        
        # Send second response indicating connection from peer
        peer_response = b'\x05\x00\x00\x01'  # Version, success, reserved, IPv4
        peer_response += socket.inet_aton('192.168.1.100')  # Mock peer IP
        peer_response += struct.pack('>H', 12345)  # Mock peer port
        
        writer.write(peer_response)
        await writer.drain()
    
    async def _handle_socks4(self, reader, writer, first_byte):
        """Handle SOCKS4 protocol"""
        # Read rest of SOCKS4 request
        request_data = await reader.read(7)  # CMD(1) + PORT(2) + IP(4)
        if len(request_data) < 7 or request_data[0] != 0x02:  # Not BIND
            response = b'\x00\x5b' + b'\x00' * 6  # Request rejected
            writer.write(response)
            await writer.drain()
            return
        
        # Read user ID (null terminated)
        while True:
            byte = await reader.read(1)
            if not byte or byte == b'\x00':
                break
        
        # Send successful BIND response
        response = b'\x00\x5a'  # VN, CD (success)
        response += struct.pack('>H', 8080)  # Mock bound port
        response += socket.inet_aton('127.0.0.1')  # Mock bound IP
        
        writer.write(response)
        await writer.drain()
        
        # Simulate connection from peer
        await asyncio.sleep(1)
        
        peer_response = b'\x00\x5a'  # VN, CD (success)
        peer_response += struct.pack('>H', 12345)  # Mock peer port
        peer_response += socket.inet_aton('192.168.1.100')  # Mock peer IP
        
        writer.write(peer_response)
        await writer.drain()
    
    async def stop(self):
        """Stop mock SOCKS server with proper cleanup"""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            
            # Cancel any remaining client tasks
            if self._client_tasks:
                for task in self._client_tasks:
                    if not task.done():
                        task.cancel()
                
                # Wait for cancelled tasks to complete
                await asyncio.gather(*self._client_tasks, return_exceptions=True)
                self._client_tasks.clear()