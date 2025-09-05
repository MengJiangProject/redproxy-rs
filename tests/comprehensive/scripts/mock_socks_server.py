#!/usr/bin/env python3
"""
Standalone Mock SOCKS Server for BIND testing
Supports SOCKS4 and SOCKS5 BIND commands for testing RedProxy SOCKS connector
"""

import asyncio
import socket
import struct
import signal
import sys
from typing import Optional

class MockSocksServer:
    """Mock SOCKS server that handles BIND commands for testing"""
    
    def __init__(self, host: str = "0.0.0.0", port: int = 1080):
        self.host = host
        self.port = port
        self.server = None
        self.running = True
    
    async def start(self):
        """Start the mock SOCKS server"""
        print(f"Starting mock SOCKS server on {self.host}:{self.port}")
        
        async def handle_client(reader, writer):
            client_addr = writer.get_extra_info('peername')
            print(f"New client connection from {client_addr}")
            
            try:
                await self._handle_socks_session(reader, writer)
            except Exception as e:
                print(f"Error handling client {client_addr}: {e}")
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except:
                    pass
                print(f"Client {client_addr} disconnected")
        
        self.server = await asyncio.start_server(handle_client, self.host, self.port)
        print(f"Mock SOCKS server listening on {self.host}:{self.port}")
        
        # Keep running until shutdown
        while self.running:
            await asyncio.sleep(1)
    
    async def stop(self):
        """Stop the mock SOCKS server"""
        self.running = False
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            print("Mock SOCKS server stopped")
    
    async def _handle_socks_session(self, reader, writer):
        """Handle a SOCKS protocol session"""
        # Read version byte first
        version_data = await reader.read(1)
        if not version_data:
            print("No version data received")
            return
        
        version = version_data[0]
        print(f"SOCKS version: {version}")
        
        if version == 5:
            await self._handle_socks5(reader, writer)
        elif version == 4:
            await self._handle_socks4(reader, writer, version_data)
        else:
            print(f"Unsupported SOCKS version: {version}")
    
    async def _handle_socks5(self, reader, writer):
        """Handle SOCKS5 protocol"""
        print("Handling SOCKS5 session")
        
        # Read authentication methods
        auth_data = await reader.read(1)
        if not auth_data:
            return
        
        num_methods = auth_data[0]
        methods = await reader.read(num_methods)
        print(f"SOCKS5 auth methods: {[hex(m) for m in methods]}")
        
        # Accept no authentication (0x00)
        writer.write(b'\x05\x00')
        await writer.drain()
        print("SOCKS5 auth response sent: no auth required")
        
        # Read SOCKS5 request
        request_header = await reader.read(4)  # VER CMD RSV ATYP
        if len(request_header) < 4:
            print("Incomplete SOCKS5 request header")
            return
        
        version, cmd, reserved, addr_type = request_header
        print(f"SOCKS5 request: version={version}, cmd={cmd}, addr_type={addr_type}")
        
        # Read address based on type
        if addr_type == 0x01:  # IPv4
            addr_data = await reader.read(6)  # 4 bytes IP + 2 bytes port
            if len(addr_data) == 6:
                ip = socket.inet_ntoa(addr_data[:4])
                port = struct.unpack('>H', addr_data[4:6])[0]
                target = f"{ip}:{port}"
        elif addr_type == 0x03:  # Domain name
            domain_len_data = await reader.read(1)
            if not domain_len_data:
                return
            domain_len = domain_len_data[0]
            domain_and_port = await reader.read(domain_len + 2)
            if len(domain_and_port) == domain_len + 2:
                domain = domain_and_port[:domain_len].decode('utf-8')
                port = struct.unpack('>H', domain_and_port[domain_len:domain_len+2])[0]
                target = f"{domain}:{port}"
        elif addr_type == 0x04:  # IPv6
            addr_data = await reader.read(18)  # 16 bytes IP + 2 bytes port
            if len(addr_data) == 18:
                ip = socket.inet_ntop(socket.AF_INET6, addr_data[:16])
                port = struct.unpack('>H', addr_data[16:18])[0]
                target = f"[{ip}]:{port}"
        else:
            print(f"Unsupported address type: {addr_type}")
            # Send address type not supported error
            error_response = b'\x05\x08\x00\x01' + b'\x00' * 6
            writer.write(error_response)
            await writer.drain()
            return
        
        print(f"SOCKS5 target: {target}")
        
        if cmd == 0x02:  # BIND command
            await self._handle_socks5_bind(reader, writer, target)
        elif cmd == 0x01:  # CONNECT command
            await self._handle_socks5_connect(writer, target)
        else:
            print(f"Unsupported SOCKS5 command: {cmd}")
            # Send command not supported error
            error_response = b'\x05\x07\x00\x01' + b'\x00' * 6
            writer.write(error_response)
            await writer.drain()
    
    async def _handle_socks5_bind(self, reader, writer, target: str):
        """Handle SOCKS5 BIND command"""
        print(f"SOCKS5 BIND request for {target}")
        
        # Send first response with bound address
        response = b'\x05\x00\x00\x01'  # Version, success, reserved, IPv4
        response += socket.inet_aton('127.0.0.1')  # Mock bound IP
        response += struct.pack('>H', 8080)  # Mock bound port
        
        writer.write(response)
        await writer.drain()
        print("SOCKS5 BIND first response sent (bound address: 127.0.0.1:8080)")
        
        # Simulate waiting for connection
        await asyncio.sleep(1)
        
        # Send second response indicating peer connection
        peer_response = b'\x05\x00\x00\x01'  # Version, success, reserved, IPv4
        peer_response += socket.inet_aton('192.168.1.100')  # Mock peer IP
        peer_response += struct.pack('>H', 12345)  # Mock peer port
        
        writer.write(peer_response)
        await writer.drain()
        print("SOCKS5 BIND second response sent (peer: 192.168.1.100:12345)")
        
        # Keep connection open for a bit
        await asyncio.sleep(5)
    
    async def _handle_socks5_connect(self, writer, target: str):
        """Handle SOCKS5 CONNECT command (basic implementation)"""
        print(f"SOCKS5 CONNECT request for {target} (not fully implemented)")
        
        # Send success response for testing
        response = b'\x05\x00\x00\x01'  # Version, success, reserved, IPv4
        response += socket.inet_aton('127.0.0.1')  # Mock server IP
        response += struct.pack('>H', 80)  # Mock server port
        
        writer.write(response)
        await writer.drain()
        print("SOCKS5 CONNECT response sent")
    
    async def _handle_socks4(self, reader, writer, first_byte):
        """Handle SOCKS4 protocol"""
        print("Handling SOCKS4 session")
        
        # Read rest of SOCKS4 request: CMD(1) + PORT(2) + IP(4)
        request_data = await reader.read(7)
        if len(request_data) < 7:
            print("Incomplete SOCKS4 request")
            return
        
        cmd = request_data[0]
        port = struct.unpack('>H', request_data[1:3])[0]
        ip = socket.inet_ntoa(request_data[3:7])
        
        # Read user ID (null terminated)
        user_id = b''
        while True:
            byte = await reader.read(1)
            if not byte or byte == b'\x00':
                break
            user_id += byte
        
        print(f"SOCKS4 request: cmd={cmd}, target={ip}:{port}, user_id={user_id.decode('utf-8', errors='ignore')}")
        
        if cmd == 0x02:  # BIND command
            await self._handle_socks4_bind(reader, writer, ip, port)
        elif cmd == 0x01:  # CONNECT command
            await self._handle_socks4_connect(writer, ip, port)
        else:
            print(f"Unsupported SOCKS4 command: {cmd}")
            # Send request rejected
            response = b'\x00\x5b' + b'\x00' * 6
            writer.write(response)
            await writer.drain()
    
    async def _handle_socks4_bind(self, reader, writer, target_ip: str, target_port: int):
        """Handle SOCKS4 BIND command"""
        print(f"SOCKS4 BIND request for {target_ip}:{target_port}")
        
        # Send first response with bound address
        response = b'\x00\x5a'  # VN=0, CD=0x5a (request granted)
        response += struct.pack('>H', 8080)  # Mock bound port
        response += socket.inet_aton('127.0.0.1')  # Mock bound IP
        
        writer.write(response)
        await writer.drain()
        print("SOCKS4 BIND first response sent (bound address: 127.0.0.1:8080)")
        
        # Simulate waiting for connection
        await asyncio.sleep(1)
        
        # Send second response indicating peer connection
        peer_response = b'\x00\x5a'  # VN=0, CD=0x5a (connection established)
        peer_response += struct.pack('>H', 12345)  # Mock peer port
        peer_response += socket.inet_aton('192.168.1.100')  # Mock peer IP
        
        writer.write(peer_response)
        await writer.drain()
        print("SOCKS4 BIND second response sent (peer: 192.168.1.100:12345)")
        
        # Keep connection open for a bit
        await asyncio.sleep(5)
    
    async def _handle_socks4_connect(self, writer, target_ip: str, target_port: int):
        """Handle SOCKS4 CONNECT command (basic implementation)"""
        print(f"SOCKS4 CONNECT request for {target_ip}:{target_port} (not fully implemented)")
        
        # Send success response
        response = b'\x00\x5a'  # VN=0, CD=0x5a (request granted)
        response += struct.pack('>H', target_port)
        response += socket.inet_aton(target_ip)
        
        writer.write(response)
        await writer.drain()
        print("SOCKS4 CONNECT response sent")


async def main():
    """Main server function"""
    server = MockSocksServer()
    
    # Set up signal handlers for graceful shutdown
    def signal_handler():
        print("\nReceived shutdown signal, stopping server...")
        asyncio.create_task(server.stop())
    
    # Handle SIGTERM and SIGINT
    for sig in [signal.SIGTERM, signal.SIGINT]:
        signal.signal(sig, lambda s, f: signal_handler())
    
    try:
        await server.start()
    except KeyboardInterrupt:
        print("\nKeyboard interrupt received, stopping server...")
    except Exception as e:
        print(f"Server error: {e}")
    finally:
        await server.stop()


if __name__ == "__main__":
    print("Mock SOCKS Server for BIND Testing")
    print("Supports SOCKS4 and SOCKS5 BIND commands")
    print("Press Ctrl+C to stop")
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nServer stopped by user")
    except Exception as e:
        print(f"Server failed: {e}")
        sys.exit(1)