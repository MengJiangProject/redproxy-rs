#!/usr/bin/env python3
"""
WebSocket Test Server for RedProxy comprehensive tests
Provides HTTP endpoints and WebSocket echo functionality for testing
"""

import asyncio
import json
import logging
import os
import signal
import sys
from datetime import datetime
from typing import Optional

import aiohttp
from aiohttp import web, WSMsgType


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('websocket-server')


class WebSocketTestServer:
    """WebSocket test server with HTTP and WebSocket endpoints"""
    
    def __init__(self, port: int = 9998):
        self.port = port
        self.app = web.Application()
        self.connected_clients = set()
        self.setup_routes()
        
    def setup_routes(self):
        """Setup HTTP and WebSocket routes"""
        # Specific routes first (order matters in aiohttp)
        self.app.router.add_get('/', self.handle_root)  
        self.app.router.add_get('/info', self.handle_info)
        self.app.router.add_get('/health', self.handle_health)
        self.app.router.add_get('/ws', self.handle_websocket)
        
        # HTTP test endpoints for chunked encoding and other tests (BEFORE catch-all)
        self.app.router.add_get('/chunked', self.handle_chunked_get)
        self.app.router.add_post('/chunked', self.handle_chunked_post)
        self.app.router.add_post('/malformed_chunked', self.handle_malformed_chunked)
        self.app.router.add_get('/large', self.handle_large)
        self.app.router.add_get('/error', self.handle_error)
        self.app.router.add_get('/malformed', self.handle_malformed)
        self.app.router.add_post('/100-continue', self.handle_100_continue)
        
        # Catch-all for other test paths (MUST BE LAST)
        self.app.router.add_route('*', '/{path:.*}', self.handle_generic)
        
    async def handle_root(self, request):
        """Root endpoint with server information"""
        return web.json_response({
            'message': 'WebSocket Test Server with HTTP Test Endpoints',
            'server': 'aiohttp + Python',
            'capabilities': ['websocket', 'http_testing', 'chunked_encoding'],
            'endpoints': {
                'http_root': '/',
                'info': '/info',
                'health': '/health',
                'websocket': '/ws',
                'chunked_get': '/chunked',
                'chunked_post': '/chunked',
                'malformed_chunked': '/malformed_chunked', 
                'large_response': '/large',
                'error_response': '/error',
                'malformed_response': '/malformed',
                'continue_handling': '/100-continue'
            },
            'websocket_url': f'ws://localhost:{self.port}/ws',
            'description': 'Merged WebSocket server with HTTP test server functionality for comprehensive proxy testing'
        })
    
    async def handle_info(self, request):
        """Server information endpoint"""
        logger.info(f"Info request from {request.remote}")
        return web.json_response({
            'server': 'WebSocket Test Server',
            'implementation': 'aiohttp + Python',
            'websocket_support': True,
            'connected_clients': len(self.connected_clients),
            'port': self.port,
            'timestamp': datetime.now().isoformat()
        })
    
    async def handle_health(self, request):
        """Health check endpoint"""
        logger.info(f"Health check from {request.remote}")
        return web.json_response({
            'status': 'healthy',
            'timestamp': datetime.now().isoformat()
        })
    
    async def handle_websocket(self, request):
        """WebSocket connection handler"""
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        
        # Add to connected clients
        self.connected_clients.add(ws)
        client_ip = request.remote
        logger.info(f"New WebSocket connection from {client_ip}")
        
        # Send welcome message
        await ws.send_str(json.dumps({
            'type': 'welcome',
            'message': 'Connected to WebSocket test server',
            'server': 'aiohttp + Python',
            'timestamp': datetime.now().isoformat()
        }))
        
        try:
            async for msg in ws:
                if msg.type == WSMsgType.TEXT:
                    try:
                        # Try to parse as JSON
                        data = json.loads(msg.data)
                        logger.info(f"Received JSON: {data}")
                        
                        # Handle special commands
                        if isinstance(data, dict) and 'command' in data:
                            await self.handle_command(ws, data)
                        else:
                            # Echo the message back
                            await ws.send_str(json.dumps({
                                'type': 'echo',
                                'original': data,
                                'timestamp': datetime.now().isoformat()
                            }))
                            
                    except json.JSONDecodeError:
                        # Handle plain text messages
                        logger.info(f"Received text: {msg.data}")
                        await ws.send_str(f"Echo: {msg.data}")
                        
                elif msg.type == WSMsgType.ERROR:
                    logger.error(f"WebSocket error: {ws.exception()}")
                    break
                    
        except Exception as e:
            logger.error(f"WebSocket handler error: {e}")
        finally:
            # Remove from connected clients
            self.connected_clients.discard(ws)
            logger.info(f"WebSocket connection from {client_ip} closed")
            
        return ws
    
    async def handle_command(self, ws, data):
        """Handle special WebSocket commands"""
        command = data.get('command')
        
        if command == 'ping':
            await ws.send_str(json.dumps({
                'type': 'pong',
                'timestamp': datetime.now().isoformat()
            }))
            
        elif command == 'echo':
            # Echo back the entire message
            await ws.send_str(json.dumps({
                'type': 'echo',
                'original': data,
                'timestamp': datetime.now().isoformat()
            }))
            
        elif command == 'close':
            await ws.send_str(json.dumps({
                'type': 'closing',
                'message': 'Close requested by client'
            }))
            await ws.close(code=1000, message=b'Close requested by client')
            
        elif command == 'error':
            await ws.close(code=1002, message=b'Test error condition')
            
        elif command == 'info':
            await ws.send_str(json.dumps({
                'type': 'info',
                'connected_clients': len(self.connected_clients),
                'server': 'WebSocket Test Server (Python)',
                'timestamp': datetime.now().isoformat()
            }))
            
        else:
            await ws.send_str(json.dumps({
                'type': 'error',
                'message': f'Unknown command: {command}',
                'available_commands': ['ping', 'echo', 'close', 'error', 'info']
            }))
    
    # HTTP Test Server handlers (merged from servers.py)
    
    async def handle_chunked_get(self, request):
        """Send a chunked response - for chunked encoding tests"""
        logger.info("Serving chunked GET response")
        
        response = web.StreamResponse()
        response.headers['Transfer-Encoding'] = 'chunked'
        response.headers['Content-Type'] = 'text/plain'
        await response.prepare(request)
        
        # Send data in chunks - aiohttp will handle the chunked encoding format
        chunks = [b"Hello ", b"chunked ", b"world!"]
        for chunk in chunks:
            await response.write(chunk)
        
        await response.write_eof()
        return response
    
    async def handle_chunked_post(self, request):
        """Handle chunked POST request - echo back the data"""
        logger.info("Handling chunked POST request")
        
        # Read the chunked request body
        body = await request.read()
        logger.info(f"Received {len(body)} bytes in chunked POST")
        
        return web.Response(
            text=f"Received chunked POST: {len(body)} bytes",
            status=200,
            headers={'Content-Type': 'text/plain'}
        )
    
    async def handle_malformed_chunked(self, request):
        """Handle malformed chunked request - return error"""
        logger.info("Handling malformed chunked request")
        
        # Read any body data
        try:
            body = await request.read()
            logger.info(f"Received malformed chunked request: {len(body)} bytes")
        except Exception as e:
            logger.info(f"Error reading malformed chunked body: {e}")
        
        return web.Response(
            text="Bad Request: Malformed chunked encoding",
            status=400,
            headers={'Content-Type': 'text/plain'}
        )
    
    async def handle_large(self, request):
        """Send a large response"""
        logger.info(f"Serving large response for {request.method} {request.path}")
        body = "X" * 100000  # 100KB
        return web.Response(
            text=body,
            status=200,
            headers={'Content-Type': 'text/plain'}
        )
    
    async def handle_error(self, request):
        """Send an error response"""
        logger.info(f"Serving error response for {request.method} {request.path}")
        return web.Response(
            text="Server Error",
            status=500,
            headers={'Content-Type': 'text/plain'}
        )
    
    async def handle_malformed(self, request):
        """Send a malformed response"""
        logger.info(f"Serving malformed response for {request.method} {request.path}")
        # Return a response that's technically valid but unusual
        return web.Response(
            text="INVALID HTTP RESPONSE",
            status=200,
            headers={'Content-Type': 'text/plain', 'X-Malformed': 'true'}
        )
    
    async def handle_100_continue(self, request):
        """Handle 100-continue requests"""
        logger.info("Handling 100-continue request")
        
        # aiohttp handles 100-continue automatically, so just return response
        body = await request.read()
        return web.Response(
            text=f"Received body: {len(body)} bytes",
            status=200,
            headers={'Content-Type': 'text/plain'}
        )
    
    async def handle_generic(self, request):
        """Generic handler for any other paths"""
        path = request.path
        method = request.method
        logger.info(f"Generic handler: {method} {path}")
        
        return web.json_response({
            'message': 'Generic test endpoint',
            'method': method,
            'path': path,
            'server': 'WebSocket Test Server with HTTP endpoints',
            'timestamp': datetime.now().isoformat()
        })
    
    async def start_server(self):
        """Start the server"""
        runner = web.AppRunner(self.app)
        await runner.setup()
        
        site = web.TCPSite(runner, '0.0.0.0', self.port)
        await site.start()
        
        logger.info(f"WebSocket test server started on port {self.port}")
        logger.info(f"HTTP: http://localhost:{self.port}")
        logger.info(f"WebSocket: ws://localhost:{self.port}/ws")
        
        return runner


async def main():
    """Main server function"""
    port = int(os.getenv('PORT', '9998'))
    server = WebSocketTestServer(port)
    
    # Start server
    runner = await server.start_server()
    
    # Setup graceful shutdown
    def signal_handler():
        logger.info("Received shutdown signal")
        asyncio.create_task(runner.cleanup())
    
    # Handle shutdown signals
    for sig in (signal.SIGTERM, signal.SIGINT):
        asyncio.get_event_loop().add_signal_handler(sig, signal_handler)
    
    try:
        # Keep server running
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        await runner.cleanup()


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Server stopped")
        sys.exit(0)