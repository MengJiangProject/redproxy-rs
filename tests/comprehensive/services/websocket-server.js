const http = require('http');
const url = require('url');

const server = http.createServer((req, res) => {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(200);
    res.end();
    return;
  }

  const parsedUrl = url.parse(req.url, true);
  
  if (req.method === 'GET') {
    if (parsedUrl.pathname === '/') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(`
<!DOCTYPE html>
<html>
<head>
    <title>WebSocket Test Server</title>
</head>
<body>
    <h1>WebSocket Test Server</h1>
    <p>This server supports WebSocket upgrades and HTTP requests.</p>
    <p>Status: Running</p>
    <p>Server: Node.js HTTP Server</p>
    <p>Port: 8080</p>
    <script>
        // WebSocket connection test
        if (window.WebSocket) {
            console.log('WebSocket support detected');
        }
    </script>
</body>
</html>
      `);
    } else if (parsedUrl.pathname === '/api/status') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        status: 'running',
        server: 'websocket-test-server',
        timestamp: new Date().toISOString(),
        websocket_support: true
      }));
    } else {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not Found');
    }
  } else {
    res.writeHead(405, { 'Content-Type': 'text/plain' });
    res.end('Method Not Allowed');
  }
});

// Handle WebSocket upgrades
server.on('upgrade', (request, socket, head) => {
  console.log('WebSocket upgrade requested');
  
  // Simple WebSocket handshake
  const key = request.headers['sec-websocket-key'];
  const acceptKey = require('crypto')
    .createHash('sha1')
    .update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')
    .digest('base64');

  const responseHeaders = [
    'HTTP/1.1 101 Switching Protocols',
    'Upgrade: websocket',
    'Connection: Upgrade',
    `Sec-WebSocket-Accept: ${acceptKey}`,
    '', ''
  ].join('\r\n');

  socket.write(responseHeaders);
  
  // Handle WebSocket messages
  socket.on('data', (data) => {
    console.log('WebSocket data received:', data.toString());
    // Echo the data back
    socket.write(data);
  });
  
  socket.on('error', (err) => {
    console.error('WebSocket error:', err);
  });
  
  socket.on('close', () => {
    console.log('WebSocket connection closed');
  });
});

const PORT = process.env.PORT || 8080;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`WebSocket test server running on port ${PORT}`);
  console.log('Supports HTTP requests and WebSocket upgrades');
});