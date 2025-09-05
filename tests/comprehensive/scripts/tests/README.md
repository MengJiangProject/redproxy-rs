# RedProxy Test Structure

## Directory Tree

```
tests/
├── httpx/              # HTTP/HTTPS listener tests
│   ├── test_connect.py       # CONNECT tunneling
│   ├── test_forward.py       # Forward proxy
│   ├── test_keepalive.py     # Keep-alive connections
│   ├── test_continue.py      # HTTP 100 Continue
│   ├── test_chunked.py       # Chunked encoding
│   ├── test_websocket.py     # WebSocket upgrade
│   └── test_destructive.py   # Error handling
├── socks/              # SOCKS listener tests
│   ├── test_socks4.py        # SOCKS4 protocol
│   ├── test_socks5.py        # SOCKS5 protocol
│   └── test_auth.py          # SOCKS authentication
├── quic/               # QUIC listener tests
│   ├── test_handshake.py     # QUIC handshake
│   └── test_streams.py       # QUIC streams
├── matrix/             # Protocol matrix tests
│   └── test_combinations.py  # All listener×connector combinations
├── security/           # Security tests
│   ├── test_mtls.py          # mTLS validation
│   └── test_certificates.py  # Certificate handling
├── performance/        # Performance tests
│   ├── test_concurrent.py    # Concurrent connections
│   └── test_throughput.py    # Throughput benchmarks
└── shared/             # Shared utilities
    ├── __init__.py
    ├── fixtures.py           # Common pytest fixtures
    ├── servers.py            # Test server utilities
    └── helpers.py            # Test helper functions
```

## Running Tests

### By Category
```bash
# All HTTP listener tests
pytest tests/httpx/

# All SOCKS tests  
pytest tests/socks/

# All QUIC tests
pytest tests/quic/
```

### By Function
```bash
# All connect tests across protocols
pytest -k "connect"

# All performance tests
pytest tests/performance/

# All security tests
pytest tests/security/
```

### Individual Tests
```bash
# Specific test file
pytest tests/httpx/test_connect.py

# Specific test function
pytest tests/httpx/test_connect.py::test_basic_connect_tunnel

# Run with timeout
pytest tests/httpx/test_connect.py --timeout=30
```

### With Markers
```bash
# Slow tests only
pytest -m "slow"

# Skip slow tests
pytest -m "not slow"

# Integration tests
pytest -m "integration"
```