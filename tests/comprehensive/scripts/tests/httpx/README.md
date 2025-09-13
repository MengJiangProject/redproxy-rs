# HttpX Test Suite Architecture

## Overview

This directory contains comprehensive tests for redproxy's HttpX functionality. All tests run against the **same integrated configuration** (`httpx.yaml`) with httpx listener + httpx connector → http-proxy, but focus on different aspects of the pipeline.

## Architecture Understanding

### Integrated Testing Approach
All httpx tests use the same configuration:
```
client → redproxy (httpx listener) → httpx connector → http-proxy:3128 → target server
```

### Component Focus Areas
- **HttpX Listener** (`src/listeners/httpx.rs`): Client-side protocol handling
  - Protocol negotiation (HTTP/1.1, HTTP/2, HTTP/3) with clients
  - Request parsing and validation from clients
  - Client-side keep-alive connection management
  - Client authentication and authorization

- **HttpX Connector** (`src/connectors/httpx.rs`): Server-side proxy connectivity  
  - Connections to HTTP proxy servers (Squid on port 3128)
  - Connection pooling and reuse with proxy servers
  - Server-side keep-alive connections to proxies
  - Proxy authentication and protocol negotiation
  - Proxy chaining: redproxy → HTTP proxy → target server

### HttpContext
- **HttpContext** (`src/protocols/http/http_context.rs`): Request state management
  - Type-safe HTTP property storage across the pipeline
  - Request lifecycle management: listener → rules → connector
  - Single source of truth for HTTP request/response data

## Test Categories

### 1. Listener Tests (`test_listener.py`)
**Purpose**: Test HttpX listener behavior in isolation
**Configuration**: Uses `httpx-listener.yaml` (httpx listener + direct connector)
**Focus Areas**:
- Client protocol negotiation (HTTP/1.0, HTTP/1.1)
- Request parsing and validation
- Client-side keep-alive connection management
- Malformed request handling
- HTTP method support (GET, POST, HEAD, OPTIONS, etc.)
- Proxy authentication parsing
- Concurrent client connection handling

**Key Tests**:
```python
test_listener_http1_protocol_negotiation()    # Protocol handling
test_listener_client_keep_alive()            # Client keep-alive
test_listener_malformed_request_handling()   # Error handling
test_listener_concurrent_clients()           # Performance
```

### 2. Connector Tests (`test_httpx_connector.py`)
**Purpose**: Test HttpX connector behavior in isolation  
**Configuration**: Uses `httpx-connector.yaml` (http listener + httpx connector → http-proxy)
**Focus Areas**:
- HTTP proxy server connection establishment (connects to Squid on port 3128)
- Connection pool management and efficiency with proxy servers
- Server-side keep-alive connection reuse to proxy
- Proxy error handling (proxy down, authentication failures)
- Protocol version negotiation with HTTP proxies
- Proxy authentication and authorization

**Key Tests**:
```python
test_connector_http_proxy_connection()      # Proxy connectivity  
test_connector_proxy_keep_alive()          # Proxy keep-alive
test_connection_pooling()                  # Pool efficiency with proxy
test_connector_proxy_authentication()      # Proxy auth handling
```

### 3. Integration Tests (`test_integration.py`)
**Purpose**: Test complete end-to-end flow through both listener and connector
**Configuration**: Uses `httpx.yaml` (httpx listener + httpx connector)  
**Focus Areas**:
- Complete request flow: client → httpx listener → httpx connector → http-proxy → backend
- HttpContext state management across the complete pipeline
- End-to-end keep-alive behavior (client-side and proxy-side)
- Performance under concurrent load through proxy chain
- Memory efficiency across complete pipeline
- Error propagation through complete proxy chain

**Key Tests**:
```python
test_end_to_end_request_flow()             # Complete pipeline
test_keep_alive_end_to_end()              # E2E keep-alive  
test_http_context_state_management()       # Context lifecycle
test_concurrent_end_to_end_requests()     # E2E performance
```

### 4. HttpContext Tests (`test_http_context.py`)
**Purpose**: Test HttpContext functionality regardless of listener/connector types
**Configuration**: Uses `httpx.yaml` (any listener/connector combination)
**Focus Areas**:
- HttpContext request storage and retrieval
- Type safety and API compatibility
- Memory efficiency and cleanup
- Backward compatibility with legacy patterns
- Authentication handling within context

**Key Tests**:
```python
test_context_request_storage()             # Basic functionality
test_context_memory_efficiency()          # Resource management
test_legacy_api_compatibility()           # Backward compatibility
test_http_method_handling()               # Method support
```

### 5. Other Protocol Tests
- `test_connect.py`: HTTP CONNECT tunneling (works with any listener)
- `test_forward.py`: HTTP forward proxy (works with any listener)  
- `test_keepalive.py`: Keep-alive specific tests (works with any listener)
- `test_chunked.py`: Chunked encoding (works with any listener)
- `test_websocket.py`: WebSocket upgrade (works with any listener)

## Configuration

### Single Integrated Configuration
All httpx tests use the same configuration file: `httpx.yaml`

```yaml
listeners:
  - name: httpx      # HttpX listener
    type: httpx
    bind: "0.0.0.0:8800"
    protocols:
      http1:
        enable: true

connectors:
  - name: httpx      # HttpX connector to Squid proxy
    type: httpx
    server: "http-proxy"
    port: 3128
    protocol:
      type: "http/1.1" 
      keep_alive: true
    pool:
      enable: true
      max_connections: 50

rules:
  - filter: 'request.target.host == "http-echo"'
    target: httpx    # Route through httpx connector → http-proxy
  - filter: "true"
    target: httpx    # Default to httpx connector
```

**Pipeline**: `client → httpx listener:8800 → httpx connector → http-proxy:3128 → target`

## Running Tests

### By Component
```bash
# Test only HttpX listener
pytest tests/httpx/test_listener.py -m httpx_listener

# Test only HttpX connector  
pytest tests/httpx/test_httpx_connector.py -m httpx_connector

# Test complete integration
pytest tests/httpx/test_integration.py -m httpx_integration

# Test HttpContext functionality
pytest tests/httpx/test_http_context.py -m http_context
```

### By Category
```bash
# Performance tests across all components
pytest tests/httpx/ -m performance

# Destructive/error handling tests
pytest tests/httpx/ -m destructive

# All HttpX related tests
pytest tests/httpx/
```

### Individual Tests
```bash
# Specific functionality
pytest tests/httpx/test_listener.py::TestHttpxListener::test_listener_client_keep_alive
pytest tests/httpx/test_integration.py::TestHttpxIntegration::test_end_to_end_request_flow
```

## Test Markers

- `httpx_listener`: Tests specific to HttpX listener
- `httpx_connector`: Tests specific to HttpX connector  
- `httpx_integration`: Tests requiring both listener and connector
- `http_context`: Tests for HttpContext functionality
- `performance`: Performance and load tests
- `destructive`: Tests with error conditions or malformed data
- `compatibility`: Backward compatibility tests

## Benefits of This Integrated Architecture

1. **Real-World Testing**: Tests validate components within realistic integrated pipeline
2. **Focused Validation**: Each test category focuses on different aspects of the same pipeline
3. **Simplified Setup**: Single configuration eliminates configuration management complexity
4. **Practical Scenarios**: Tests proxy chaining behavior that matches production usage
5. **Clear Debugging**: Test names clearly indicate which aspect (listener/connector/integration) failed
6. **Component Awareness**: Tests understand their role within the complete pipeline