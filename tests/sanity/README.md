# RedProxy Sanity Tests

This directory contains comprehensive Docker-based sanity tests that verify RedProxy's core functionality by testing real network scenarios with actual client commands.

## Test Architecture

The test environment consists of:

- **RedProxy Server**: The proxy server under test with HTTP and SOCKS listeners
- **HTTP Echo Server**: Target service for direct connection testing
- **Target Nginx Server**: Backend service for upstream proxy testing
- **Upstream HTTP Proxy (Squid)**: Tests HTTP CONNECT connector functionality
- **Upstream SOCKS Proxy**: Tests SOCKS5 connector functionality
- **Test Runner**: Alpine container that runs curl commands to verify functionality

## What Gets Tested

### Listeners
- **HTTP CONNECT Proxy**: Tests HTTP CONNECT tunnel establishment
- **SOCKS5 Proxy**: Tests SOCKS5 protocol handling

### Connectors
- **Direct Connector**: Tests direct TCP connections
- **HTTP CONNECT Connector**: Tests upstream HTTP proxy connectivity
- **SOCKS5 Connector**: Tests upstream SOCKS proxy connectivity

### Features
- **Rule-based Routing**: Different targets based on Milu filter rules
- **Protocol Translation**: HTTP CONNECT → SOCKS5, SOCKS5 → HTTP, etc.
- **Concurrent Connections**: Multiple simultaneous proxy connections
- **Error Handling**: Connection failures and timeouts

## Running the Tests

### Prerequisites
- Docker and Docker Compose
- At least 2GB free memory for all containers

### Run All Tests
```bash
cd tests/sanity
docker-compose up --build --abort-on-container-exit
```

### Run with Logs
```bash
cd tests/sanity
docker-compose up --build --abort-on-container-exit --remove-orphans
```

### Cleanup
```bash
cd tests/sanity
docker-compose down -v --remove-orphans
```

## Test Scenarios

1. **Direct HTTP CONNECT**: `curl -x redproxy:8800 http://http-echo:8080/`
   - Tests: HTTP listener + direct connector
   - Expected: Echo server response

2. **HTTP CONNECT through Upstream**: `curl -x redproxy:8800 http://target-server:80/`
   - Tests: HTTP listener + HTTP CONNECT connector
   - Expected: Nginx response via Squid proxy

3. **SOCKS5 Proxy**: `curl --socks5 redproxy:1081 http://target-server:80/`
   - Tests: SOCKS listener + SOCKS5 connector
   - Expected: Nginx response via SOCKS proxy

4. **Protocol Chaining**: SOCKS5 client → RedProxy → SOCKS5 upstream → Target
   - Tests: Complex multi-hop proxy scenarios

5. **Concurrent Connections**: 5 simultaneous requests
   - Tests: Connection handling and performance

6. **Error Handling**: Connections to non-existent hosts
   - Tests: Proper error propagation

## Configuration

The test uses `redproxy-config.yaml` with:
- HTTP proxy on port 8800
- SOCKS5 proxy on port 1081
- Rule-based routing for different test scenarios
- Appropriate timeouts for container environment

## Expected Output

Successful test run shows:
```
✓ HTTP CONNECT to echo server works (direct connector)
✓ HTTP CONNECT through upstream HTTP proxy works
✓ SOCKS5 proxy through upstream SOCKS works
✓ Upstream HTTP proxy is working
✓ Upstream SOCKS proxy is working
✓ Complex routing (SOCKS->RedProxy->SOCKS->Target) works
✓ All 5 concurrent connections succeeded
✓ Properly handled connection to non-existent host
=== All tests passed! ===
```

## Troubleshooting

### Container startup issues
Check service dependencies:
```bash
docker-compose logs redproxy
docker-compose logs http-echo
```

### Network connectivity issues
Verify internal networking:
```bash
docker-compose exec test-runner nc -z redproxy 8800
docker-compose exec test-runner nc -z http-echo 8080
```

### RedProxy configuration issues
Check logs for configuration errors:
```bash
docker-compose logs redproxy
```