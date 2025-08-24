# RedProxy Comprehensive Test Suite

Simplified, maintainable test suite for **basic** RedProxy functionality validation.

**⚠️ Current Status: Foundation Only (24% coverage)**  
This is a starting point, not a complete comprehensive test suite.

## Quick Start

```bash
cd tests/comprehensive
make test-all                    # Run all tests
make test-protocols             # HTTP CONNECT and SOCKS5 tests  
make test-security              # Security and error handling
make test-performance           # Concurrency and load tests
```

## Architecture

**Single RedProxy instance** with static configuration:
- `config/base.yaml` - Static config for container environment
- `docker-compose.yml` - ~65 lines, clean service definitions
- 3 focused test scripts instead of 8+ specialized ones
- Shared test library eliminates code duplication

## Current Test Coverage (Limited)

### ✅ **What's Tested (6/25 Protocol Matrix combinations)**
- **HTTP Listener → Direct/HTTP/SOCKS5 Connectors**: Basic proxy functionality
- **SOCKS5 Listener → Direct/HTTP/SOCKS5 Connectors**: Basic SOCKS proxying
- **Basic Security**: Error handling, concurrent connections
- **Basic Performance**: Connection efficiency, load testing

### ❌ **Major Missing Features (19/25 combinations + advanced features)**
- **Protocol Matrix**: Only 6/25 listener×connector combinations tested
- **QUIC/HTTP3**: No QUIC listener or connector testing
- **TPROXY**: No transparent proxy testing (Linux-specific)
- **Reverse Proxy**: No reverse proxy listener testing
- **Load Balancing**: No multi-upstream connector testing
- **UDP Protocols**: No UDP tunneling or proxying
- **RFC 9298**: No "Proxying UDP in HTTP" testing
- **SSH Integration**: No SSH tunneling/forwarding
- **mTLS**: No client certificate authentication
- **Advanced Routing**: Limited Milu rule engine testing
- **Metrics**: No Prometheus/monitoring validation
- **WebSocket**: No upgrade handling testing
- **HTTP Forward Proxy**: Only CONNECT, missing GET/POST/etc

## Environment Variables

- `TEST_SUITE={protocols|security|performance}` - Select test category
- `VERBOSE=true` - Enable detailed output

## Files (10 total)

```
tests/comprehensive/
├── Makefile                    # Simple test targets
├── docker-compose.yml         # Single compose file (~68 lines)
├── Dockerfile                 # Multi-stage RedProxy build
├── README.md                  # This file
├── config/base.yaml           # Static config for tests
└── scripts/
    ├── run-tests.sh           # Test suite router
    ├── test-protocols.sh      # Protocol tests
    ├── test-security.sh       # Security tests  
    ├── test-performance.sh    # Performance tests
    └── lib/common.sh          # Shared functions
```

## Future Work Needed

### **Protocol Matrix Completion (Priority 1)**
RedProxy supports a 5×5 listener×connector matrix (25 combinations):

| Listener | Direct | HTTP | SOCKS5 | QUIC | Load Balancer |
|----------|--------|------|--------|------|---------------|
| HTTP     | ✅     | ✅    | ✅      | ❌    | ❌             |
| SOCKS5   | ✅     | ✅    | ✅      | ❌    | ❌             |
| QUIC     | ❌     | ❌    | ❌      | ❌    | ❌             |
| TPROXY   | ❌     | ❌    | ❌      | ❌    | ❌             |
| Reverse  | ❌     | ❌    | ❌      | ❌    | ❌             |

### **Advanced Feature Testing (Priority 2)**
- UDP protocols and RFC 9298 (existing unit tests available)
- SSH integration (existing unit tests available)  
- mTLS client certificates
- Metrics and monitoring endpoints
- WebSocket upgrade handling
- HTTP Forward Proxy (GET/POST/PUT/DELETE)
- Graceful shutdown and configuration validation

### **Reference Implementation**
The original over-engineered version (30 files, 318-line docker-compose) attempted to cover these features but was unmaintainable. See the `feature/comprehensive-tests` branch for the full implementation. This simplified version (10 files, 63-line docker-compose) provides a foundation for incremental expansion.

**Goal**: Systematic addition of missing features while maintaining simplicity and maintainability.