# RedProxy Comprehensive Test Suite

Simplified, maintainable test suite for **basic** RedProxy functionality validation.

**✅ Current Status: Matrix Implementation Complete (30/30 combinations)**  
All core listener×connector protocol combinations are now implemented and tested.

## Quick Start

```bash
cd tests/comprehensive
make test-all                    # Run all tests
make test-matrix                # Test all listener×connector combinations  
make test-security              # Security and error handling
make test-performance           # Concurrency and load tests
make clean                      # Stop services and clean up
```

## Architecture

**Single RedProxy instance** with matrix configuration:
- `config/base.yaml` - Static config for container environment
- `docker-compose.yml` - ~65 lines, clean service definitions
- Matrix test with comprehensive HTTP forward proxy functionality
- Shared test library eliminates code duplication

## Current Test Coverage

### ✅ **What's Tested (Complete Matrix Coverage)**
- **HTTP Listener → All Connectors**: Full HTTP forward proxy functionality (GET/POST/JSON/headers)
- **SOCKS5 Listener → All Connectors**: Complete SOCKS proxying with authentication handling
- **Reverse Proxy Listener → All Connectors**: Direct HTTP requests through reverse proxy
- **QUIC Listener → All Connectors**: HTTP CONNECT proxy over QUIC streams
- **SSH Listener → All Connectors**: SSH tunnel port forwarding
- **Matrix Testing**: All 30 listener×connector combinations validated
- **Basic Security**: Error handling, concurrent connections
- **Basic Performance**: Connection efficiency, load testing

### ❌ **Advanced Features Still Missing**
- **TPROXY**: No transparent proxy testing (Linux-specific, requires special network setup)
- **UDP Protocols**: No UDP tunneling or proxying
- **RFC 9298**: No "Proxying UDP in HTTP" testing  
- **mTLS**: No client certificate authentication
- **Advanced Routing**: Limited Milu rule engine testing
- **Metrics**: No Prometheus/monitoring validation
- **WebSocket**: No upgrade handling testing

## Files (10 total)

```
tests/comprehensive/
├── Makefile                   # build targets
├── docker-compose.yml         # Single compose file (~68 lines)
├── Dockerfile                 # Multi-stage RedProxy build
├── README.md                  # This file
├── config/base.yaml           # Static config for tests
└── scripts/
    ├── test_matrix.py         # Matrix combination tests
    ├── test_security.py       # Security tests  
    ├── test_performance.py    # Performance tests
    ├── matrix_generator.py    # Matrix config generator
    ├── generate_test_certs.py # Certificate generation
    └── lib/test_utils.py      # Shared test library
```

## Future Work Needed

### **Protocol Matrix Status**
RedProxy supports 5 listener types × 6 connector types (30 combinations):

| Listener | Direct | HTTP | SOCKS5 | Load Balancer | QUIC | SSH |
|----------|--------|------|--------|---------------|------|-----|
| HTTP     | ✅     | ✅    | ✅      | ✅             | ✅    | ✅   |
| SOCKS5   | ✅     | ✅    | ✅      | ✅             | ✅    | ✅   |
| Reverse  | ✅     | ✅    | ✅      | ✅             | ✅    | ✅   |
| QUIC     | ✅     | ✅    | ✅      | ✅             | ✅    | ✅   |
| SSH      | ✅     | ✅    | ✅      | ✅             | ✅    | ✅   |

**All 30 combinations implemented and tested (100% matrix coverage)**

### **Advanced Feature Testing (Priority 2)**
- TPROXY transparent proxy testing (requires special network setup)
- UDP protocols and RFC 9298 (existing unit tests available)
- mTLS client certificates
- Metrics and monitoring endpoints
- WebSocket upgrade handling
- Enhanced HTTP Forward Proxy (PUT/DELETE methods, large payloads, connection reuse)
- Graceful shutdown and configuration validation

### **Reference Implementation**
The original over-engineered version (30 files, 318-line docker-compose) attempted to cover these features but was unmaintainable. See the `feature/comprehensive-tests` branch for the full implementation. This simplified version (10 files, 63-line docker-compose) provides a foundation for incremental expansion.

**Goal**: Systematic addition of missing features while maintaining simplicity and maintainability.