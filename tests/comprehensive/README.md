# RedProxy Comprehensive Test Suite

This directory contains an extensive test suite that validates ALL RedProxy features, protocols, and configurations in realistic scenarios.

## Test Architecture

### Test Categories

1. **Essential Tests** - Core HTTP/SOCKS5 proxy functionality
2. **QUIC Tests** - HTTP/3 and QUIC protocol validation
3. **mTLS Tests** - Client certificate authentication and security
4. **Load Balancer Tests** - Multi-upstream routing and failover
5. **Rules Tests** - Milu language engine and filtering
6. **Linux Tests** - Platform-specific features (TPROXY, splice)
7. **Performance Tests** - Throughput, latency, concurrent connections

### Test Environment

Uses unified Docker Compose with standardized port allocation:

- **RedProxy Instances**: All use HTTP:8800, SOCKS5:1081, Metrics:8888
- **Test Targets**: Nginx (80), WebSocket (3000), blocked services
- **Upstream Proxies**: HTTP:3128, SOCKS5:1080, QUIC:9443, mTLS:9800
- **Certificate Authority**: Embedded generation in docker-compose.yml
- **Shared Test Library**: DRY test functions eliminating code duplication
- **Isolated Network**: Docker bridge network preventing localhost conflicts

## Test Coverage Matrix

### Listeners × Connectors
| Listener | Direct | HTTP | SOCKS5 | QUIC | Load Balancer |
|----------|--------|------|--------|------|---------------|
| HTTP     | ✓      | ✓    | ✓      | ✓    | ✓             |
| SOCKS5   | ✓      | ✓    | ✓      | ✓    | ✓             |
| QUIC     | ✓      | ✓    | ✓      | ✓    | ✓             |
| TPROXY   | ✓      | ✓    | ✓      | ✓    | ✓             |
| Reverse  | ✓      | ✓    | ✓      | ✓    | ✓             |

### Protocol Features
- **HTTP**: CONNECT tunneling, Forward proxy (GET/POST/PUT/DELETE), WebSocket upgrades
- **SOCKS**: v4/v4a/v5 with authentication
- **QUIC**: HTTP/3, custom protocols, BBR congestion control
- **TPROXY**: TCP/UDP transparent proxying (Linux only)
- **mTLS**: Client certificate validation, custom CA chains

### Advanced Features
- **Metrics**: Prometheus endpoints, embedded UI, custom metrics
- **Load Balancing**: Round-robin, weighted, hash-based routing
- **Rule Engine**: Complex Milu expressions, performance, memory usage
- **Configuration**: Hot reload, validation, feature flags
- **Performance**: Linux splice(), buffer tuning, connection pooling

## Running Tests

### Quick Test (Essential Features)
```bash
cd tests/comprehensive
make test-essential
```

### Full Test Suite (All Features)
```bash
cd tests/comprehensive  
make test-all
```

### Performance Benchmarks
```bash
cd tests/comprehensive
make test-performance
```

### Feature-Specific Tests
```bash
make test-quic          # QUIC protocol tests
make test-mtls          # mTLS security tests
make test-loadbalancer  # Load balancing tests
make test-rules         # Milu rule engine tests
make test-linux         # Linux-only features (TPROXY, splice)
make test-performance   # Performance benchmarks
```

### Port Allocation
All services use unified port scheme to avoid conflicts:
- **RedProxy HTTP**: 8800 (all instances)
- **RedProxy SOCKS5**: 1081 (all instances)  
- **RedProxy Metrics**: 8888 (all instances)
- **Upstream HTTP**: 3128 (Squid proxy)
- **Upstream SOCKS5**: 1080 (go-socks5-proxy)
- **Upstream QUIC**: 9443 (RedProxy QUIC)
- **Upstream mTLS**: 9800 (RedProxy with mTLS)

## Test Scenarios

### 1. Protocol Matrix (25 combinations)
Every listener type connected to every connector type with real traffic validation.

### 2. HTTP Feature Coverage
- HTTP/1.1 and HTTP/2 support
- CONNECT tunneling with various protocols
- Forward proxy for GET/POST/PUT/DELETE/PATCH requests
- WebSocket upgrade handling
- Custom headers preservation
- Chunked transfer encoding
- Keep-alive connection reuse

### 3. SOCKS Protocol Coverage
- SOCKS v4/v4a/v5 protocol compliance
- Username/password authentication
- IPv4 and IPv6 address handling
- Domain name resolution modes
- Error code handling

### 4. QUIC Protocol Coverage
- HTTP/3 over QUIC
- Custom application protocols
- Connection migration
- 0-RTT resumption
- BBR congestion control validation
- Certificate validation

### 5. Security & mTLS
- Client certificate authentication
- Custom CA certificate chains
- Certificate revocation handling
- TLS version negotiation
- Cipher suite selection
- Certificate validation modes

### 6. Performance & Scalability
- Concurrent connection limits
- Memory usage under load
- CPU utilization patterns
- Network throughput measurements
- Latency percentiles (p50, p95, p99)
- Connection pool efficiency

### 7. Rule Engine Validation
- Complex Milu filter expressions
- Performance with large rule sets
- Dynamic rule evaluation
- Memory efficiency
- Custom hash functions
- Load balancing algorithms

### 8. Error Handling & Edge Cases
- Network failures and timeouts
- Malformed protocol messages
- Resource exhaustion scenarios
- Invalid configurations
- Certificate errors
- DNS resolution failures

### 9. Monitoring & Observability
- Prometheus metrics accuracy
- Embedded UI functionality
- Access log formatting
- Custom metric collection
- Performance counter validation

### 10. Real-World Integration
- Multi-hop proxy chains
- CDN integration scenarios
- Load balancer deployments
- Kubernetes ingress patterns
- High-availability configurations

## Expected Outcomes

### Test Results
- **Pass/Fail Status**: Clear indication for each test category
- **Performance Metrics**: Throughput, latency, resource usage
- **Coverage Report**: Feature coverage percentage
- **Compatibility Matrix**: Platform/feature support validation

### Continuous Integration
- Automated test execution on PRs
- Performance regression detection  
- Feature flag combination validation
- Cross-platform compatibility checks
- Security vulnerability scanning

## Troubleshooting

### Common Issues
- **QUIC Tests Failing**: Check UDP port availability and firewall rules
- **mTLS Tests Failing**: Verify certificate generation and trust chains
- **TPROXY Tests Failing**: Ensure Linux system with proper capabilities
- **Performance Tests Inconsistent**: Check system load and resource limits

### Debug Commands
```bash
# View detailed logs
make logs SERVICE=redproxy-quic

# Test individual protocols
make test-debug PROTOCOL=quic

# Performance profiling
make profile-memory
make profile-cpu
```

This comprehensive test suite ensures RedProxy functions correctly across all supported protocols, features, and deployment scenarios.