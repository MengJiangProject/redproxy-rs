[![Rust Build and Test](https://github.com/bearice/redproxy-rs/actions/workflows/rust.yml/badge.svg)](https://github.com/bearice/redproxy-rs/actions/workflows/rust.yml)

# redproxy-rs

A high-performance proxy routing tool written in Rust. It can translate between different protocols and select destination proxies based on configurable policies.

## Protocol Support

### Listeners (Inbound Protocols)

| Protocol | RFC Specification | Authentication | Features | Notes |
|----------|-------------------|----------------|----------|-------|
| HTTP/HTTPS | [RFC 7230-7237](https://tools.ietf.org/html/rfc7230) | Basic Auth, mTLS | CONNECT tunneling, Forward proxy | WebSocket upgrade support |
| SOCKS v4 | [RFC 1080](https://tools.ietf.org/html/rfc1080) | UserPassword/NoAuth, mTLS | CONNECT, BIND | Legacy protocol |
| SOCKS v4a | SOCKS4a extension | UserPassword/NoAuth, mTLS | CONNECT, BIND | Domain name support |
| SOCKS v5 | [RFC 1928](https://tools.ietf.org/html/rfc1928) | UserPassword/NoAuth, mTLS | CONNECT, BIND, UDP ASSOCIATE | Full feature support |
| QUIC | [RFC 9000](https://tools.ietf.org/html/rfc9000) | Basic Auth, mTLS | HTTP/1 over QUIC | QUIC as transport protocols only, not http3 |
| SSH Tunnels | [RFC 4254](https://tools.ietf.org/html/rfc4254) | SSH keys, passwords | Port forwarding | Secure tunneling |
| TPROXY | - | - | Transparent proxy | iptables REDIRECT |
| Reverse Proxy | - | - | General reverse proxy (TCP&UDP) | - |

### Connectors (Outbound Protocols)

| Protocol | RFC Specification | Authentication | Features | Notes |
|----------|-------------------|----------------|----------|-------|
| Direct TCP | - | - | Direct connections | Configurable bind address, fwmark on linux |
| HTTP CONNECT | [RFC 7231](https://tools.ietf.org/html/rfc7231) | Basic Auth, mTLS | Proxy tunneling | Standard HTTP proxy |
| HTTP Forward | [RFC 7230-7237](https://tools.ietf.org/html/rfc7230) | Basic Auth, mTLS | GET, POST, PUT, DELETE | Full HTTP methods |
| SOCKS v4 | [RFC 1080](https://tools.ietf.org/html/rfc1080) | UserPassword/NoAuth, mTLS | CONNECT, BIND | Legacy protocol |
| SOCKS v4a | SOCKS4a extension | UserPassword/NoAuth, mTLS | CONNECT, BIND | Domain name support |
| SOCKS v5 | [RFC 1928](https://tools.ietf.org/html/rfc1928) | UserPassword/NoAuth, mTLS | CONNECT, BIND, UDP ASSOCIATE | Full feature support |
| QUIC | [RFC 9000](https://tools.ietf.org/html/rfc9000) | Basic Auth, mTLS | HTTP/1 over QUIC | QUIC as transport protocols only, not http3 |
| SSH Tunnels | [RFC 4254](https://tools.ietf.org/html/rfc4254) | SSH keys, passwords | Port forwarding | Secure tunneling |
| Load Balancing | - | - | Multiple algorithms | Round-robin, random, hash |

## RFC Implementations

### Core Protocol RFCs
- **[RFC 1080](https://tools.ietf.org/html/rfc1080)** - SOCKS Protocol Version 4 (including BIND command)
- **[RFC 1928](https://tools.ietf.org/html/rfc1928)** - SOCKS Protocol Version 5 (including BIND command)
- **[RFC 1929](https://tools.ietf.org/html/rfc1929)** - Username/Password Authentication for SOCKS V5
- **[RFC 7230-7237](https://tools.ietf.org/html/rfc7230)** - HTTP/1.1 specification
- **[RFC 9000](https://tools.ietf.org/html/rfc9000)** - QUIC transport protocol
- **[RFC 4254](https://tools.ietf.org/html/rfc4254)** - SSH Connection Protocol

### Advanced Protocol RFCs
- **[RFC 9298](https://tools.ietf.org/html/rfc9298)** - Proxying UDP in HTTP (UDP-over-HTTP tunneling)
- **[RFC 6455](https://tools.ietf.org/html/rfc6455)** - WebSocket protocol with upgrade support
- **[RFC 7617](https://tools.ietf.org/html/rfc7617)** - HTTP Basic Authentication
- **[RFC 2817](https://tools.ietf.org/html/rfc2817)** - Upgrading to TLS Within HTTP/1.1

## Key Features

- **Multi-Protocol Translation**: Convert between different proxy protocols seamlessly
- **Security**: mTLS support, authentication, loop prevention, timeout protection
- **Performance**: Zero-copy optimizations, Linux splice() syscall, graceful shutdown
- **Observability**: Prometheus metrics, structured JSON logging, embedded web console
- **Dynamic Configuration**: Real-time rule updates via RESTful API with Milu DSL

## Configuration

See [CONFIG_GUIDE.md](CONFIG_GUIDE.md) for comprehensive configuration documentation and examples.

### Quick Start Example

```yaml
listeners:
  - name: http-proxy
    type: http
    bind: "0.0.0.0:8080"
  
  - name: socks-proxy  
    type: socks
    bind: "0.0.0.0:1080"
    allowBind: true  # Enable SOCKS BIND command

connectors:
  - name: direct
    type: direct
  
  - name: upstream-proxy
    type: socks
    server: "proxy.example.com" 
    port: 1080

rules:
  - filter: 'request.target.host =~ ".*\\.local"'
    target: direct
  # Empty filter means matches all
  - target: upstream-proxy
```

## Development

Redproxy-rs includes a complete Nix development environment:

```bash
# Using Nix flakes (recommended)
nix develop

# Traditional development
cargo build
cargo test
```

For comprehensive testing:
```bash
# Run full test suite including integration tests  
make test-all

# Run specific protocol tests
make test-bind  # SOCKS BIND functionality
make test-matrix  # All protocol combinations
```

## Why redproxy-rs?

Originally created to replace a [TypeScript version of this](https://github.com/bearice/redproxy) that had been running on home routers for years.
