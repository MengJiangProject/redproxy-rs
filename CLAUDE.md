# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Building and Testing
- `cargo build` - Build the project (features: quic, metrics, embedded-ui enabled by default)
- `cargo build --release` - Build optimized release version
- `cargo test` - Run all tests
- `cargo test --package milu` - Run tests for the Milu language parser specifically
- `cargo run -- -c config.yaml` - Run with custom config file
- `cargo run -- -t` - Test/validate configuration without starting the proxy
- `cargo run -- --log debug` - Run with debug logging (levels: erro, warn, info, debug, trace)

### Feature-specific builds
- `cargo build --no-default-features` - Build without QUIC, metrics, and embedded UI
- `cargo build --features "quic"` - Build with only QUIC support
- `cargo build --features "metrics embedded-ui"` - Build with metrics and web UI

## Project Architecture

### High-Level Structure
This is a Rust-based proxy routing tool that translates between protocols and selects destination proxies by policy. The architecture follows a modular design with clear separation of concerns:

**Core Components:**
- **Config System** (`src/config.rs`) - YAML-based configuration with comprehensive validation
- **Listeners** (`src/listeners/`) - Accept incoming connections (HTTP, SOCKS, QUIC, TPROXY, reverse proxy)
- **Connectors** (`src/connectors/`) - Handle outbound connections (direct, HTTP, SOCKS, QUIC, load balancing)
- **Rules Engine** (`src/rules/`) - Route requests based on Milu script filters
- **Context System** (`src/context.rs`) - Request lifecycle management with state tracking
- **Milu Language** (`milu/`) - Custom DSL for rule filtering and log formatting

### Request Flow Architecture
1. **Listener** accepts connection and creates `ContextRef` 
2. **Rules Engine** evaluates Milu filters against request properties to select connector
3. **Connector** establishes upstream connection
4. **Bidirectional copying** (`src/copy.rs`) handles data transfer with splice optimization on Linux
5. **Context lifecycle** tracks states: Created → ServerConnecting → Connected → Terminated

### Key Architectural Patterns
- **Plugin Architecture**: Listeners and connectors implement traits for easy extensibility
- **Async-first Design**: Built on Tokio with Arc/RwLock for shared state management
- **Feature Flags**: Optional QUIC and metrics support via Cargo features
- **Configuration-driven**: All behavior configurable through YAML with extensive validation

### Milu Language Integration
The embedded Milu DSL enables:
- **Rule Filtering**: `request.target.host == "example.com" && request.source.host =~ "192.168.*"`
- **Access Log Formatting**: Template strings with expression interpolation
- **Load Balancing**: Hash-based routing with custom hash functions
- Located in `milu/` workspace member with full parser and standard library

### Protocol Support Matrix
- **Listeners**: HTTP/HTTPS (with mTLS), SOCKS v4/v4a/v5, QUIC, TPROXY (Linux), Reverse Proxy
- **Connectors**: Direct TCP, HTTP CONNECT, SOCKS5, QUIC, Load Balancing
- **Security**: mTLS support across HTTP/SOCKS with certificate validation
- **Performance**: Linux splice() syscall support, BBR congestion control for QUIC

### Development Context
- **Error Handling**: Uses `easy-error` crate for error propagation with context
- **Logging**: `tracing` with structured logging and configurable levels
- **Testing**: Unit tests embedded in modules, use `cargo test` for validation
- **Platform Support**: Cross-platform with Linux-specific optimizations (TPROXY, splice)

### Configuration Structure
All configuration is YAML-based with these main sections:
- `listeners[]` - Inbound connection handlers
- `connectors[]` - Outbound connection methods  
- `rules[]` - Routing logic with Milu filters
- `metrics` - Prometheus/web UI configuration (optional)
- `accessLog` - Logging configuration with Milu formatting
- `timeouts` - Connection timeout settings
- `ioParams` - Buffer sizes and splice configuration

The comprehensive CONFIG_GUIDE.md and MILU_LANG_GUIDE.md provide detailed configuration reference.