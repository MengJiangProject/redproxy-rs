# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Comprehensive Test Suite

This directory contains comprehensive integration tests for the redproxy-rs project using Docker Compose orchestration. The test suite validates all protocol combinations, security features, and performance characteristics.

### Test Commands

#### Running Tests
- `make test-all` - Run all comprehensive test suites
- `make test-matrix` - Test all listener×connector combinations
- `make test-security` - Security and error handling tests
- `make test-performance` - Concurrency and performance tests
- `make clean` - Stop all services and clean up

#### Prerequisites
- Docker and Docker Compose must be installed
- The test runner uses Python with uv for dependency management
- Tests generate certificates and SSH keys automatically

### Test Architecture

#### Core Components
- **Docker Compose Orchestration** - Multi-container test environment with services isolation
- **Python Test Framework** - uv-managed Python scripts for test execution
- **Certificate Generation** - Automated TLS/mTLS certificate creation for secure testing
- **Matrix Testing** - Exhaustive listener×connector protocol combination testing
- **Logging and Monitoring** - Structured test result collection in logs/ directory

#### Test Categories
1. **Matrix Tests** (`test_matrix.py`) - All protocol combination validation
2. **Security Tests** (`test_security.py`) - mTLS, certificate validation, error handling
3. **Performance Tests** (`test_performance.py`) - Concurrency, throughput, resource usage

#### Generated Configuration
- `config/generated/matrix.yaml` - Auto-generated test configuration with all protocol combinations
- `config/generated/` - Contains TLS certificates, SSH keys, and other test artifacts
- Tests use `/config/generated/matrix.yaml` as the primary redproxy configuration

### Development Context

#### Test Environment Setup
- Tests run in isolated Docker containers with proper UID/GID mapping
- Certificate generation is dependency-driven (only regenerates when needed)
- All test dependencies managed through uv and pyproject.toml
- Logs are collected in `logs/` directory for analysis

#### Protocol Testing Matrix
The comprehensive tests validate all supported protocol combinations:
- **Listeners**: HTTP, HTTPS (mTLS), SOCKS4/4a/5, QUIC, Reverse Proxy
- **Connectors**: Direct TCP, HTTP CONNECT, SOCKS5, QUIC, Load Balancing
- **Security Features**: mTLS validation, certificate chains, client authentication
- **Performance**: Concurrent connections, throughput benchmarks

#### Configuration Management
- Base configuration in `config/base.yaml`
- Protocol-specific configs (QUIC, SQUID) in `config/`
- Matrix generator creates comprehensive test scenarios automatically
- All certificates and keys generated on-demand for security testing
- you MUST NOT connect to test service in host environments, it wont work