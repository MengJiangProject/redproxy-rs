# Changelog

All notable changes to redproxy-rs will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.10.0] - 2025-09-07

### Added
- **🔧 SOCKS BIND Support**: Complete SOCKS BIND command implementation for both SOCKS4 and SOCKS5 (#218, #420)
  - Direct TCP BIND operations with configurable bind addresses  
  - SOCKS proxy BIND with upstream server support
  - Timeout protection to prevent resource exhaustion attacks
  - NAT address override functionality for complex network scenarios
  - Comprehensive test coverage including timeout validation
- **🌐 HTTP/HTTPS Enhancements**: 
  - RFC 9298 Proxying UDP in HTTP protocol support (#406)
  - HTTP authentication support for connectors and listeners (#405)
  - Enhanced WebSocket detection with proper header parsing
  - HTTP forward proxy implementation with WebSocket support (#404)
  - HTTP loop prevention system with configurable hop limits
- **🔒 SSH Tunnel Support**: Full SSH tunneling for both listeners and connectors with key authentication
- **🧪 Comprehensive Test Suite**: Docker-based integration testing with matrix protocol validation
- **⚡ Performance Optimizations**: Zero-copy buffer operations and splice() syscall support on Linux
- **🛡️ Graceful Shutdown System**: SIGTERM/SIGINT/CTRL+C signal handling with configurable timeouts
- **🏗️ Development Environment**: Nix flake with direnv support and complete Rust toolchain

### Changed
- **🏗️ Architecture Overhaul**: Major refactoring of main.rs and connector architecture for improved testability
- **🔧 Modernization**: 
  - Replaced lazy_static with std::sync::OnceLock throughout codebase
  - Updated to Rust Edition 2024 with modern language features
  - Migrated from easy_error to anyhow for improved error handling
  - Replaced trust-dns-resolver with hickory-resolver for DNS
  - Replaced serde_yaml with serde_yaml_ng for better YAML handling
- **⚡ Performance Improvements**:
  - Zero-copy buffer allocation optimizations
  - Enhanced LoadBalanceConnector with OnceLock dependency injection
  - Linux splice() syscall integration for high-performance data transfer
- **🛡️ Security & Reliability**:
  - Improved error context messages across connectors and listeners
  - Enhanced HTTP loop detection algorithms
  - Better connection cleanup during server shutdown
  - Timeout-based resource protection for BIND operations

### Removed
- **🚫 Safety Improvements**: Eliminated all dangerous panic!() and unwrap() calls in production code
- **🧹 Code Cleanup**: Removed unused NoAuth struct from SOCKS implementation
- **📦 Deprecated Dependencies**: Removed legacy error handling and DNS resolver libraries

### Fixed
- **🔧 Build & Compatibility**:
  - Windows build compatibility issues resolved
  - Cross-compilation setup and CI workflow improvements
  - Import path corrections for TPROXY listener functions
  - Missing Debug derives added for internal structs
- **🧪 Testing & Reliability**:
  - HTTP test reliability and stability improvements
  - Socket operations and connector testing edge cases
  - Docker layer caching for comprehensive test suite
  - Permission errors in comprehensive test infrastructure
- **⚡ Performance & Memory**:
  - Connection cleanup during graceful server shutdown
  - Buffer allocation optimizations for zero-copy operations
  - Eliminated unused parameter warnings across codebase

### Security
- **🛡️ Resource Protection**: BIND operations now have configurable timeouts to prevent resource exhaustion attacks
- **🔒 Authentication**: Enhanced HTTP authentication support with proper credential handling  
- **🌐 Loop Prevention**: Comprehensive HTTP proxy loop detection prevents infinite request cycles
- **⚡ Memory Safety**: Eliminated all panic!() and unwrap() calls that could cause crashes in production

### Dependencies
- **📦 Major Updates**: Updated to Rust Edition 2024 with modern language features
- **🔄 Library Migration**: 
  - `trust-dns-resolver` → `hickory-resolver` (better DNS handling)
  - `serde_yaml` → `serde_yaml_ng` (improved YAML parsing) 
  - `easy_error` → `anyhow` (better error context)
  - `lazy_static` → `std::sync::OnceLock` (standard library solution)
- **⬆️ Version Bumps**: tokio 1.47+, rustls 0.23+, clap 4.5+, and 50+ other dependency updates

## [0.9.0] - 2022-10-28

### Added
- **SOCKS UDP**: SOCKS UDP Associate support (#222)

### Changed
- Dependency updates and maintenance

## [0.8.1] - 2022-10-14

### Added
- **Performance**: Linux splice() support to avoid memory copies (#219)

### Fixed
- Zero-copy optimization for improved performance

## [0.8.0] - 2022-09-20

### Added
- **UDP Forwarding**: Experimental UDP forwarding features (#201)

### Fixed
- Removed useless transmute operations (#188)
- Fixed various bugs (#189, #190)

## [0.7.0] - 2022-07-11

### Added
- **Timeouts**: Idle timeout support with zero value to disable timeouts
- **Linux**: Experimental fwmark support on Linux
- **Milu**: Short circuit evaluation in Milu language

### Changed
- Better OS-dependent handling
- Updated log levels for accepting errors
- Added half-closed stream status indicators
- Removed unnecessary callbacks and debug prints

### Fixed
- Copy operations no longer update state on errors

## [0.6.0] - 2021-12-21

### Added
- **SOCKS Auth**: Command-based authentication (`auth_cmd`) for SOCKS listener
- **Caching**: Authentication command cache
- **TLS**: Support for both PKCS1 and PKCS8 private keys in PEM format
- Username integration into extra map

### Changed
- Renamed `auth_cmd` parameter (was `cmd`)
- Authentication flow: check userdb first, then auth_cmd

### Fixed
- Missing connector in script_ext
- Configuration examples updated

---

## Release Notes

### Version Numbering
- **Major** version increments for breaking changes
- **Minor** version increments for new features (backward compatible)
- **Patch** version increments for bug fixes (backward compatible)

### Categories
- **Added** for new features
- **Changed** for changes in existing functionality
- **Deprecated** for soon-to-be removed features
- **Removed** for now removed features
- **Fixed** for any bug fixes
- **Security** for vulnerability fixes