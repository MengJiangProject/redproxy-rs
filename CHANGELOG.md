# Changelog

All notable changes to redproxy-rs will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] - 0.10.0

### Added
- Nix development environment with direnv support
- Default devShell with complete Rust toolchain (cargo, rustc, clippy, rustfmt, rust-src)

### Changed
- **Major Refactoring**: Refactored main.rs for improved testability and maintainability
- **Architecture**: Refactored connector architecture with improved socket abstraction
- **Testing**: Enhanced connector testing framework and socket operations testing
- **Performance**: Improved LoadBalanceConnector dependency injection with OnceLock
- **Modernization**: Replaced lazy_static with std::sync::OnceLock throughout codebase
- **Memory**: Optimized buffer allocation for zero-copy performance improvement
- **Error Handling**: Migrated from easy_error to anyhow for improved error handling
- **Code Quality**: Refactored GlobalState to eliminate God Object anti-pattern
- Modernized Rust code with let-chains pattern matching for cleaner nested conditions
- Improved TPROXY listener error handling with proper error chains (`.source()` vs deprecated `.cause`)
- Updated flake.lock with latest Nix dependencies
- Code formatting and minor improvements

### Removed
- **Safety**: Eliminated dangerous panic! calls in production code
- **Stability**: Eliminated dangerous unwrap() calls to prevent production crashes
- Unused `NoAuth` struct from SOCKS implementation (superseded by `PasswordAuth` for better client compatibility)

### Fixed
- HTTP test reliability issues
- Socket operations and connector testing edge cases
- Windows build compatibility issues
- Cross-compilation setup and CI workflow improvements
- Import path for `set_keepalive` function in TPROXY listener
- Unused parameter warnings in TPROXY TCP accept method
- Added missing Debug derives for internal structs

### Dependencies
- Updated Rust edition to 2024
- Bumped major dependencies: tokio, rustls, clap, serde, and others
- Replaced trust-dns-resolver with hickory-resolver for DNS handling
- Replaced serde_yaml with serde_yaml_ng for improved YAML handling

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