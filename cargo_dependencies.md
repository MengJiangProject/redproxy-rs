# Cargo Dependencies

This file lists the Rust dependencies and their versions as specified in `Cargo.toml`.

**Note:** The versions listed here are as per the `Cargo.toml` file at the time of generation. It is recommended to manually check these versions against [crates.io](https://crates.io/) to ensure they are up-to-date and to identify any potentially outdated dependencies.

## Main Dependencies

*   tokio: 1.45.1
*   tokio-rustls: 0.26
*   rustls: 0.23
*   tokio-util: 0.7
*   bytes: 1.4.0
*   rustls-pemfile: 2.2
*   webpki-roots: 1.0
*   async-trait: 0.1
*   easy-error: 1.0
*   tracing: 0.1
*   tracing-subscriber: 0.3
*   yaml-rust: 0.4
*   serde: 1.0
*   serde_yaml_ng: 0.10
*   serde_json: 1.0
*   clap: 4.5
*   futures: 0.3.25
*   cidr: 0.3
*   rand: 0.9
*   libc: 0.2
*   hickory-resolver: 0.25
*   chashmap-async: 0.1.0
*   lru: 0.14
*   milu: (local path, not a crates.io version)

## Optional Dependencies (Features)

### QUIC Feature
*   quinn: 0.11
*   futures-util: 0.3.24
*   pin-project-lite: 0.2.9

### Metrics Feature
*   axum: 0.8
*   tower: 0.5
*   tower-http: 0.6
*   prometheus: 0.14
*   lazy_static: 1

## Target-Specific Dependencies

### Not Windows (`cfg(not(target_os = "windows"))`)
*   nix: 0.30

### Windows (`cfg(target_os = "windows")`)
*   winapi: 0.3.9
