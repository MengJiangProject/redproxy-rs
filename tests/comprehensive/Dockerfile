# Multi-stage build for RedProxy comprehensive tests
FROM rust:latest as builder

WORKDIR /usr/src/app
COPY . .

# Build with all features for comprehensive testing
RUN cargo build --release --all-features

# Runtime stage - use Ubuntu for newer glibc
FROM ubuntu:24.04

# Install runtime dependencies for Ubuntu
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN useradd -r -s /bin/false redproxy

# Copy binary
COPY --from=builder /usr/src/app/target/release/redproxy-rs /usr/local/bin/redproxy

# Create directories
RUN mkdir -p /config /logs && chown redproxy:redproxy /logs

USER redproxy
WORKDIR /

# Use environment variable substitution in config
CMD ["redproxy", "-c", "/config/base.yaml"]