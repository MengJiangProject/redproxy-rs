# Multi-stage build for RedProxy comprehensive tests
FROM rust:latest as builder

WORKDIR /usr/src/app

# Copy manifest files first for better layer caching
COPY Cargo.toml Cargo.lock ./
COPY milu/ milu/

# Fetch dependencies first (cached layer)
RUN cargo fetch

# Copy source code
COPY . .

# Build with all features for comprehensive testing
RUN cargo build --release --all-features

# Runtime stage - use Debian to match test runner
FROM debian:stable-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create user with dynamic UID/GID
ARG UID=1000
ARG GID=1000
RUN groupadd -g ${GID} redproxy 2>/dev/null || true
RUN useradd -u ${UID} -g ${GID} -m -s /bin/false redproxy 2>/dev/null || true

# Copy binary
COPY --from=builder /usr/src/app/target/release/redproxy-rs /usr/local/bin/redproxy

USER ${UID}:${GID}
WORKDIR /

# Use environment variable substitution in config
CMD ["redproxy", "-c", "/config/base.yaml"]