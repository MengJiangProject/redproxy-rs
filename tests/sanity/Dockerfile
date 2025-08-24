FROM rust:latest AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy source code
COPY . .

# Build the application (minimal features for sanity tests - just core proxy functionality)
RUN cargo build --release --no-default-features

# Runtime stage - use Debian slim for glibc compatibility
FROM debian:stable-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -g 1000 redproxy && \
    useradd -d /app -s /bin/bash -u 1000 -g redproxy redproxy

WORKDIR /app

# Copy the binary
COPY --from=builder /app/target/release/redproxy-rs /app/redproxy-rs

# Set ownership
RUN chown redproxy:redproxy /app/redproxy-rs

USER redproxy

# Expose ports
EXPOSE 8800 1081

CMD ["/app/redproxy-rs", "-c", "/app/config.yaml"]