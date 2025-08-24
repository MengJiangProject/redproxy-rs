FROM rust:latest AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy source code
COPY . .

# Build the application
RUN cargo build --release --features "quic metrics embedded-ui"

# Runtime stage - use Debian slim for glibc compatibility
FROM debian:stable-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the binary
COPY --from=builder /app/target/release/redproxy-rs /app/redproxy-rs

# Make it executable
RUN chmod +x /app/redproxy-rs

# Expose ports
EXPOSE 8800 1081

CMD ["/app/redproxy-rs", "-c", "/app/config.yaml"]