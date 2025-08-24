FROM rust:1.75-alpine AS builder

# Install build dependencies
RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static pkgconfig

WORKDIR /app

# Copy source code
COPY . .

# Build the application
RUN cargo build --release --features "quic metrics embedded-ui"

# Runtime stage
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache ca-certificates

WORKDIR /app

# Copy the binary
COPY --from=builder /app/target/release/redproxy-rs /app/redproxy-rs

# Make it executable
RUN chmod +x /app/redproxy-rs

# Expose ports
EXPOSE 8800 1081

CMD ["/app/redproxy-rs", "-c", "/app/config.yaml"]