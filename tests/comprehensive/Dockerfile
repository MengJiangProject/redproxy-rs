FROM rust:latest AS chef 
# We only pay the installation cost once, 
# it will be cached from the second build onwards
RUN cargo install cargo-chef 
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare  --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json

# Build dependencies - this is the caching Docker layer!
RUN cargo chef cook --recipe-path recipe.json

# Build application
COPY . .
RUN cargo build --all-features

# Runtime stage - use Debian to match test runner
FROM debian:stable-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    gdb lldb \
    lsof \
    && rm -rf /var/lib/apt/lists/*

# Create user with dynamic UID/GID
ARG UID=1000
ARG GID=1000
RUN groupadd -g ${GID} redproxy 2>/dev/null || true
RUN useradd -u ${UID} -g ${GID} -m -s /bin/false redproxy 2>/dev/null || true

# Copy binary
COPY --from=builder /app/target/debug/redproxy-rs /usr/local/bin/redproxy

USER ${UID}:${GID}
WORKDIR /

# Use environment variable substitution in config
CMD ["redproxy", "-c", "/config/base.yaml"]