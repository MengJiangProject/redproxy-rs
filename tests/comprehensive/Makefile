.PHONY: help test-all test-security test-performance test-httpx test-matrix clean build rebuild output-dirs

# Export current user ID and group ID for Docker containers
export UID := $(shell id -u)
export GID := $(shell id -g)

# Generate version string with git hash
CARGO_VERSION := $(shell grep -E '^version = ' ../../Cargo.toml | head -n1 | sed 's/version = "\(.*\)"/\1/')
GIT_HASH := $(shell cd ../.. && git rev-parse --short HEAD 2>/dev/null || echo "unknown")
GIT_DIRTY := $(shell cd ../.. && git diff --quiet 2>/dev/null || echo "-dirty")
export REDPROXY_VERSION := $(CARGO_VERSION)-$(GIT_HASH)$(GIT_DIRTY)

# Generated file paths (Docker container paths)
GENERATED_DIR := config/generated
CERTS_MARKER := $(GENERATED_DIR)/.certs-generated
MATRIX_CONFIG := $(GENERATED_DIR)/matrix.yaml
LOGS_DIR := logs
REPORTS_DIR := reports
RUNNER_IMAGE := $(GENERATED_DIR)/.test-runner-image-built
REDPROXY_IMAGE := $(GENERATED_DIR)/.redproxy-image-built

# Dependency files that trigger image rebuilds
RUNNER_DEP_FILES := scripts/pyproject.toml scripts/uv.lock Dockerfile.test-runner

# Rust source files that trigger RedProxy image rebuilds (relative to repo root)
RUST_SRC :=  ../../src ../../milu
REDPROXY_DEP_FILES := Dockerfile ../../Cargo.toml ../../Cargo.lock $(shell find $(RUST_SRC) -name "*.rs" -o -name "Cargo.toml" -o -name "Cargo.lock" 2>/dev/null || echo "")

# Default target
help:
	@echo "targets:"
	@echo "  test-httpx          - HttpX listener comprehensive tests"
	@echo "                        Use ARGS='--tests connect forward' for selective tests"
	@echo "                        Use ARGS='--list' to see available test suites"
	@echo "  test-security       - Security and error handling tests"
	@echo "  test-performance    - Concurrency and performance tests"
	@echo "  test-matrix         - Test all listener×connector combinations"
	@echo "  test-all            - Run all test suites"
	@echo "  clean               - Stop all services and clean up"
	@echo ""
	@echo "examples:"
	@echo "  make test-httpx                                    # Run all HttpX tests"
	@echo "  make test-httpx ARGS='--tests connect forward'    # Run only CONNECT and forward tests"
	@echo "  make test-httpx ARGS='--tests destructive'        # Run only error handling tests"
	@echo "  make test-httpx ARGS='--list'                     # List available test suites"

# Create required directories
$(LOGS_DIR):
	mkdir -p $(LOGS_DIR)

$(REPORTS_DIR):
	mkdir -p $(REPORTS_DIR)

$(GENERATED_DIR):
	mkdir -p $(GENERATED_DIR)

# Create output directories
output-dirs: $(LOGS_DIR) $(REPORTS_DIR) $(GENERATED_DIR)

# Build test-runner image when dependencies change
$(RUNNER_IMAGE): $(RUNNER_DEP_FILES) output-dirs
	@echo "Building test-runner image (dependencies changed)..."
	docker-compose build test-runner
	@touch $(RUNNER_IMAGE)

# Build RedProxy images when Rust code changes
$(REDPROXY_IMAGE): $(REDPROXY_DEP_FILES) output-dirs
	@echo "Building RedProxy images (Rust code changed)..."
	docker-compose build redproxy quic-proxy
	@touch $(REDPROXY_IMAGE)

# Generate test certificates and keys (only if not present)
$(CERTS_MARKER): scripts/generate_test_certs.py $(RUNNER_IMAGE) output-dirs
	@echo "Generating test certificates and SSH keys..."
	docker-compose run --rm test-runner uv run --frozen /scripts/generate_test_certs.py
	@echo "Certificate generation completed"
	@touch $(CERTS_MARKER)

# Generate matrix configuration (only if certs changed or config missing)
$(MATRIX_CONFIG): scripts/matrix_generator.py $(CERTS_MARKER) $(RUNNER_IMAGE)
	@echo "Generating matrix configuration..."
	docker-compose run --rm test-runner uv run --frozen /scripts/matrix_generator.py
	@echo "Matrix configuration generation completed"

# Matrix tests (all listener×connector combinations)
test-matrix: $(MATRIX_CONFIG) $(RUNNER_IMAGE) $(REDPROXY_IMAGE)
	@echo "Running matrix tests..."
	REDPROXY_CONFIG=/config/generated/matrix.yaml docker-compose run --rm test-runner uv run --frozen /scripts/test_matrix.py
	@echo "Matrix tests completed"

# Security tests  
test-security: $(RUNNER_IMAGE) $(REDPROXY_IMAGE)
	@echo "Running security tests..."
	docker-compose run --rm test-runner uv run --frozen /scripts/test_security.py $(ARGS)
	@echo "Security tests completed"

# Performance tests
test-performance: $(RUNNER_IMAGE) $(REDPROXY_IMAGE)
	@echo "Running performance tests..."
	docker-compose run --rm test-runner uv run --frozen /scripts/test_performance.py $(ARGS)
	@echo "Performance tests completed"

# HttpX listener tests
test-httpx: $(RUNNER_IMAGE) $(REDPROXY_IMAGE)
	@echo "Running HttpX listener tests..."
	REDPROXY_CONFIG=/config/httpx.yaml docker-compose run --rm test-runner uv run --frozen /scripts/test_httpx_listener.py $(ARGS)
	@echo "HttpX listener tests completed"

# Run all tests (can be parallelized with make -j)
test-all: test-matrix test-security test-performance test-httpx
	@echo "All comprehensive tests completed successfully!"

# Cleanup
clean:
	@echo "Cleaning up test environment..."
	docker-compose down -v --remove-orphans
	docker image prune -f --filter label=project=comprehensive
	rm -rf ./$(LOGS_DIR) ./$(GENERATED_DIR) ./$(REPORTS_DIR)
	@echo "Cleanup completed"