.PHONY: help test-all test-security test-performance clean build rebuild

# Export current user ID and group ID for Docker containers
export UID := $(shell id -u)
export GID := $(shell id -g)

# Generated file paths (Docker container paths)
GENERATED_DIR := config/generated
CERTS_MARKER := $(GENERATED_DIR)/.certs-generated
MATRIX_CONFIG := $(GENERATED_DIR)/matrix.yaml
LOGS_DIR := logs
IMAGE_MARKER := $(GENERATED_DIR)/.test-runner-image-built
REDPROXY_IMAGE_MARKER := $(GENERATED_DIR)/.redproxy-image-built

# Dependency files that trigger image rebuilds
DEP_FILES := scripts/pyproject.toml scripts/uv.lock Dockerfile.test-runner

# Rust source files that trigger RedProxy image rebuilds (relative to repo root)
RUST_FILES := ../../Cargo.toml ../../Cargo.lock ../../src ../../milu
REDPROXY_DEP_FILES := Dockerfile $(shell find $(RUST_FILES) -name "*.rs" -o -name "*.toml" -o -name "*.lock" 2>/dev/null || echo "")

# Default target
help:
	@echo "targets:"
	@echo "  test-security       - Security and error handling tests"
	@echo "  test-performance    - Concurrency and performance tests"
	@echo "  test-matrix         - Test all listener×connector combinations"
	@echo "  test-all            - Run all test suites"
	@echo "  clean               - Stop all services and clean up"

# Create required directories
$(LOGS_DIR):
	mkdir -p $(LOGS_DIR)

# Build test-runner image when dependencies change
$(IMAGE_MARKER): $(DEP_FILES) | $(GENERATED_DIR)
	@echo "Building test-runner image (dependencies changed)..."
	docker-compose build test-runner
	@touch $(IMAGE_MARKER)

# Build RedProxy images when Rust code changes
$(REDPROXY_IMAGE_MARKER): $(REDPROXY_DEP_FILES) | $(GENERATED_DIR)
	@echo "Building RedProxy images (Rust code changed)..."
	docker-compose build redproxy quic-proxy
	@touch $(REDPROXY_IMAGE_MARKER)

# Ensure generated directory exists
$(GENERATED_DIR):
	mkdir -p $(GENERATED_DIR)

# Generate test certificates and keys (only if not present)
$(CERTS_MARKER): scripts/generate_test_certs.py $(IMAGE_MARKER) | $(LOGS_DIR)
	@echo "Generating test certificates and SSH keys..."
	docker-compose run --rm test-runner uv run --frozen /scripts/generate_test_certs.py
	@echo "Certificate generation completed"
	@mkdir -p $(GENERATED_DIR) && touch $(CERTS_MARKER)

# Generate matrix configuration (only if certs changed or config missing)
$(MATRIX_CONFIG): scripts/matrix_generator.py $(CERTS_MARKER) $(IMAGE_MARKER)
	@echo "Generating matrix configuration..."
	docker-compose run --rm test-runner uv run --frozen /scripts/matrix_generator.py
	@echo "Matrix configuration generation completed"

# Matrix tests (all listener×connector combinations)
test-matrix: $(MATRIX_CONFIG) $(REDPROXY_IMAGE_MARKER)
	@echo "Running matrix tests..."
	REDPROXY_CONFIG=/config/generated/matrix.yaml docker-compose run --rm test-runner uv run --frozen /scripts/test_matrix.py
	@echo "Matrix tests completed"

# Security tests  
test-security: $(IMAGE_MARKER) $(REDPROXY_IMAGE_MARKER) | $(LOGS_DIR)
	@echo "Running security tests..."
	docker-compose run --rm test-runner uv run --frozen /scripts/test_security.py
	@echo "Security tests completed"

# Performance tests
test-performance: $(IMAGE_MARKER) $(REDPROXY_IMAGE_MARKER) | $(LOGS_DIR)
	@echo "Running performance tests..."
	docker-compose run --rm test-runner uv run --frozen /scripts/test_performance.py
	@echo "Performance tests completed"

# Run all tests (can be parallelized with make -j)
test-all: test-matrix test-security test-performance
	@echo "All comprehensive tests completed successfully!"

# Cleanup
clean:
	@echo "Cleaning up test environment..."
	docker-compose down -v --remove-orphans
	docker image prune -f --filter label=project=comprehensive
	rm -rf ./$(LOGS_DIR) ./$(GENERATED_DIR)
	@echo "Cleanup completed"