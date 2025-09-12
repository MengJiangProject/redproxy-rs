.PHONY: help test-all test-security test-performance test-httpx test-matrix test-bind clean cleanup-redproxy output-dirs

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
RUNNER_DEP_FILES := scripts/pyproject.toml Dockerfile.test-runner

# Rust source files that trigger RedProxy image rebuilds (relative to repo root)
RUST_SRC :=  ../../src ../../milu
REDPROXY_DEP_FILES := Dockerfile ../../Cargo.toml ../../Cargo.lock $(shell find $(RUST_SRC) -name "*.rs" -o -name "Cargo.toml" -o -name "Cargo.lock" 2>/dev/null || echo "")


# Default target
help:
	@echo "pytest-based test targets:"
	@echo "  test-httpx          - HttpX listener tests"
	@echo "  test-security       - Security and error handling tests"
	@echo "  test-performance    - Concurrency and performance tests"
	@echo "  test-matrix         - Test all listener&connector combinations"
	@echo "  test-bind           - SOCKS BIND functionality tests"
	@echo "  test-all            - Run all test suites"
	@echo "  clean               - Stop all services and clean up"

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
$(MATRIX_CONFIG): scripts/generate_matrix_config.py $(CERTS_MARKER) $(RUNNER_IMAGE)
	@echo "Generating matrix configuration..."
	docker-compose run --rm test-runner uv run --frozen /scripts/generate_matrix_config.py
	@echo "Matrix configuration generation completed"

# Stop any running redproxy containers (cleanup before parallel tests)
cleanup-redproxy:
	@echo "Cleaning up any running redproxy containers..."
	docker-compose stop redproxy 2>/dev/null || true

# Matrix tests (all listener×connector combinations) - NEW PYTEST FORMAT
test-matrix: $(MATRIX_CONFIG) $(RUNNER_IMAGE) $(REDPROXY_IMAGE) output-dirs cleanup-redproxy
	@echo "Running matrix tests (pytest)..."
	REDPROXY_CONFIG=/config/generated/matrix.yaml docker-compose run --rm test-runner \
		uv run --frozen pytest tests/matrix \
		--html=/reports/matrix-report.html --self-contained-html \
		--junitxml=/reports/matrix-junit.xml \
		--json-report --json-report-file=/reports/matrix.json \
		$(ARGS)
	@echo "Matrix tests completed - reports generated in ./reports/"

# Security tests - NEW PYTEST FORMAT  
test-security: $(RUNNER_IMAGE) $(REDPROXY_IMAGE) output-dirs cleanup-redproxy
	@echo "Running security tests (pytest)..."
	REDPROXY_CONFIG=/config/base.yaml docker-compose run --rm test-runner \
		uv run --frozen pytest tests/security \
		--html=/reports/security-report.html --self-contained-html \
		--junitxml=/reports/security-junit.xml \
		--json-report --json-report-file=/reports/security.json \
		$(ARGS)
	@echo "Security tests completed - reports generated in ./reports/"

# Performance tests - NEW PYTEST FORMAT (with reduced logging)
test-performance: $(RUNNER_IMAGE) $(REDPROXY_IMAGE) output-dirs cleanup-redproxy
	@echo "Running performance tests (pytest) with reduced logging..."
	REDPROXY_CONFIG=/config/base.yaml docker-compose run --rm test-runner \
		uv run --frozen pytest tests/performance \
		--html=/reports/performance-report.html --self-contained-html \
		--junitxml=/reports/performance-junit.xml \
		--json-report --json-report-file=/reports/performance.json \
		--tb=short --disable-warnings -q \
		$(ARGS)
	@echo "Performance tests completed - reports generated in ./reports/"

# HttpX component tests
test-httpx: $(RUNNER_IMAGE) $(REDPROXY_IMAGE) output-dirs cleanup-redproxy
	@echo "Running HttpX component tests..."
	REDPROXY_CONFIG=/config/httpx.yaml docker-compose run --rm test-runner \
		uv run --frozen pytest tests/httpx \
		--html=/reports/httpx-report.html --self-contained-html \
		--junitxml=/reports/httpx-junit.xml \
		--json-report --json-report-file=/reports/httpx.json \
		$(ARGS)
	@echo "HttpX tests completed - reports generated in ./reports/"


# BIND functionality tests - NEW PYTEST FORMAT
test-bind: $(RUNNER_IMAGE) $(REDPROXY_IMAGE) output-dirs cleanup-redproxy
	@echo "Running BIND functionality tests..."
	REDPROXY_CONFIG=/config/bind-test.yaml docker-compose run --rm test-runner \
		uv run --frozen pytest tests/bind \
		--html=/reports/bind-report.html --self-contained-html \
		--junitxml=/reports/bind-junit.xml \
		--json-report --json-report-file=/reports/bind.json \
		$(ARGS)
	@echo "BIND tests completed - reports generated in ./reports/"

# Run all tests (can be parallelized with make -j)
test-all: test-matrix test-security test-performance test-httpx test-bind
	@echo "All comprehensive tests completed successfully!"

# Cleanup
clean:
	@echo "Cleaning up test environment..."
	docker-compose down -v --remove-orphans
	docker image prune -f --filter label=project=comprehensive
	rm -rf ./$(LOGS_DIR) ./$(GENERATED_DIR) ./$(REPORTS_DIR)
	@echo "Cleanup completed"