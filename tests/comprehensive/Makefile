.PHONY: help test-all test-protocols test-security test-performance clean logs status

# Default target
help:
	@echo "RedProxy Comprehensive Test Suite (Simplified)"
	@echo "=============================================="
	@echo ""
	@echo "Test targets:"
	@echo "  test-protocols    - HTTP CONNECT and SOCKS5 protocol tests"
	@echo "  test-security     - Security and error handling tests"
	@echo "  test-performance  - Concurrency and performance tests"
	@echo "  test-all          - Run all test suites"
	@echo ""
	@echo "Utility targets:"
	@echo "  clean             - Stop all services and clean up"
	@echo "  logs              - View redproxy logs"
	@echo "  status            - Show running services"
	@echo ""
	@echo "Environment variables:"
	@echo "  VERBOSE=true      - Enable verbose output"
	@echo ""
	@echo "Examples:"
	@echo "  make test-protocols"
	@echo "  VERBOSE=true make test-security"
	@echo "  make -j3 test-all  # Run tests in parallel"

# Create required directories
create-logs:
	mkdir -p logs

# Protocol tests
test-protocols: create-logs
	@echo "Running protocol tests..."
	TEST_SUITE=protocols docker-compose up --abort-on-container-exit --remove-orphans test-runner
	@echo "Protocol tests completed"

# Security tests  
test-security: create-logs
	@echo "Running security tests..."
	TEST_SUITE=security docker-compose up --abort-on-container-exit --remove-orphans test-runner
	@echo "Security tests completed"

# Performance tests
test-performance: create-logs
	@echo "Running performance tests..."
	TEST_SUITE=performance docker-compose up --abort-on-container-exit --remove-orphans test-runner
	@echo "Performance tests completed"

# Run all tests (can be parallelized with make -j)
test-all: test-protocols test-security test-performance
	@echo "All comprehensive tests completed successfully!"

# View logs
logs:
	docker-compose logs -f redproxy

# Show status
status:
	@echo "=== Running Services ==="
	docker-compose ps

# Cleanup
clean:
	@echo "Cleaning up test environment..."
	docker-compose down -v --remove-orphans
	rm -rf ./logs
	@echo "Cleanup completed"