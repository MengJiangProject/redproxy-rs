.PHONY: help test-all test-essential test-quic test-mtls test-loadbalancer test-rules test-linux test-performance clean logs
.PHONY: svc-cert-generator svc-target-nginx svc-target-websocket svc-target-blocked
.PHONY: svc-upstream-http svc-upstream-socks5 svc-upstream-quic svc-upstream-mtls
.PHONY: svc-upstream-lb-1 svc-upstream-lb-2 svc-upstream-lb-3
.PHONY: svc-redproxy-essential svc-redproxy-features svc-redproxy-quic svc-redproxy-mtls
.PHONY: svc-redproxy-loadbalancer svc-redproxy-rules svc-redproxy-linux svc-redproxy-performance

# Default target
help:
	@echo "RedProxy Comprehensive Test Suite (Unified Architecture)"
	@echo "========================================================"
	@echo ""
	@echo "Test targets:"
	@echo "  test-essential     - Essential features (HTTP, SOCKS5, basic routing)"
	@echo "  test-quic         - QUIC protocol support"
	@echo "  test-mtls         - Mutual TLS authentication"
	@echo "  test-loadbalancer - Load balancing algorithms"
	@echo "  test-rules        - Milu rule engine"
	@echo "  test-linux        - Linux-specific features (TPROXY, splice)"
	@echo "  test-performance  - Performance benchmarks"
	@echo "  test-all          - Run complete test suite"
	@echo ""
	@echo "Service management:"
	@echo "  clean             - Stop all services and clean up"
	@echo "  logs SERVICE=name - View logs for a service"
	@echo ""
	@echo "Parallel execution:"
	@echo "  make -j4 test-all - Run tests in parallel"

# Certificate generation - prerequisite for TLS tests
certificates/.generated:
	@echo "Generating certificates..."
	mkdir -p certificates test-results logs
	chmod 777 logs
	docker-compose up cert-generator
	touch $@

# Service startup targets with health checks
svc-cert-generator: certificates/.generated

svc-target-nginx:
	@echo "Starting nginx target server..."
	docker-compose up -d target-nginx

svc-target-websocket:
	@echo "Starting websocket target server..."
	docker-compose up -d target-websocket

svc-target-blocked:
	@echo "Starting blocked target server..."
	docker-compose up -d target-blocked

svc-upstream-http:
	@echo "Starting upstream HTTP proxy..."
	docker-compose up -d upstream-http

svc-upstream-socks5:
	@echo "Starting upstream SOCKS5 proxy..."
	docker-compose up -d upstream-socks5

svc-upstream-quic: svc-cert-generator
	@echo "Starting upstream QUIC proxy..."
	docker-compose up -d upstream-quic

svc-upstream-mtls: svc-cert-generator
	@echo "Starting upstream mTLS proxy..."
	docker-compose up -d upstream-mtls

svc-upstream-lb-1:
	@echo "Starting load balancer upstream 1..."
	docker-compose up -d upstream-lb-1

svc-upstream-lb-2:
	@echo "Starting load balancer upstream 2..."
	docker-compose up -d upstream-lb-2

svc-upstream-lb-3:
	@echo "Starting load balancer upstream 3..."
	docker-compose up -d upstream-lb-3

svc-redproxy-essential: svc-target-nginx
	@echo "Starting RedProxy essential..."
	docker-compose up -d redproxy-essential

svc-redproxy-features: svc-target-nginx
	@echo "Starting RedProxy with full features..."
	docker-compose up -d redproxy-features

svc-redproxy-quic: svc-cert-generator svc-target-nginx
	@echo "Starting RedProxy QUIC..."
	docker-compose up -d redproxy-quic

svc-redproxy-mtls: svc-cert-generator svc-target-nginx
	@echo "Starting RedProxy mTLS..."
	docker-compose up -d redproxy-mtls

svc-redproxy-loadbalancer: svc-upstream-lb-1 svc-upstream-lb-2 svc-upstream-lb-3
	@echo "Starting RedProxy load balancer..."
	docker-compose up -d redproxy-loadbalancer

svc-redproxy-rules: svc-target-nginx svc-target-blocked
	@echo "Starting RedProxy rules engine..."
	docker-compose up -d redproxy-rules

svc-redproxy-linux: svc-target-nginx
	@echo "Starting RedProxy Linux features..."
	@if [ "$$(uname)" != "Linux" ]; then \
		echo "Warning: Linux-specific tests require Linux system"; \
		exit 1; \
	fi
	docker-compose up -d redproxy-linux

svc-redproxy-performance: svc-target-nginx
	@echo "Starting RedProxy for performance testing..."
	docker-compose up -d redproxy-performance

# Test targets with precise dependencies
test-essential: svc-redproxy-essential svc-redproxy-features svc-target-websocket svc-upstream-http svc-upstream-socks5
	@echo "Running essential feature tests..."
	mkdir -p test-results
	docker-compose run --rm tester-essential
	@echo "Essential tests completed successfully"

test-quic: svc-redproxy-quic svc-upstream-quic
	@echo "Running QUIC protocol tests..."
	mkdir -p test-results
	docker-compose run --rm tester-quic
	@echo "QUIC tests completed successfully"

test-mtls: svc-redproxy-mtls svc-upstream-mtls
	@echo "Running mTLS security tests..."
	mkdir -p test-results
	docker-compose run --rm tester-mtls
	@echo "mTLS tests completed successfully"

test-loadbalancer: svc-redproxy-loadbalancer
	@echo "Running load balancer tests..."
	mkdir -p test-results
	docker-compose run --rm tester-loadbalancer
	@echo "Load balancer tests completed successfully"

test-rules: svc-redproxy-rules
	@echo "Running Milu rule engine tests..."
	mkdir -p test-results
	docker-compose run --rm tester-rules
	@echo "Rules tests completed successfully"

test-linux: svc-redproxy-linux
	@echo "Running Linux-specific tests..."
	mkdir -p test-results
	docker-compose run --rm tester-linux
	@echo "Linux tests completed successfully"

test-performance: svc-redproxy-performance
	@echo "Running performance benchmarks..."
	mkdir -p test-results
	docker-compose run --rm tester-performance
	@echo "Performance tests completed successfully"

# Run all tests - can be parallelized with make -j
test-all: test-essential test-quic test-mtls test-loadbalancer test-rules test-linux test-performance
	@echo "All comprehensive tests completed successfully!"

# Cleanup
clean:
	@echo "Cleaning up test environment..."
	docker-compose --profile manual down -v --remove-orphans
	rm -rf ./test-results ./certificates ./logs
	@echo "Cleanup completed"

# View logs for a specific service
logs:
	@if [ -z "$(SERVICE)" ]; then \
		echo "Usage: make logs SERVICE=service-name"; \
		echo "Available services: redproxy-essential redproxy-quic redproxy-mtls target-nginx upstream-http etc."; \
		exit 1; \
	fi
	docker-compose logs -f $(SERVICE)

# Show running services
status:
	@echo "=== Running Services ==="
	docker-compose ps

# Show dependency graph (dry run)
show-deps:
	@echo "Use 'make -n test-TARGET' to see dependency execution order"
	@echo "Example: make -n test-all"