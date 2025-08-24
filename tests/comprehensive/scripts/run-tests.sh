#!/bin/bash
# Main test runner for RedProxy comprehensive tests
# Selects test suite based on TEST_SUITE environment variable

set -e

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load shared library
# shellcheck source=lib/common.sh
. "$SCRIPT_DIR/lib/common.sh"

# Setup test environment
setup_test_env

log_info "=== RedProxy Comprehensive Test Runner ==="
log_info "Test Suite: ${TEST_SUITE:-protocols}"
log_info "Verbose: $VERBOSE"
echo

# Wait for all services to be ready
log_info "Waiting for services to be ready..."
wait_for_service "$HTTP_ECHO_HOST" "$HTTP_ECHO_PORT"
wait_for_service "$TARGET_HOST" "$TARGET_PORT"  
wait_for_service "http-proxy" 3128
wait_for_service "socks-proxy" 1080
wait_for_service "$REDPROXY_HOST" "$REDPROXY_HTTP_PORT"
wait_for_service "$REDPROXY_HOST" "$REDPROXY_SOCKS_PORT"
echo

# Route to appropriate test suite
case "${TEST_SUITE:-protocols}" in
    "protocols")
        log_info "Running protocol tests..."
        "$SCRIPT_DIR/test-protocols.sh"
        ;;
    "security")
        log_info "Running security tests..."  
        "$SCRIPT_DIR/test-security.sh"
        ;;
    "performance")
        log_info "Running performance tests..."
        "$SCRIPT_DIR/test-performance.sh"
        ;;
    *)
        log_error "Unknown test suite: $TEST_SUITE"
        log_error "Available suites: protocols, security, performance"
        exit 1
        ;;
esac

# Cleanup
cleanup_test

log_info "All tests completed successfully!"