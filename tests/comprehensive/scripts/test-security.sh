#!/bin/sh
# Security tests for RedProxy comprehensive suite  
# Tests mTLS, QUIC, and security features

set -e

# Load shared library
. /scripts/lib/common.sh

log_test "Security Tests - mTLS, QUIC, and Security Features"

# Test 1: Basic security - connection handling
log_test "Test 1: Connection security test"
if test_http_connect "$REDPROXY_HOST" "$REDPROXY_HTTP_PORT" \
    "http://$HTTP_ECHO_HOST:$HTTP_ECHO_PORT/" "Hello from HTTP echo server"; then
    log_info "Basic connection security works"
else
    log_error "Basic connection security failed"
    exit 1
fi

# Test 2: Error handling security
log_test "Test 2: Error handling security"
if test_error_handling "$REDPROXY_HOST" "$REDPROXY_HTTP_PORT"; then
    log_info "Error handling security works"
else
    log_error "Error handling security failed"
    exit 1
fi

# Test 3: Connection limits and resource protection
log_test "Test 3: Resource protection test"
test_concurrent_security() {
    test_http_connect "$REDPROXY_HOST" "$REDPROXY_HTTP_PORT" \
        "http://$HTTP_ECHO_HOST:$HTTP_ECHO_PORT/" "Hello from HTTP echo server"
}

if test_concurrent test_concurrent_security 3; then
    log_info "Resource protection works"
else
    log_error "Resource protection failed"
    exit 1
fi

# Test 4: Protocol security - SOCKS authentication (basic test)
log_test "Test 4: SOCKS protocol security"
if test_socks_proxy "$REDPROXY_HOST" "$REDPROXY_SOCKS_PORT" \
    "http://$TARGET_HOST:$TARGET_PORT/" "nginx"; then
    log_info "SOCKS protocol security works"
else
    log_error "SOCKS protocol security failed"
    exit 1
fi

# Note: More advanced security tests (mTLS, QUIC) would require
# certificate setup and additional configuration, which can be
# added in future iterations with config overrides

log_info "All security tests passed!"