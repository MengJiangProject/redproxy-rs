#!/bin/sh
# Protocol tests for RedProxy comprehensive suite
# Tests HTTP CONNECT and SOCKS5 protocols with different connectors

set -e

# Load shared library
. /scripts/lib/common.sh

log_test "Protocol Tests - HTTP CONNECT and SOCKS5"

# Test 1: HTTP CONNECT to echo server (direct connector)
log_test "Test 1: HTTP CONNECT direct connection"
if test_http_connect "$REDPROXY_HOST" "$REDPROXY_HTTP_PORT" \
    "http://$HTTP_ECHO_HOST:$HTTP_ECHO_PORT/" "Hello from HTTP echo server"; then
    log_info "HTTP CONNECT direct connection works"
else
    log_error "HTTP CONNECT direct connection failed"
    exit 1
fi

# Test 2: HTTP CONNECT through upstream HTTP proxy
log_test "Test 2: HTTP CONNECT through upstream HTTP proxy"
if test_http_connect "$REDPROXY_HOST" "$REDPROXY_HTTP_PORT" \
    "http://$TARGET_HOST:$TARGET_PORT/" "nginx"; then
    log_info "HTTP CONNECT through upstream HTTP proxy works"
else
    log_error "HTTP CONNECT through upstream HTTP proxy failed"
    exit 1
fi

# Test 3: SOCKS5 proxy functionality
log_test "Test 3: SOCKS5 proxy through upstream SOCKS"
if test_socks_proxy "$REDPROXY_HOST" "$REDPROXY_SOCKS_PORT" \
    "http://$TARGET_HOST:$TARGET_PORT/" "nginx"; then
    log_info "SOCKS5 proxy through upstream SOCKS works"
else
    log_error "SOCKS5 proxy through upstream SOCKS failed"
    exit 1
fi

# Test 4: Verify upstream proxies work directly
log_test "Test 4: Verify upstream proxies"
if test_http_connect "http-proxy" 3128 \
    "http://$TARGET_HOST:$TARGET_PORT/" "nginx"; then
    log_info "Upstream HTTP proxy is working"
else
    log_error "Upstream HTTP proxy failed"
    exit 1
fi

if test_socks_proxy "socks-proxy" 1080 \
    "http://$TARGET_HOST:$TARGET_PORT/" "nginx"; then
    log_info "Upstream SOCKS proxy is working"  
else
    log_error "Upstream SOCKS proxy failed"
    exit 1
fi

# Test 5: Protocol chaining test
log_test "Test 5: Complex routing test"
if test_socks_proxy "$REDPROXY_HOST" "$REDPROXY_SOCKS_PORT" \
    "http://$HTTP_ECHO_HOST:$HTTP_ECHO_PORT/" "Hello from HTTP echo server"; then
    log_info "Complex routing works"
else
    log_error "Complex routing failed"
    exit 1
fi

log_info "All protocol tests passed!"