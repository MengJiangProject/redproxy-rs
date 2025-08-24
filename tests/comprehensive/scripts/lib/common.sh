#!/bin/sh
# Shared test library for RedProxy comprehensive tests
# Provides reusable functions to eliminate code duplication

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo "${GREEN}✓${NC} $1"
}

log_warn() {
    echo "${YELLOW}⚠${NC} $1"
}

log_error() {
    echo "${RED}✗${NC} $1"
}

log_test() {
    echo "${YELLOW}=== $1 ===${NC}"
}

# Service health check
wait_for_service() {
    local host=$1
    local port=$2
    local timeout=${3:-30}
    local count=0
    
    log_info "Waiting for $host:$port..."
    while ! nc -z "$host" "$port" 2>/dev/null; do
        if [ $count -ge $timeout ]; then
            log_error "Timeout waiting for $host:$port"
            return 1
        fi
        sleep 1
        count=$((count + 1))
    done
    log_info "$host:$port is ready"
}

# HTTP test functions
test_http_connect() {
    local proxy_host=$1
    local proxy_port=$2
    local target_url=$3
    local expected_text=$4
    
    response=$(curl -x "$proxy_host:$proxy_port" --connect-timeout 10 -s "$target_url")
    if echo "$response" | grep -q "$expected_text"; then
        return 0
    else
        log_error "HTTP CONNECT test failed"
        log_error "Response: $response"
        return 1
    fi
}

# SOCKS test functions  
test_socks_proxy() {
    local proxy_host=$1
    local proxy_port=$2
    local target_url=$3
    local expected_text=$4
    
    response=$(curl --socks5 "$proxy_host:$proxy_port" --connect-timeout 10 -s "$target_url")
    if echo "$response" | grep -q "$expected_text"; then
        return 0
    else
        log_error "SOCKS proxy test failed"
        log_error "Response: $response"
        return 1
    fi
}

# Concurrent test helper
test_concurrent() {
    local test_func=$1
    local count=${2:-5}
    local pids=""
    
    log_info "Running $count concurrent tests..."
    
    for i in $(seq 1 $count); do
        ($test_func > "/tmp/test_$i.out" 2>&1) &
        pids="$pids $!"
    done
    
    # Wait for all tests
    for pid in $pids; do
        wait $pid
    done
    
    # Check results
    success_count=0
    for i in $(seq 1 $count); do
        if [ -f "/tmp/test_$i.out" ]; then
            success_count=$((success_count + 1))
        fi
    done
    
    if [ $success_count -eq $count ]; then
        log_info "All $count concurrent tests succeeded"
        return 0
    else
        log_error "Only $success_count/$count concurrent tests succeeded"
        return 1
    fi
}

# Error handling test  
test_error_handling() {
    local proxy_host=$1
    local proxy_port=$2
    
    set +e
    curl -x "$proxy_host:$proxy_port" --connect-timeout 5 -s http://nonexistent-host:80/ > /dev/null 2>&1
    error_code=$?
    set -e
    
    if [ $error_code -ne 0 ]; then
        log_info "Error handling test passed (properly rejected invalid request)"
        return 0
    else
        log_error "Error handling test failed (should have rejected invalid request)"
        return 1
    fi
}

# Test environment setup
setup_test_env() {
    # Install required tools
    apk add --no-cache curl netcat-openbsd >/dev/null 2>&1 || {
        log_warn "Could not install test tools (may already be installed)"
    }
    
    # Create log directory
    mkdir -p /logs
    
    # Set default values
    REDPROXY_HOST=${REDPROXY_HOST:-redproxy}
    REDPROXY_HTTP_PORT=${REDPROXY_HTTP_PORT:-8800}
    REDPROXY_SOCKS_PORT=${REDPROXY_SOCKS_PORT:-1081}
    HTTP_ECHO_HOST=${HTTP_ECHO_HOST:-http-echo}
    HTTP_ECHO_PORT=${HTTP_ECHO_PORT:-8080}
    TARGET_HOST=${TARGET_HOST:-target-server}
    TARGET_PORT=${TARGET_PORT:-80}
    VERBOSE=${VERBOSE:-false}
}

# Cleanup function
cleanup_test() {
    # Clean up temporary files
    rm -f /tmp/test_*.out
    log_info "Test cleanup completed"
}