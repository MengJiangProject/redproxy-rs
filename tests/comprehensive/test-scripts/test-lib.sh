#!/bin/bash
# Shared test library for RedProxy comprehensive tests
# Source this file in test scripts: source /test-scripts/test-lib.sh

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test tracking globals
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0
FAILED_TESTS=()

# Logging setup
setup_logging() {
    local test_suite=${1:-"test"}
    mkdir -p /test-results || true
    LOG_FILE="/test-results/${test_suite}.log"
}

# Function to log both to console and file
log_both() {
    echo "$1" | tee -a "$LOG_FILE" 2>/dev/null || echo "$1"
}

log() {
    local msg="${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
    echo -e "$msg"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE" 2>/dev/null || true
}

success() {
    echo -e "${GREEN}✓ $1${NC}"
    echo "✓ $1" >> "$LOG_FILE" 2>/dev/null || true
    TESTS_PASSED=$((TESTS_PASSED + 1))
}

error() {
    echo -e "${RED}✗ $1${NC}"
    echo "✗ $1" >> "$LOG_FILE" 2>/dev/null || true
    TESTS_FAILED=$((TESTS_FAILED + 1))
    FAILED_TESTS+=("$1")
}

warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

test_step() {
    TESTS_RUN=$((TESTS_RUN + 1))
    log "Running test: $1"
}

# Wait for service function
wait_for_service() {
    local host=$1
    local port=$2
    local timeout=${3:-30}
    local count=0
    
    log "Waiting for $host:$port (timeout: ${timeout}s)..."
    while ! nc -z "$host" "$port" 2>/dev/null; do
        if [ $count -ge $timeout ]; then
            error "Timeout waiting for $host:$port"
            return 1
        fi
        sleep 1
        count=$((count + 1))
    done
    success "$host:$port is ready"
}

# HTTP test helper
test_http_request() {
    local url=$1
    local expected_text=$2
    local proxy_arg=$3
    local description=$4
    local timeout=${5:-10}
    
    test_step "$description"
    
    if [ -n "$proxy_arg" ]; then
        response=$(curl $proxy_arg --connect-timeout $timeout -s "$url" 2>/dev/null || echo "CURL_ERROR")
    else
        response=$(curl --connect-timeout $timeout -s "$url" 2>/dev/null || echo "CURL_ERROR")
    fi
    
    if echo "$response" | grep -q "$expected_text"; then
        success "$description"
        return 0
    else
        error "$description - Expected: '$expected_text', Got: '$(echo "$response" | head -c 100)...'"
        return 1
    fi
}

# SOCKS test helper  
test_socks_request() {
    local socks_proxy=$1
    local url=$2
    local expected_text=$3
    local description=$4
    local timeout=${5:-10}
    
    test_step "$description"
    
    response=$(curl --socks5 "$socks_proxy" --connect-timeout $timeout -s "$url" 2>/dev/null || echo "CURL_ERROR")
    
    if echo "$response" | grep -q "$expected_text"; then
        success "$description"
        return 0
    else
        error "$description - Expected: '$expected_text', Got: '$(echo "$response" | head -c 100)...'"
        return 1
    fi
}

# Concurrent test helper
test_concurrent_requests() {
    local proxy_arg=$1
    local url=$2
    local expected_text=$3
    local num_requests=$4
    local description=$5
    
    test_step "$description"
    
    # Run concurrent requests
    for i in $(seq 1 $num_requests); do
        (curl $proxy_arg --connect-timeout 5 -s "$url" > /tmp/concurrent_test_$i.out 2>&1) &
    done
    wait
    
    # Check results
    local success_count=0
    for i in $(seq 1 $num_requests); do
        if grep -q "$expected_text" /tmp/concurrent_test_$i.out 2>/dev/null; then
            success_count=$((success_count + 1))
        fi
    done
    
    if [ $success_count -eq $num_requests ]; then
        success "$description - All $num_requests requests succeeded"
        return 0
    else
        error "$description - Only $success_count/$num_requests requests succeeded"
        return 1
    fi
}

# Test metrics endpoint
test_metrics() {
    local host=$1
    local port=$2
    local description=$3
    
    test_step "$description"
    
    # Test Prometheus metrics
    response=$(curl --connect-timeout 10 -s "http://$host:$port/api/metrics" 2>/dev/null || echo "CURL_ERROR")
    if echo "$response" | grep -q "http_requests_total\|http_request_duration_seconds"; then
        success "$description - Prometheus metrics"
    else
        error "$description - Prometheus metrics not found"
        return 1
    fi
    
    # Test embedded UI
    response=$(curl --connect-timeout 10 -s "http://$host:$port/" 2>/dev/null || echo "CURL_ERROR")
    if echo "$response" | grep -q -i "html\|redproxy"; then
        success "$description - Embedded UI"
    else
        warning "$description - Embedded UI not accessible"
    fi
    
    return 0
}

# Service readiness check helper
wait_for_services() {
    log "=== Service Readiness Check ==="
    for service_port in "$@"; do
        local host=$(echo "$service_port" | cut -d':' -f1)
        local port=$(echo "$service_port" | cut -d':' -f2)
        wait_for_service "$host" "$port" || exit 1
    done
}

# Error handling test helper
test_error_handling() {
    local proxy_arg=$1
    local invalid_url=$2
    local description=$3
    
    test_step "$description"
    set +e
    curl $proxy_arg --connect-timeout 5 -s "$invalid_url" > /tmp/error_test.out 2>&1
    error_code=$?
    set -e
    
    if [ $error_code -ne 0 ]; then
        success "$description"
        return 0
    else
        error "$description - Should have failed"
        return 1
    fi
}

# Timeout test helper
test_timeout_handling() {
    local proxy_arg=$1
    local timeout_url=$2
    local description=$3
    
    test_step "$description"
    set +e
    timeout 3 curl $proxy_arg --connect-timeout 1 -s "$timeout_url" > /tmp/timeout_test.out 2>&1
    timeout_code=$?
    set -e
    
    if [ $timeout_code -ne 0 ]; then
        success "$description"
        return 0
    else
        error "$description - Should have timed out"
        return 1
    fi
}

# Generate test summary and report
generate_test_report() {
    local test_suite=$1
    local features_tested=("${@:2}")
    
    log ""
    log "=== Test Summary ==="
    log "Tests completed: $TESTS_RUN"
    log "Tests passed: $TESTS_PASSED"  
    log "Tests failed: $TESTS_FAILED"
    
    if [ $TESTS_FAILED -eq 0 ]; then
        success "=== ALL ${test_suite^^} TESTS PASSED! ==="
        success "RedProxy ${test_suite} features are working correctly:"
        for feature in "${features_tested[@]}"; do
            success "  ✓ $feature"
        done
        
        # Save success report  
        echo "{\"status\": \"PASSED\", \"tests_run\": $TESTS_RUN, \"passed\": $TESTS_PASSED, \"failed\": $TESTS_FAILED, \"timestamp\": \"$(date -Iseconds)\"}" > "/test-results/${test_suite}-report.json" 2>/dev/null || echo "{\"status\": \"PASSED\", \"tests_run\": $TESTS_RUN, \"passed\": $TESTS_PASSED, \"failed\": $TESTS_FAILED}" > "/tmp/${test_suite}-report.json"
        
        return 0
    else
        error "=== SOME ${test_suite^^} TESTS FAILED ==="
        error "Failed tests:"
        for test in "${FAILED_TESTS[@]}"; do
            error "  - $test"
        done
        
        # Save failure report
        echo "{\"status\": \"FAILED\", \"tests_run\": $TESTS_RUN, \"passed\": $TESTS_PASSED, \"failed\": $TESTS_FAILED, \"timestamp\": \"$(date -Iseconds)\", \"failed_tests\": [$(printf '\"%s\",' "${FAILED_TESTS[@]}" | sed 's/,$/')]}" > "/test-results/${test_suite}-report.json" 2>/dev/null || echo "{\"status\": \"FAILED\", \"tests_run\": $TESTS_RUN, \"passed\": $TESTS_PASSED, \"failed\": $TESTS_FAILED}" > "/tmp/${test_suite}-report.json"
        
        return 1
    fi
}

# Cleanup trap setup
setup_cleanup_trap() {
    local test_suite=$1
    cleanup() {
        echo "{\"status\": \"INTERRUPTED\", \"tests_run\": $TESTS_RUN, \"passed\": $TESTS_PASSED, \"failed\": $TESTS_FAILED, \"timestamp\": \"$(date -Iseconds)\"}" > "/test-results/${test_suite}-report.json" 2>/dev/null || true
    }
    trap cleanup EXIT INT TERM
}