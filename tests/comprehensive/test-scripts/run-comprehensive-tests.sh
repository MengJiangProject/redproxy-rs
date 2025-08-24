#!/bin/bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test tracking
SUITES_RUN=0
SUITES_PASSED=0
SUITES_FAILED=0
FAILED_SUITES=()

# Logging setup
mkdir -p /test-results || true
LOG_FILE="/test-results/comprehensive-tests.log"

log() {
    local msg="${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
    echo -e "$msg"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE" 2>/dev/null || true
}

success() {
    echo -e "${GREEN}✓ $1${NC}"
    echo "✓ $1" >> "$LOG_FILE" 2>/dev/null || true
    SUITES_PASSED=$((SUITES_PASSED + 1))
}

error() {
    echo -e "${RED}✗ $1${NC}"
    echo "✗ $1" >> "$LOG_FILE" 2>/dev/null || true
    SUITES_FAILED=$((SUITES_FAILED + 1))
    FAILED_SUITES+=("$1")
}

warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

run_test_suite() {
    local suite_name=$1
    local test_script=$2
    
    SUITES_RUN=$((SUITES_RUN + 1))
    log "=== Running $suite_name ==="
    
    if [ -f "/test-scripts/$test_script" ]; then
        if /test-scripts/$test_script; then
            success "$suite_name completed successfully"
            return 0
        else
            error "$suite_name failed"
            return 1
        fi
    else
        warning "$suite_name skipped (script not found: $test_script)"
        return 0
    fi
}

main() {
    log "=== RedProxy Comprehensive Test Suite ==="
    log "Running all available test suites..."
    
    # Run available test suites in logical order
    run_test_suite "Essential Tests" "run-essential-tests.sh"
    run_test_suite "QUIC Tests" "run-quic-tests.sh"
    run_test_suite "mTLS Tests" "run-mtls-tests.sh"
    run_test_suite "Load Balancer Tests" "run-loadbalancer-tests.sh"
    run_test_suite "Rule Engine Tests" "run-rules-tests.sh"
    run_test_suite "Linux-specific Tests" "run-linux-tests.sh"
    run_test_suite "Performance Tests" "run-performance-tests.sh"
    
    log ""
    log "=== Comprehensive Test Summary ==="
    log "Test suites completed: $SUITES_RUN"
    log "Test suites passed: $SUITES_PASSED"
    log "Test suites failed: $SUITES_FAILED"
    
    if [ $SUITES_FAILED -eq 0 ]; then
        success "=== ALL COMPREHENSIVE TESTS PASSED! ==="
        echo "{\"status\": \"PASSED\", \"suites_run\": $SUITES_RUN, \"passed\": $SUITES_PASSED, \"failed\": $SUITES_FAILED, \"timestamp\": \"$(date -Iseconds)\"}" > /test-results/comprehensive-tests-report.json 2>/dev/null || true
        exit 0
    else
        error "=== SOME TEST SUITES FAILED ==="
        error "Failed suites:"
        for suite in "${FAILED_SUITES[@]}"; do
            error "  - $suite"
        done
        echo "{\"status\": \"FAILED\", \"suites_run\": $SUITES_RUN, \"passed\": $SUITES_PASSED, \"failed\": $SUITES_FAILED, \"timestamp\": \"$(date -Iseconds)\", \"failed_suites\": [$(printf '\"%s\",' "${FAILED_SUITES[@]}" | sed 's/,$//')]}\"" > /test-results/comprehensive-tests-report.json 2>/dev/null || true
        exit 1
    fi
}

# Execute main function
main "$@"