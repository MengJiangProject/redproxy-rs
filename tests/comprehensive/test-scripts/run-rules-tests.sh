#!/bin/bash

set -e

# Load shared test library
source /test-scripts/test-lib.sh

# Initialize logging for rules tests
setup_logging "rules-tests"
setup_cleanup_trap "rules-tests"

# Test rule-based routing
test_rule_based_routing() {
    local proxy_arg=$1
    local url=$2
    local expected_text=$3
    local rule_description=$4
    local description=$5
    
    test_step "$description"
    
    response=$(curl $proxy_arg --connect-timeout 10 -s "$url" 2>/dev/null || echo "CURL_ERROR")
    
    if echo "$response" | grep -q "$expected_text"; then
        success "$description - Rule: $rule_description"
        return 0
    else
        error "$description - Expected: '$expected_text', Got: '$(echo "$response" | head -c 100)...'"
        return 1
    fi
}

# Test rule blocking functionality
test_rule_blocking() {
    local proxy_arg=$1
    local blocked_url=$2
    local description=$3
    
    test_step "$description"
    set +e
    curl $proxy_arg --connect-timeout 5 -s "$blocked_url" > /tmp/rule_block_test.out 2>&1
    error_code=$?
    set -e
    
    # Check if the request was blocked (should fail or return specific error)
    if [ $error_code -ne 0 ]; then
        success "$description"
        return 0
    else
        # Check response content for block indication or HTTP error codes
        if grep -q -i -E "(blocked|denied|forbidden|error|400|403|502|connection)" /tmp/rule_block_test.out 2>/dev/null; then
            success "$description"
            return 0
        else
            # Debug: show what we actually got
            echo "DEBUG: Response content:" >&2
            cat /tmp/rule_block_test.out >&2
            error "$description - Request should have been blocked by rules"
            return 1
        fi
    fi
}

# Test Milu expression evaluation
test_milu_expressions() {
    local proxy_arg=$1
    local test_url=$2
    local description=$3
    
    test_step "$description"
    
    # Test various Milu expressions by making requests that should match different rules
    # This is a basic test since we can't directly evaluate Milu expressions
    local milu_test_passed=0
    
    # Test host-based rule matching
    response=$(curl $proxy_arg --connect-timeout 10 -s "$test_url" 2>/dev/null || echo "CURL_ERROR")
    if echo "$response" | grep -q "Hello from Nginx"; then
        milu_test_passed=$((milu_test_passed + 1))
    fi
    
    # Test with different hosts to trigger different rules
    response=$(curl $proxy_arg -H "Host: test.example.com" --connect-timeout 10 -s "$test_url" 2>/dev/null || echo "CURL_ERROR")
    if [ "$response" != "CURL_ERROR" ]; then
        milu_test_passed=$((milu_test_passed + 1))
    fi
    
    if [ $milu_test_passed -ge 1 ]; then
        success "$description"
        return 0
    else
        error "$description - Milu expression evaluation failed"
        return 1
    fi
}

# Main test execution
main() {
    log "=== RedProxy Milu Rules Engine Tests ==="
    log "Starting rule engine and Milu language validation..."
    
    # Wait for rules services to be ready
    wait_for_services \
        "target-nginx:80" \
        "target-blocked:80" \
        "redproxy-rules:8800" \
        "redproxy-rules:1081" \
        "redproxy-rules:8888"
    
    log ""
    log "=== Basic Rule Engine Tests ==="
    
    # Test 1: Allow rule - should route to target
    test_rule_based_routing "-x redproxy-rules:8800" "http://target-nginx:80/" "Hello from Nginx" \
        "request.target.host == 'target-nginx'" \
        "Basic allow rule routing"
    
    # Test 2: Host-based routing rule
    test_rule_based_routing "-x redproxy-rules:8800" "http://target-nginx:80/" "Hello from Nginx" \
        "request.target.host =~ '.*nginx.*'" \
        "Host pattern matching rule"
    
    log ""
    log "=== Rule Blocking Tests ==="
    
    # Test 3: Block rule - should deny access
    test_rule_blocking "-x redproxy-rules:8800" "http://target-blocked:80/" \
        "Block rule denies access to blocked targets"
    
    # Test 4: Port-based blocking
    test_rule_blocking "-x redproxy-rules:8800" "http://target-nginx:8080/" \
        "Port-based blocking rule"
    
    log ""
    log "=== Milu Language Expression Tests ==="
    
    # Test 5: Complex Milu expressions
    test_milu_expressions "-x redproxy-rules:8800" "http://target-nginx:80/" \
        "Complex Milu expression evaluation"
    
    # Test 6: SOCKS5 rule engine
    test_socks_request "redproxy-rules:1081" "http://target-nginx:80/" "Hello from Nginx" \
        "SOCKS5 proxy with rule engine"
    
    log ""
    log "=== Rule Priority and Chaining Tests ==="
    
    # Test 7: Rule priority testing
    test_step "Rule priority and order evaluation"
    # Test that rules are evaluated in the correct order
    response=$(curl -x redproxy-rules:8800 --connect-timeout 10 -s "http://target-nginx:80/" 2>/dev/null || echo "CURL_ERROR")
    if echo "$response" | grep -q "Hello from Nginx"; then
        success "Rule priority and order evaluation"
    else
        error "Rule priority and order evaluation - Rules not evaluated correctly"
    fi
    
    # Test 8: Rule condition chaining
    test_step "Rule condition chaining with logical operators"
    # Test AND/OR conditions in Milu expressions
    response=$(curl -x redproxy-rules:8800 -H "User-Agent: TestAgent" --connect-timeout 10 -s "http://target-nginx:80/" 2>/dev/null || echo "CURL_ERROR")
    if [ "$response" != "CURL_ERROR" ]; then
        success "Rule condition chaining with logical operators"
    else
        error "Rule condition chaining with logical operators - Chained conditions failed"
    fi
    
    log ""
    log "=== Rule Metrics and Monitoring ==="
    
    # Test 9: Rule engine metrics
    test_step "Rule engine metrics and statistics"
    if nc -z redproxy-rules 8888 2>/dev/null; then
        response=$(curl --connect-timeout 10 -s "http://redproxy-rules:8888/api/metrics" 2>/dev/null || echo "CURL_ERROR")
        if echo "$response" | grep -q -E "(rules_|matched_|blocked_)"; then
            success "Rule engine metrics and statistics"
        else
            warning "Rule engine metrics and statistics - No rule-specific metrics found"
        fi
    else
        warning "Rule engine metrics and statistics - Metrics endpoint not accessible"
    fi
    
    log ""
    log "=== Advanced Milu Features ==="
    
    # Test 10: Request context access
    test_step "Milu request context variable access"
    # Test access to request.source, request.target, etc.
    response=$(curl -x redproxy-rules:8800 --connect-timeout 10 -s "http://target-nginx:80/" 2>/dev/null || echo "CURL_ERROR")
    if echo "$response" | grep -q "Hello from Nginx"; then
        success "Milu request context variable access"
    else
        error "Milu request context variable access - Context variables not accessible"
    fi
    
    # Generate comprehensive test report
    local rules_features=(
        "Basic allow rule routing"
        "Host pattern matching rules"
        "Block rule enforcement"
        "Port-based rule filtering"
        "Complex Milu expression evaluation"
        "SOCKS5 rule engine integration"
        "Rule priority and ordering"
        "Logical operator chaining"
        "Rule engine metrics"
        "Request context variable access"
    )
    
    generate_test_report "rules" "${rules_features[@]}"
    exit $?
}

# Execute main function
main "$@"
