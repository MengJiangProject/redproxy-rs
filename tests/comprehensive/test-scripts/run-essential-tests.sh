#!/bin/bash

set -e

# Load shared test library
source /test-scripts/test-lib.sh

# Initialize logging for essential tests
setup_logging "essential-tests"
setup_cleanup_trap "essential-tests"

# Main test execution
main() {
    log "=== RedProxy Comprehensive Essential Tests ==="
    log "Starting essential feature validation..."
    
    # Wait for all services to be ready
    wait_for_services \
        "target-nginx:80" \
        "target-websocket:8080" \
        "upstream-http:3128" \
        "upstream-socks5:1080" \
        "redproxy-essential:8800" \
        "redproxy-essential:1081" \
        "redproxy-features:8800" \
        "redproxy-features:1081" \
        "redproxy-features:8888"
    
    log ""
    log "=== Basic Protocol Tests ==="
    
    # Test 1: HTTP CONNECT proxy - Essential RedProxy
    test_http_request "http://target-nginx:80/" "Hello from Nginx" "-x redproxy-essential:8800" \
        "HTTP CONNECT proxy (essential config)"
    
    # Test 2: SOCKS5 proxy - Essential RedProxy  
    test_socks_request "redproxy-essential:1081" "http://target-nginx:80/" "Hello from Nginx" \
        "SOCKS5 proxy (essential config)"
    
    # Test 3: HTTP CONNECT proxy - Features RedProxy
    test_http_request "http://target-nginx:80/" "Hello from Nginx" "-x redproxy-features:8800" \
        "HTTP CONNECT proxy (features config)"
    
    # Test 4: SOCKS5 proxy - Features RedProxy
    test_socks_request "redproxy-features:1081" "http://target-nginx:80/" "Hello from Nginx" \
        "SOCKS5 proxy (features config)"
    
    log ""
    log "=== Protocol Chain Tests ==="
    
    # Test 5: Verify upstream proxies work directly
    test_http_request "http://target-nginx:80/" "Hello from Nginx" "-x upstream-http:3128" \
        "Upstream HTTP proxy direct access"
        
    test_socks_request "upstream-socks5:1080" "http://target-nginx:80/" "Hello from Nginx" \
        "Upstream SOCKS5 proxy direct access"
    
    # Test 6: Protocol chaining through RedProxy
    test_socks_request "redproxy-essential:1081" "http://target-websocket:8080/" "WebSocket" \
        "SOCKS5 -> RedProxy -> Direct connection"
    
    log ""
    log "=== Advanced Feature Tests ==="
    
    # Test 7: WebSocket support through HTTP proxy
    test_http_request "http://target-websocket:8080/" "WebSocket" "-x redproxy-features:8800" \
        "WebSocket server through HTTP proxy"
    
    # Test 8: Metrics endpoint functionality
    test_metrics "redproxy-features" 8888 "Metrics and monitoring"
    
    log ""
    log "=== Performance Tests ==="
    
    # Test 9: Concurrent connections
    test_concurrent_requests "-x redproxy-features:8800" "http://target-nginx:80/" "Hello from Nginx" 10 \
        "10 concurrent HTTP CONNECT connections"
    
    test_concurrent_requests "--socks5 redproxy-features:1081" "http://target-nginx:80/" "Hello from Nginx" 5 \
        "5 concurrent SOCKS5 connections"
    
    log ""
    log "=== Error Handling Tests ==="
    
    # Test 10: Invalid host handling
    test_error_handling "-x redproxy-essential:8800" "http://nonexistent-host.invalid/" \
        "Properly handled connection to invalid host"
    
    # Test 11: Connection timeout handling
    test_timeout_handling "-x redproxy-essential:8800" "http://192.0.2.1:80/" \
        "Properly handled connection timeout"
    
    log ""
    log "=== Rule Engine Tests ==="
    
    # Test 12: Rule-based routing verification
    test_http_request "http://target-nginx:80/" "Hello from Nginx" "-x redproxy-features:8800" \
        "Rule-based routing to direct connector"
    
    # Generate comprehensive test report
    local essential_features=(
        "HTTP CONNECT proxy listeners"
        "SOCKS5 proxy listeners"
        "Direct, HTTP, and SOCKS5 connectors"
        "Rule-based routing with Milu expressions"
        "Concurrent connection handling"
        "Error handling and timeouts"
        "Metrics and monitoring endpoints"
        "WebSocket protocol support"
        "Protocol chaining scenarios"
    )
    
    generate_test_report "essential" "${essential_features[@]}"
    exit $?
}

# Execute main function
main "$@"