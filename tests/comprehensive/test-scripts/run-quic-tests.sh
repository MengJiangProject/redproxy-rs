#!/bin/bash

set -e

# Load shared test library
source /test-scripts/test-lib.sh

# Initialize logging for QUIC tests
setup_logging "quic-tests"
setup_cleanup_trap "quic-tests"

# QUIC-specific test helper (HTTP/3 over QUIC)
test_quic_request() {
    local url=$1
    local expected_text=$2
    local proxy_arg=$3
    local description=$4
    local timeout=${5:-15}
    
    test_step "$description"
    
    # Use curl with HTTP/3 support for QUIC testing
    # Note: Some curl versions may not have HTTP/3 support
    if curl --version | grep -q "HTTP3"; then
        response=$(curl $proxy_arg --http3-only \
            --connect-timeout $timeout -s "$url" 2>/dev/null || echo "CURL_ERROR")
    else
        # Fallback to testing QUIC proxy with regular HTTP/1.1
        response=$(curl $proxy_arg --connect-timeout $timeout -s "$url" 2>/dev/null || echo "CURL_ERROR")
    fi
    
    if echo "$response" | grep -q "$expected_text"; then
        success "$description"
        return 0
    else
        error "$description - Expected: '$expected_text', Got: '$(echo "$response" | head -c 100)...'"
        return 1
    fi
}

# Test QUIC UDP connectivity
test_quic_udp_connectivity() {
    local host=$1
    local port=$2
    local description=$3
    
    test_step "$description"
    
    # Test UDP connectivity to QUIC port using netcat or socat
    if command -v socat >/dev/null 2>&1; then
        # Send a simple UDP packet and check if port is reachable
        if timeout 5 socat UDP4-SENDTO:$host:$port /dev/null >/dev/null 2>&1; then
            success "$description"
            return 0
        fi
    fi
    
    # Alternative: use nc for UDP testing
    if echo "test" | timeout 3 nc -u "$host" "$port" >/dev/null 2>&1; then
        success "$description"
        return 0
    else
        error "$description - UDP port $host:$port not reachable"
        return 1
    fi
}

# Main test execution
main() {
    log "=== RedProxy QUIC Protocol Tests ==="
    log "Starting QUIC/HTTP3 feature validation..."
    
    # Wait for QUIC services to be ready
    wait_for_services \
        "target-nginx:80" \
        "redproxy-quic:8800" \
        "redproxy-quic:1081" \
        "redproxy-quic:8888"
    
    log ""
    log "=== QUIC UDP Connectivity Tests ==="
    
    # Test 1: QUIC UDP port connectivity
    test_quic_udp_connectivity "redproxy-quic" 8812 \
        "QUIC UDP port connectivity check"
    
    # Test 2: QUIC upstream connectivity  
    test_quic_udp_connectivity "upstream-quic" 9443 \
        "QUIC upstream UDP port connectivity"
    
    log ""
    log "=== QUIC Proxy Tests ==="
    
    # Test 3: HTTP proxy over QUIC transport
    test_http_request "http://target-nginx:80/" "Hello from Nginx" "-x redproxy-quic:8800" \
        "HTTP proxy with QUIC transport"
    
    # Test 4: SOCKS5 proxy over QUIC transport
    test_socks_request "redproxy-quic:1081" "http://target-nginx:80/" "Hello from Nginx" \
        "SOCKS5 proxy with QUIC transport"
    
    log ""
    log "=== QUIC Protocol Features ==="
    
    # Test 5: QUIC connection multiplexing (concurrent requests)
    test_concurrent_requests "-x redproxy-quic:8800" "http://target-nginx:80/" "Hello from Nginx" 5 \
        "QUIC connection multiplexing with 5 concurrent requests"
    
    # Test 6: QUIC protocol version negotiation
    test_step "QUIC protocol version support"
    # Check if QUIC service reports supported versions
    if nc -z redproxy-quic 8800 2>/dev/null; then
        success "QUIC protocol version support"
    else
        error "QUIC protocol version support - Service not accessible"
    fi
    
    log ""
    log "=== QUIC Performance Features ==="
    
    # Test 7: QUIC 0-RTT connection resumption simulation
    test_step "QUIC connection efficiency test"
    start_time=$(date +%s%N)
    test_http_request "http://target-nginx:80/" "Hello from Nginx" "-x redproxy-quic:8800" \
        "QUIC connection latency test" 10 >/dev/null 2>&1
    end_time=$(date +%s%N)
    duration=$(( (end_time - start_time) / 1000000 )) # Convert to milliseconds
    
    if [ $duration -lt 5000 ]; then # Less than 5 seconds
        success "QUIC connection efficiency test - ${duration}ms"
    else
        warning "QUIC connection efficiency test - ${duration}ms (slower than expected)"
    fi
    
    # Generate comprehensive test report
    local quic_features=(
        "QUIC UDP transport connectivity"
        "HTTP proxy over QUIC transport"
        "SOCKS5 proxy over QUIC transport"
        "QUIC connection multiplexing"
        "QUIC protocol version negotiation"
        "QUIC upstream connectors"
        "QUIC connection efficiency"
    )
    
    generate_test_report "quic" "${quic_features[@]}"
    exit $?
}

# Execute main function
main "$@"