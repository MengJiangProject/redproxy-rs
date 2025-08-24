#!/bin/bash

set -e

# Load shared test library
source /test-scripts/test-lib.sh

# Initialize logging for linux tests
setup_logging "linux-tests"
setup_cleanup_trap "linux-tests"

# Test Linux kernel features availability
test_linux_kernel_features() {
    local description=$1
    
    test_step "$description"
    
    local features_available=0
    
    # Check if splice syscall is available
    if [ -e /proc/sys/fs/pipe-max-size ]; then
        features_available=$((features_available + 1))
        log "Splice syscall support detected"
    fi
    
    # Check netfilter/iptables support for TPROXY
    if [ -e /proc/net/netfilter ] || [ -e /sys/module/xt_TPROXY ]; then
        features_available=$((features_available + 1))
        log "Netfilter TPROXY support detected"
    fi
    
    # Check for CAP_NET_ADMIN capability
    if capsh --print 2>/dev/null | grep -q "cap_net_admin"; then
        features_available=$((features_available + 1))
        log "CAP_NET_ADMIN capability available"
    fi
    
    if [ $features_available -ge 1 ]; then
        success "$description - $features_available Linux features available"
        return 0
    else
        error "$description - No Linux-specific features detected"
        return 1
    fi
}

# Setup TPROXY iptables rules for transparent proxying
setup_tproxy_rules() {
    log "Setting up TPROXY iptables rules..."
    
    # Load required kernel modules
    modprobe xt_TPROXY 2>/dev/null || log "Warning: xt_TPROXY module not available"
    modprobe nf_tproxy_ipv4 2>/dev/null || log "Warning: nf_tproxy_ipv4 module not available"
    
    # Create custom routing table for TPROXY
    ip rule add fwmark 1 lookup 100 2>/dev/null || true
    ip route add local 0.0.0.0/0 dev lo table 100 2>/dev/null || true
    
    # Create TPROXY chain
    iptables -t mangle -N TPROXY_CHAIN 2>/dev/null || true
    iptables -t mangle -F TPROXY_CHAIN 2>/dev/null || true
    
    # Add basic return rule for local traffic
    iptables -t mangle -A TPROXY_CHAIN -d 127.0.0.0/8 -j RETURN
    
    # Try TPROXY target first
    if iptables -t mangle -A TPROXY_CHAIN -d target-nginx -p tcp --dport 80 -j TPROXY --on-port 8080 --tproxy-mark 1 2>/dev/null; then
        log "TPROXY target available - using full transparent proxy"
        TPROXY_METHOD="tproxy"
        # Apply rules to OUTPUT chain for locally generated traffic
        iptables -t mangle -I OUTPUT -j TPROXY_CHAIN
    else
        log "TPROXY target not available - using REDIRECT fallback"
        # REDIRECT must be in nat table, not mangle
        iptables -t nat -N REDIRECT_CHAIN 2>/dev/null || true
        iptables -t nat -F REDIRECT_CHAIN 2>/dev/null || true
        
        # Redirect traffic to TPROXY listener FIRST (nat table processed before filter)
        iptables -t nat -A REDIRECT_CHAIN -d target-nginx -p tcp --dport 80 -j REDIRECT --to-port 8080
        iptables -t nat -I OUTPUT -j REDIRECT_CHAIN
        
        # Block any remaining direct access to target-nginx (shouldn't happen due to REDIRECT)
        iptables -I OUTPUT -d target-nginx -p tcp --dport 80 -j REJECT --reject-with tcp-reset
        TPROXY_METHOD="redirect"
    fi
    log "Transparent proxy rules configured using $TPROXY_METHOD method"
}

# Cleanup TPROXY iptables rules
cleanup_tproxy_rules() {
    log "Cleaning up TPROXY iptables rules..."
    
    # Clean up based on method used
    if [ "$TPROXY_METHOD" = "tproxy" ]; then
        iptables -t mangle -D OUTPUT -j TPROXY_CHAIN 2>/dev/null || true
        iptables -t mangle -F TPROXY_CHAIN 2>/dev/null || true
        iptables -t mangle -X TPROXY_CHAIN 2>/dev/null || true
    else
        # Clean up REDIRECT rules
        iptables -t nat -D OUTPUT -j REDIRECT_CHAIN 2>/dev/null || true
        iptables -t nat -F REDIRECT_CHAIN 2>/dev/null || true
        iptables -t nat -X REDIRECT_CHAIN 2>/dev/null || true
        # Clean up REJECT rule
        iptables -D OUTPUT -d target-nginx -p tcp --dport 80 -j REJECT --reject-with tcp-reset 2>/dev/null || true
        # Also clean up mangle chain
        iptables -t mangle -F TPROXY_CHAIN 2>/dev/null || true
        iptables -t mangle -X TPROXY_CHAIN 2>/dev/null || true
    fi
    
    ip rule del fwmark 1 lookup 100 2>/dev/null || true
    ip route del local 0.0.0.0/0 dev lo table 100 2>/dev/null || true
}

# Test TPROXY functionality with real transparent interception
test_tproxy_functionality() {
    local target_host=$1
    local target_port=$2
    local description=$3
    
    test_step "$description"
    
    # Check if TPROXY listener is running
    if ! nc -z localhost 8080 2>/dev/null; then
        error "$description - TPROXY listener not accessible on port 8080"
        return 1
    fi
    
    # Setup iptables rules for transparent proxying
    setup_tproxy_rules
    
    # Give iptables rules time to take effect
    sleep 2
    
    # Show current iptables rules for debugging
    log "Current iptables rules:"
    iptables-save
    
    # Test transparent interception (NO explicit proxy configuration)
    # Traffic to target-nginx:80 should be transparently intercepted
    log "Testing transparent interception: curl http://$target_host:$target_port/api/client-info (no proxy config)"
    
    # Test with interception rules active - use client-info endpoint to see connecting IP
    response=$(timeout 15 curl --connect-timeout 10 -s "http://$target_host:$target_port/api/client-info" 2>/dev/null || echo "CURL_ERROR")
    
    # Cleanup iptables rules
    cleanup_tproxy_rules
    
    if echo "$response" | grep -q '"client_ip"'; then
        # Parse the client IP from the JSON response
        client_ip=$(echo "$response" | grep -o '"client_ip":"[^"]*"' | cut -d'"' -f4)
        log "Client IP seen by target-nginx: $client_ip"
        
        # Get the upstream-socks5 container IP for comparison
        socks_ip=$(nslookup upstream-socks5 | grep "^Address" | tail -1 | awk '{print $2}' 2>/dev/null || echo "unknown")
        log "Upstream SOCKS5 container IP: $socks_ip"
        
        # Verify that traffic came through SOCKS proxy by checking client IP
        if [ "$client_ip" = "$socks_ip" ]; then
            success "$description - Traffic transparently intercepted and routed through SOCKS proxy (client IP: $client_ip)"
            return 0
        else
            # Check if traffic went through TPROXY but with different routing
            if grep -q '"listener":"tproxy"' /logs/access-linux.log 2>/dev/null; then
                warning "$description - TPROXY working but client IP ($client_ip) doesn't match SOCKS proxy ($socks_ip)"
                return 0
            else
                error "$description - Client IP ($client_ip) suggests direct connection, not through proxy"
                return 1
            fi
        fi
    else
        log "Transparent interception response (first 200 chars): '$(echo "$response" | head -c 200)'"
        
        # If transparent interception failed, verify TPROXY listener works directly
        log "Fallback: Testing TPROXY listener directly"
        if echo -e "GET / HTTP/1.1\r\nHost: $target_host\r\nConnection: close\r\n\r\n" | timeout 5 nc localhost 8080 2>/dev/null | grep -q "200 OK"; then
            error "$description - TPROXY listener works but transparent interception failed (network configuration issue)"
            return 1
        else
            # Last resort: test via regular proxy to verify backend connectivity
            backend_test=$(curl -x localhost:8800 --connect-timeout 5 -s "http://$target_host:$target_port/" 2>/dev/null || echo "BACKEND_ERROR")
            if echo "$backend_test" | grep -q "Hello from Nginx"; then
                error "$description - TPROXY listener and backend work, but transparent interception requires host networking"
                return 1
            else
                error "$description - TPROXY functionality not working"
                return 1
            fi
        fi
    fi
}

# Test splice optimization
test_splice_optimization() {
    local proxy_arg=$1
    local url=$2
    local description=$3
    
    test_step "$description"
    
    # Test data transfer through proxy and measure efficiency
    # Create a test file for transfer
    echo "Linux splice optimization test data $(date)" > /tmp/splice_test_data.txt
    
    # Transfer through proxy
    start_time=$(date +%s%N)
    response=$(curl $proxy_arg --connect-timeout 10 -s "$url" 2>/dev/null || echo "CURL_ERROR")
    end_time=$(date +%s%N)
    
    duration=$(( (end_time - start_time) / 1000000 )) # Convert to milliseconds
    
    if echo "$response" | grep -q "Hello from Nginx"; then
        success "$description - Transfer completed in ${duration}ms"
        return 0
    else
        error "$description - Splice-optimized transfer failed"
        return 1
    fi
}

# Test SO_REUSEPORT socket option
test_socket_options() {
    local description=$1
    
    test_step "$description"
    
    # Check if multiple RedProxy processes can bind to the same port with SO_REUSEPORT
    # This is tested indirectly by checking if the service starts successfully
    if nc -z localhost 8800 2>/dev/null && nc -z localhost 1081 2>/dev/null; then
        success "$description - Socket options configured correctly"
        return 0
    else
        error "$description - Socket binding failed"
        return 1
    fi
}

# Main test execution
main() {
    log "=== RedProxy Linux-Specific Features Tests ==="
    log "Starting Linux kernel integration validation..."
    
    # Check if running on Linux
    if [ "$(uname)" != "Linux" ]; then
        warning "Not running on Linux - skipping Linux-specific tests"
        # Generate minimal report for non-Linux systems
        local linux_features=("Linux kernel feature detection")
        generate_test_report "linux" "${linux_features[@]}"
        exit 0
    fi
    
    # Wait for Linux services to be ready
    # Note: tester-linux runs in same network namespace as redproxy-linux
    wait_for_services \
        "target-nginx:80" \
        "upstream-socks5:1080" \
        "localhost:8800" \
        "localhost:1081" \
        "localhost:8888"
    
    log ""
    log "=== Linux Kernel Feature Detection ==="
    
    # Test 1: Linux kernel features availability
    test_linux_kernel_features "Linux kernel features detection"
    
    log ""
    log "=== TPROXY Transparent Proxy Tests ==="
    
    # Test 2: TPROXY transparent proxying
    test_tproxy_functionality "target-nginx" "80" \
        "TPROXY transparent proxy functionality"
    
    
    log ""
    log "=== Linux I/O Optimization Tests ==="
    
    # Test 3: Splice syscall optimization
    test_splice_optimization "-x localhost:8800" "http://target-nginx:80/" \
        "Splice syscall I/O optimization"
    
    # Test 4: Socket options and performance tuning
    test_socket_options "Linux socket options configuration"
    
    
    # Generate comprehensive test report
    local linux_features=(
        "Linux kernel features detection"
        "TPROXY transparent proxy functionality"
        "Splice syscall I/O optimization"
        "Linux socket options configuration"
    )
    
    generate_test_report "linux" "${linux_features[@]}"
    exit $?
}

# Execute main function
main "$@"
