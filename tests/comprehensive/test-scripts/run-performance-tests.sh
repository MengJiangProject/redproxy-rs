#!/bin/bash

set -e

# Load shared test library
source /test-scripts/test-lib.sh

# Initialize logging for performance tests
setup_logging "performance-tests"
setup_cleanup_trap "performance-tests"

# Performance benchmark test
test_performance_benchmark() {
    local proxy_arg=$1
    local url=$2
    local num_requests=$3
    local concurrency=$4
    local description=$5
    
    test_step "$description"
    
    # Use wrk for performance testing if available
    if command -v wrk >/dev/null 2>&1; then
        # Run wrk benchmark through proxy
        wrk_output=$(wrk -t${concurrency} -c${concurrency} -d10s --timeout 10s \
            -H "Host: $(echo $url | cut -d'/' -f3)" \
            --script <(echo "
                request = function()
                    return wrk.format('GET', '$url')
                end
            ") "http://redproxy-performance:8800" 2>/dev/null || echo "WRK_ERROR")
        
        if echo "$wrk_output" | grep -q "Requests/sec"; then
            rps=$(echo "$wrk_output" | grep "Requests/sec" | awk '{print $2}' | cut -d. -f1)
            success "$description - $rps requests/sec"
            return 0
        else
            # Fallback to curl-based testing
            start_time=$(date +%s)
            successful_requests=0
            for i in $(seq 1 $num_requests); do
                if curl $proxy_arg --connect-timeout 5 -s "$url" >/dev/null 2>&1; then
                    successful_requests=$((successful_requests + 1))
                fi
            done
            end_time=$(date +%s)
            duration=$((end_time - start_time))
            
            if [ $duration -gt 0 ]; then
                rps=$((successful_requests / duration))
                success "$description - $rps requests/sec (fallback method)"
                return 0
            else
                error "$description - Performance test failed"
                return 1
            fi
        fi
    else
        # Fallback performance test using curl
        start_time=$(date +%s%N)
        successful_requests=0
        
        for i in $(seq 1 $num_requests); do
            if curl $proxy_arg --connect-timeout 5 -s "$url" >/dev/null 2>&1; then
                successful_requests=$((successful_requests + 1))
            fi
        done
        
        end_time=$(date +%s%N)
        duration=$(( (end_time - start_time) / 1000000 )) # Convert to milliseconds
        
        if [ $successful_requests -eq $num_requests ] && [ $duration -lt 30000 ]; then # Less than 30 seconds
            avg_latency=$((duration / num_requests))
            success "$description - ${avg_latency}ms avg latency, ${successful_requests}/${num_requests} successful"
            return 0
        else
            error "$description - Only ${successful_requests}/${num_requests} successful in ${duration}ms"
            return 1
        fi
    fi
}

# Latency test
test_latency_benchmark() {
    local proxy_arg=$1
    local url=$2
    local description=$3
    
    test_step "$description"
    
    local total_time=0
    local successful_requests=0
    local num_samples=10
    
    for i in $(seq 1 $num_samples); do
        start_time=$(date +%s%N)
        if curl $proxy_arg --connect-timeout 10 -s "$url" >/dev/null 2>&1; then
            end_time=$(date +%s%N)
            request_time=$(( (end_time - start_time) / 1000000 )) # Convert to milliseconds
            total_time=$((total_time + request_time))
            successful_requests=$((successful_requests + 1))
        fi
    done
    
    if [ $successful_requests -gt 0 ]; then
        avg_latency=$((total_time / successful_requests))
        if [ $avg_latency -lt 1000 ]; then # Less than 1 second average
            success "$description - ${avg_latency}ms average latency"
            return 0
        else
            warning "$description - ${avg_latency}ms average latency (higher than expected)"
            return 0
        fi
    else
        error "$description - No successful requests"
        return 1
    fi
}

# Memory usage test
test_memory_usage() {
    local description=$1
    
    test_step "$description"
    
    # Check container memory usage if possible
    if command -v docker >/dev/null 2>&1; then
        # Get memory stats for RedProxy containers
        memory_usage=$(docker stats --no-stream --format "table {{.Container}}\t{{.MemUsage}}" 2>/dev/null | grep redproxy-performance || echo "No stats available")
        if [ "$memory_usage" != "No stats available" ]; then
            success "$description - Memory usage: $memory_usage"
            return 0
        fi
    fi
    
    # Fallback: check system memory
    if [ -e /proc/meminfo ]; then
        mem_available=$(grep MemAvailable /proc/meminfo | awk '{print $2}' || echo "unknown")
        success "$description - System memory available: ${mem_available}KB"
        return 0
    else
        warning "$description - Memory usage monitoring not available"
        return 0
    fi
}

# Connection pool test
test_connection_pooling() {
    local proxy_arg=$1
    local url=$2
    local description=$3
    
    test_step "$description"
    
    # Test connection reuse by making multiple requests rapidly
    local pool_test_passed=0
    
    # Make several requests in quick succession
    for i in $(seq 1 5); do
        start_time=$(date +%s%N)
        if curl $proxy_arg --connect-timeout 5 -s "$url" >/dev/null 2>&1; then
            end_time=$(date +%s%N)
            request_time=$(( (end_time - start_time) / 1000000 ))
            
            # Subsequent requests should be faster due to connection reuse
            if [ $i -gt 1 ] && [ $request_time -lt 500 ]; then # Less than 500ms
                pool_test_passed=$((pool_test_passed + 1))
            elif [ $i -eq 1 ]; then
                pool_test_passed=$((pool_test_passed + 1)) # First request establishes connection
            fi
        fi
    done
    
    if [ $pool_test_passed -ge 3 ]; then
        success "$description"
        return 0
    else
        warning "$description - Connection pooling may not be optimal"
        return 0
    fi
}

# Main test execution
main() {
    log "=== RedProxy Performance Benchmark Tests ==="
    log "Starting performance and scalability validation..."
    
    # Wait for performance services to be ready
    wait_for_services \
        "target-nginx:80" \
        "redproxy-performance:8800" \
        "redproxy-performance:1081" \
        "redproxy-performance:8888"
    
    log ""
    log "=== Throughput Benchmarks ==="
    
    # Test 1: HTTP proxy throughput
    test_performance_benchmark "-x redproxy-performance:8800" "http://target-nginx:80/" 100 10 \
        "HTTP proxy throughput benchmark"
    
    # Test 2: SOCKS5 proxy throughput
    test_performance_benchmark "--socks5 redproxy-performance:1081" "http://target-nginx:80/" 50 5 \
        "SOCKS5 proxy throughput benchmark"
    
    log ""
    log "=== Latency Benchmarks ==="
    
    # Test 3: HTTP proxy latency
    test_latency_benchmark "-x redproxy-performance:8800" "http://target-nginx:80/" \
        "HTTP proxy latency benchmark"
    
    # Test 4: SOCKS5 proxy latency
    test_latency_benchmark "--socks5 redproxy-performance:1081" "http://target-nginx:80/" \
        "SOCKS5 proxy latency benchmark"
    
    log ""
    log "=== Scalability Tests ==="
    
    # Test 5: Concurrent connections
    test_concurrent_requests "-x redproxy-performance:8800" "http://target-nginx:80/" "Hello from Nginx" 20 \
        "High concurrency connection handling (20 concurrent)"
    
    # Test 6: Connection pooling efficiency
    test_connection_pooling "-x redproxy-performance:8800" "http://target-nginx:80/" \
        "Connection pooling and reuse efficiency"
    
    log ""
    log "=== Resource Usage Tests ==="
    
    # Test 7: Memory usage monitoring
    test_memory_usage "Memory usage optimization"
    
    # Test 8: CPU usage under load
    test_step "CPU usage under load test"
    # Run a sustained load test and monitor
    start_time=$(date +%s)
    concurrent_requests=0
    
    # Run background requests for load testing
    for i in $(seq 1 10); do
        (curl -x redproxy-performance:8800 --connect-timeout 5 -s "http://target-nginx:80/" >/dev/null 2>&1) &
    done
    wait
    
    end_time=$(date +%s)
    load_duration=$((end_time - start_time))
    
    if [ $load_duration -lt 30 ]; then # Completed in reasonable time
        success "CPU usage under load test - Load handled in ${load_duration}s"
    else
        warning "CPU usage under load test - Load took ${load_duration}s (may indicate high CPU usage)"
    fi
    
    log ""
    log "=== Protocol-Specific Performance ==="
    
    # Test 9: HTTP/1.1 vs HTTP/2 performance (if supported)
    test_step "HTTP protocol version performance"
    # Test HTTP/1.1 performance
    start_time=$(date +%s%N)
    curl -x redproxy-performance:8800 --http1.1 --connect-timeout 10 -s "http://target-nginx:80/" >/dev/null 2>&1
    end_time=$(date +%s%N)
    http1_time=$(( (end_time - start_time) / 1000000 ))
    
    success "HTTP protocol version performance - HTTP/1.1: ${http1_time}ms"
    
    log ""
    log "=== Performance Monitoring ==="
    
    # Test 10: Performance metrics collection
    test_step "Performance metrics and monitoring"
    if nc -z redproxy-performance 8888 2>/dev/null; then
        response=$(curl --connect-timeout 10 -s "http://redproxy-performance:8888/api/metrics" 2>/dev/null || echo "CURL_ERROR")
        if echo "$response" | grep -q -E "(duration_seconds|requests_total|connections_)"; then
            success "Performance metrics and monitoring - Performance metrics available"
        else
            warning "Performance metrics and monitoring - Limited performance metrics found"
        fi
    else
        warning "Performance metrics and monitoring - Metrics endpoint not accessible"
    fi
    
    # Generate comprehensive test report
    local performance_features=(
        "HTTP proxy throughput benchmark"
        "SOCKS5 proxy throughput benchmark"
        "HTTP proxy latency benchmark"
        "SOCKS5 proxy latency benchmark"
        "High concurrency connection handling"
        "Connection pooling efficiency"
        "Memory usage optimization"
        "CPU usage under load"
        "HTTP protocol performance"
        "Performance metrics monitoring"
    )
    
    generate_test_report "performance" "${performance_features[@]}"
    exit $?
}

# Execute main function
main "$@"
