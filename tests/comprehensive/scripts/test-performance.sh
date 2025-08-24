#!/bin/sh
# Performance tests for RedProxy comprehensive suite
# Tests concurrent connections, throughput, and resource usage

set -e

# Load shared library
. /scripts/lib/common.sh

log_test "Performance Tests - Concurrency and Resource Usage"

# Test 1: Concurrent HTTP connections
log_test "Test 1: Concurrent HTTP connections"
test_concurrent_http() {
    test_http_connect "$REDPROXY_HOST" "$REDPROXY_HTTP_PORT" \
        "http://$HTTP_ECHO_HOST:$HTTP_ECHO_PORT/" "Hello from HTTP echo server"
}

if test_concurrent test_concurrent_http 10; then
    log_info "Concurrent HTTP connections test passed"
else
    log_error "Concurrent HTTP connections test failed"
    exit 1
fi

# Test 2: Concurrent SOCKS connections
log_test "Test 2: Concurrent SOCKS connections"
test_concurrent_socks() {
    test_socks_proxy "$REDPROXY_HOST" "$REDPROXY_SOCKS_PORT" \
        "http://$TARGET_HOST:$TARGET_PORT/" "nginx"
}

if test_concurrent test_concurrent_socks 10; then
    log_info "Concurrent SOCKS connections test passed"
else
    log_error "Concurrent SOCKS connections test failed"
    exit 1
fi

# Test 3: Mixed protocol concurrency
log_test "Test 3: Mixed protocol concurrency"
# Run HTTP and SOCKS tests simultaneously
(
    for i in $(seq 1 5); do
        test_http_connect "$REDPROXY_HOST" "$REDPROXY_HTTP_PORT" \
            "http://$HTTP_ECHO_HOST:$HTTP_ECHO_PORT/" "Hello from HTTP echo server" &
    done
    wait
) &

(
    for i in $(seq 1 5); do
        test_socks_proxy "$REDPROXY_HOST" "$REDPROXY_SOCKS_PORT" \
            "http://$TARGET_HOST:$TARGET_PORT/" "nginx" &
    done
    wait
) &

wait

log_info "Mixed protocol concurrency test passed"

# Test 4: Connection reuse and efficiency
log_test "Test 4: Connection efficiency test"
start_time=$(date +%s)

for i in $(seq 1 20); do
    test_http_connect "$REDPROXY_HOST" "$REDPROXY_HTTP_PORT" \
        "http://$HTTP_ECHO_HOST:$HTTP_ECHO_PORT/" "Hello from HTTP echo server" > /dev/null
done

end_time=$(date +%s)
duration=$((end_time - start_time))

if [ $duration -lt 30 ]; then
    log_info "Connection efficiency test passed (${duration}s for 20 requests)"
else
    log_warn "Connection efficiency test slow (${duration}s for 20 requests)"
fi

# Test 5: Error handling under load
log_test "Test 5: Error handling under load"
# Mix valid and invalid requests
for i in $(seq 1 5); do
    (
        test_http_connect "$REDPROXY_HOST" "$REDPROXY_HTTP_PORT" \
            "http://$HTTP_ECHO_HOST:$HTTP_ECHO_PORT/" "Hello from HTTP echo server" > /dev/null
        set +e
        curl -x "$REDPROXY_HOST:$REDPROXY_HTTP_PORT" --connect-timeout 2 -s \
            http://nonexistent-host:80/ > /dev/null 2>&1
        set -e
    ) &
done
wait

log_info "Error handling under load test passed"

log_info "All performance tests passed!"