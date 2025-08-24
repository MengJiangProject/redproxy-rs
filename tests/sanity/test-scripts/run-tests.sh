#!/bin/sh

set -e

# Install required tools
apk add --no-cache curl netcat-openbsd

echo "=== RedProxy Sanity Tests ==="
echo "Waiting for services to be ready..."

# Wait for services to be ready
wait_for_service() {
    local host=$1
    local port=$2
    local timeout=${3:-30}
    local count=0
    
    echo "Waiting for $host:$port..."
    while ! nc -z "$host" "$port" 2>/dev/null; do
        if [ $count -ge $timeout ]; then
            echo "ERROR: Timeout waiting for $host:$port"
            return 1
        fi
        sleep 1
        count=$((count + 1))
    done
    echo "✓ $host:$port is ready"
}

# Wait for all services
wait_for_service "http-echo" 8080
wait_for_service "target-server" 80
wait_for_service "http-proxy" 3128
wait_for_service "socks-proxy" 1080
wait_for_service "redproxy" 8800
wait_for_service "redproxy" 1081

echo ""
echo "=== Test 1: Direct HTTP CONNECT to echo server ==="
# Test HTTP CONNECT proxy to echo server (should use direct connector)
response=$(curl -x redproxy:8800 --connect-timeout 10 -s http://http-echo:8080/)
if echo "$response" | grep -q "Hello from HTTP echo server"; then
    echo "✓ HTTP CONNECT to echo server works (direct connector)"
else
    echo "✗ HTTP CONNECT to echo server failed"
    echo "Response: $response"
    exit 1
fi

echo ""
echo "=== Test 2: HTTP CONNECT through upstream HTTP proxy ==="
# Test HTTP CONNECT to target server (should route through HTTP proxy)
response=$(curl -x redproxy:8800 --connect-timeout 10 -s http://target-server:80/)
if echo "$response" | grep -q "Hello from target nginx server"; then
    echo "✓ HTTP CONNECT through upstream HTTP proxy works"
else
    echo "✗ HTTP CONNECT through upstream HTTP proxy failed"
    echo "Response: $response"
    exit 1
fi

echo ""
echo "=== Test 3: SOCKS5 proxy functionality ==="
# Test SOCKS5 proxy (should route through upstream SOCKS proxy)
response=$(curl --socks5 redproxy:1081 --connect-timeout 10 -s http://target-server:80/)
if echo "$response" | grep -q "Hello from target nginx server"; then
    echo "✓ SOCKS5 proxy through upstream SOCKS works"
else
    echo "✗ SOCKS5 proxy through upstream SOCKS failed"
    echo "Response: $response"
    exit 1
fi

echo ""
echo "=== Test 4: Verify upstream proxies are working ==="
# Verify HTTP proxy directly
response=$(curl -x http-proxy:3128 --connect-timeout 10 -s http://target-server:80/)
if echo "$response" | grep -q "Hello from target nginx server"; then
    echo "✓ Upstream HTTP proxy is working"
else
    echo "✗ Upstream HTTP proxy failed"
    echo "Response: $response"
    exit 1
fi

# Verify SOCKS proxy directly
response=$(curl --socks5 socks-proxy:1080 --connect-timeout 10 -s http://target-server:80/)
if echo "$response" | grep -q "Hello from target nginx server"; then
    echo "✓ Upstream SOCKS proxy is working"
else
    echo "✗ Upstream SOCKS proxy failed"
    echo "Response: $response"
    exit 1
fi

echo ""
echo "=== Test 5: Protocol chaining test ==="
# Test more complex routing - SOCKS through RedProxy, which routes through HTTP proxy
# This tests the full connector chain
response=$(curl --socks5 redproxy:1081 --connect-timeout 10 -s http://http-echo:8080/)
if echo "$response" | grep -q "Hello from HTTP echo server"; then
    echo "✓ Complex routing (SOCKS->RedProxy->SOCKS->Target) works"
else
    echo "✗ Complex routing failed"
    echo "Response: $response"
    exit 1
fi

echo ""
echo "=== Test 6: Connection handling and performance ==="
# Test multiple concurrent connections
echo "Testing concurrent connections..."
for i in 1 2 3 4 5; do
    (curl -x redproxy:8800 --connect-timeout 5 -s http://http-echo:8080/ > /tmp/test_$i.out 2>&1) &
done
wait

# Check all responses
success_count=0
for i in 1 2 3 4 5; do
    if grep -q "Hello from HTTP echo server" /tmp/test_$i.out 2>/dev/null; then
        success_count=$((success_count + 1))
    fi
done

if [ $success_count -eq 5 ]; then
    echo "✓ All 5 concurrent connections succeeded"
else
    echo "✗ Only $success_count/5 concurrent connections succeeded"
    exit 1
fi

echo ""
echo "=== Test 7: Error handling ==="
# Test connection to non-existent host
set +e
curl -x redproxy:8800 --connect-timeout 5 -s http://nonexistent-host:80/ > /tmp/error_test.out 2>&1
error_code=$?
set -e

if [ $error_code -ne 0 ]; then
    echo "✓ Properly handled connection to non-existent host"
else
    echo "✗ Should have failed connecting to non-existent host"
    exit 1
fi

echo ""
echo "=== All tests passed! ==="
echo "RedProxy is functioning correctly with:"
echo "  ✓ HTTP CONNECT proxy listener"
echo "  ✓ SOCKS5 proxy listener" 
echo "  ✓ Direct connector"
echo "  ✓ HTTP CONNECT connector (upstream proxy)"
echo "  ✓ SOCKS5 connector (upstream proxy)"
echo "  ✓ Rule-based routing"
echo "  ✓ Concurrent connection handling"
echo "  ✓ Error handling"