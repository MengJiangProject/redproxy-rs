#!/bin/bash

set -e

# RedProxy Sanity Test Runner
# This script runs the comprehensive Docker-based sanity tests

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== RedProxy Sanity Test Runner ==="
echo "Location: $SCRIPT_DIR"
echo ""

# Check if Docker and Docker Compose are available
if ! command -v docker &> /dev/null; then
    echo "ERROR: Docker is not installed or not in PATH"
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "ERROR: Docker Compose is not installed or not in PATH"
    exit 1
fi

# Parse command line arguments
VERBOSE=false
CLEAN=false
BUILD_ONLY=false

for arg in "$@"; do
    case $arg in
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -c|--clean)
            CLEAN=true
            shift
            ;;
        -b|--build-only)
            BUILD_ONLY=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  -v, --verbose     Show verbose output"
            echo "  -c, --clean       Clean up before running tests"
            echo "  -b, --build-only  Build containers without running tests"
            echo "  -h, --help        Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0                Run sanity tests"
            echo "  $0 --verbose      Run with verbose logging"
            echo "  $0 --clean        Clean up and run tests"
            echo "  $0 --build-only   Build test containers only"
            exit 0
            ;;
        *)
            echo "Unknown option: $arg"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Clean up if requested
if [ "$CLEAN" = true ]; then
    echo "Cleaning up previous test runs..."
    docker-compose down -v --remove-orphans 2>/dev/null || true
    docker system prune -f
    echo ""
fi

# Build containers
echo "Building test containers..."
docker-compose build
echo ""

# Exit if build-only mode
if [ "$BUILD_ONLY" = true ]; then
    echo "Build completed. Containers ready for testing."
    exit 0
fi

# Run the tests
echo "Starting sanity tests..."
echo "This will:"
echo "  • Start RedProxy with HTTP and SOCKS listeners"
echo "  • Start upstream HTTP and SOCKS proxy servers"
echo "  • Start target HTTP servers"
echo "  • Run comprehensive client tests with curl commands"
echo ""

if [ "$VERBOSE" = true ]; then
    echo "Running in verbose mode..."
    docker-compose up --abort-on-container-exit --remove-orphans
else
    echo "Running tests (use --verbose for detailed output)..."
    docker-compose up --abort-on-container-exit --remove-orphans --quiet-pull
fi

exit_code=$?

echo ""
if [ $exit_code -eq 0 ]; then
    echo "✅ All sanity tests passed!"
    echo ""
    echo "RedProxy successfully tested with:"
    echo "  • HTTP CONNECT proxy functionality"
    echo "  • SOCKS5 proxy functionality"
    echo "  • Direct connector"
    echo "  • HTTP CONNECT upstream connector"
    echo "  • SOCKS5 upstream connector"
    echo "  • Rule-based routing"
    echo "  • Concurrent connection handling"
    echo "  • Error handling"
else
    echo "❌ Sanity tests failed!"
    echo ""
    echo "To debug:"
    echo "  docker-compose logs redproxy"
    echo "  docker-compose logs test-runner"
fi

# Clean up
echo ""
echo "Cleaning up test containers..."
docker-compose down --remove-orphans

exit $exit_code