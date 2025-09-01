"""
pytest configuration for performance tests

Provides fixtures and configuration specific to performance and load testing
"""

import pytest
import logging

# ============================================================================
# Test configuration
# ============================================================================

def pytest_configure(config):
    """Configure performance-specific test markers"""
    config.addinivalue_line(
        "markers", "performance: Performance and load tests"
    )
    config.addinivalue_line(
        "markers", "concurrent: Concurrent connection tests"
    )
    config.addinivalue_line(
        "markers", "sustained: Sustained load tests"
    )
    config.addinivalue_line(
        "markers", "memory: Memory usage and stability tests"
    )
    config.addinivalue_line(
        "markers", "throughput: Throughput and latency tests"
    )
    config.addinivalue_line(
        "markers", "slow: Slow tests that take extended time"
    )
    config.addinivalue_line(
        "markers", "suppress_output: Suppress stdout/stderr during test execution"
    )


def pytest_collection_modifyitems(config, items):
    """Auto-mark performance tests based on their file names and content"""
    for item in items:
        # Auto-mark based on file name
        if "test_concurrent.py" in str(item.fspath):
            item.add_marker(pytest.mark.concurrent)
        elif "test_sustained.py" in str(item.fspath):
            item.add_marker(pytest.mark.sustained)
            item.add_marker(pytest.mark.slow)
        elif "test_memory.py" in str(item.fspath):
            item.add_marker(pytest.mark.memory)
        elif "test_throughput.py" in str(item.fspath):
            item.add_marker(pytest.mark.throughput)
        elif "test_connection_limits.py" in str(item.fspath):
            item.add_marker(pytest.mark.concurrent)
        
        # All performance tests get the performance marker
        if "tests/performance/" in str(item.fspath):
            item.add_marker(pytest.mark.performance)
            
        # Auto-mark sustained and memory tests as slow
        if any(marker in item.name.lower() for marker in ['sustained', 'memory', 'stability']):
            item.add_marker(pytest.mark.slow)


# ============================================================================
# Performance test fixtures
# ============================================================================

@pytest.fixture(autouse=True, scope="session")
def reduce_logging_for_performance():
    """Reduce log levels for performance tests to avoid log flooding"""
    # Set httpx logging to WARNING to reduce noise during performance tests
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    
    # Set asyncio debug mode off for better performance
    logging.getLogger("asyncio").setLevel(logging.WARNING)
    
    # Reduce urllib3 connection pool warnings
    logging.getLogger("urllib3.connectionpool").setLevel(logging.WARNING)
    
    yield
    
    # Reset logging levels after performance tests
    logging.getLogger("httpx").setLevel(logging.INFO)
    logging.getLogger("httpcore").setLevel(logging.INFO)
    logging.getLogger("asyncio").setLevel(logging.INFO)
    logging.getLogger("urllib3.connectionpool").setLevel(logging.INFO)


@pytest.fixture
def suppress_output(capfd):
    """Fixture to capture and suppress stdout/stderr during performance tests"""
    # Only suppress for tests explicitly marked with 'suppress_output'
    return capfd