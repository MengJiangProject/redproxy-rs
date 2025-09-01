"""
pytest configuration for security tests

Provides fixtures and configuration specific to security and error handling testing
"""

import pytest

# ============================================================================
# Test configuration
# ============================================================================

def pytest_configure(config):
    """Configure security-specific test markers"""
    config.addinivalue_line(
        "markers", "security: Security and error handling tests"
    )
    config.addinivalue_line(
        "markers", "error_handling: Error handling and validation tests"
    )
    config.addinivalue_line(
        "markers", "malformed: Malformed request handling tests"
    )
    config.addinivalue_line(
        "markers", "size_limits: Request size limit tests"
    )


def pytest_collection_modifyitems(config, items):
    """Auto-mark security tests based on their file names and content"""
    for item in items:
        # Auto-mark based on file name
        if "test_basic.py" in str(item.fspath):
            item.add_marker(pytest.mark.security)
        elif "test_error_handling.py" in str(item.fspath):
            item.add_marker(pytest.mark.error_handling)
        elif "test_malformed.py" in str(item.fspath):
            item.add_marker(pytest.mark.malformed)
        elif "test_size_limits.py" in str(item.fspath):
            item.add_marker(pytest.mark.size_limits)
        
        # All security tests get the security marker
        if "tests/security/" in str(item.fspath):
            item.add_marker(pytest.mark.security)