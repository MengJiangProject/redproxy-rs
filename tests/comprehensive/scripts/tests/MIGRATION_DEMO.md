# Migration Demo: From Custom Framework to pytest

## Your Original Problems ❌

1. **No timeout handling** - tests hung indefinitely
2. **Can't run single tests** - had to run entire test groups
3. **No proper reporting** - custom reporting was "barely working"

## pytest Solutions ✅

### 1. Timeout Handling
```bash
# Global timeout (60s default in pyproject.toml)
pytest tests/httpx/test_connect.py

# Per-test timeout override
pytest tests/httpx/test_connect.py --timeout=30

# Individual test has @pytest.mark.timeout(15) decorator
```

### 2. Single Test Execution
```bash
# Run specific test class
pytest tests/httpx/test_connect.py::TestHTTPConnect

# Run specific test method
pytest tests/httpx/test_connect.py::TestHTTPConnect::test_basic_connect_tunnel

# Run by marker
pytest -m "connect"

# Run by keyword
pytest -k "basic_connect"

# Run all httpx tests
pytest tests/httpx/

# Run all destructive tests across all protocols
pytest -m "destructive"
```

### 3. Professional Reporting
```bash
# HTML report
pytest tests/httpx/ --html=reports/httpx_report.html --self-contained-html

# JSON report for CI/CD
pytest tests/httpx/ --json-report --json-report-file=reports/httpx.json

# JUnit XML for Jenkins/GitLab
pytest tests/httpx/ --junitxml=reports/httpx-junit.xml

# Live logging
pytest tests/httpx/ -v -s --log-cli-level=INFO
```

## Migration Status

### ✅ Completed
- [x] pytest configuration in pyproject.toml
- [x] Directory tree structure
- [x] Shared test utilities (servers.py, helpers.py)
- [x] CONNECT tests migrated (test_connect.py)

### 🔄 Next Steps
- [ ] Migrate forward proxy tests → `tests/httpx/test_forward.py`
- [ ] Migrate chunked encoding tests → `tests/httpx/test_chunked.py`
- [ ] Migrate keep-alive tests → `tests/httpx/test_keepalive.py`
- [ ] Migrate destructive tests → `tests/httpx/test_destructive.py`
- [ ] Create conftest.py with shared fixtures

## Example: Running Your Tests

Instead of your old way:
```bash
# Old way - custom framework
python test_httpx_listener.py --tests connect --timeout 120
```

New pytest way:
```bash
# Run connect tests with timeout
pytest tests/httpx/test_connect.py --timeout=120

# Run connect tests verbosely
pytest tests/httpx/test_connect.py -v

# Run just the basic connect test
pytest tests/httpx/test_connect.py::TestHTTPConnect::test_basic_connect_tunnel

# Run all connect tests across all protocols (when other protocols added)
pytest -m "connect"
```

## Benefits You Get

1. **Industry Standard** - pytest is used by every major Python project
2. **Rich Plugin Ecosystem** - timeout, html reports, parallel execution, etc.
3. **IDE Integration** - VS Code, PyCharm, etc. all support pytest natively
4. **CI/CD Ready** - GitHub Actions, Jenkins, GitLab CI all have pytest support
5. **Better Error Messages** - pytest shows exactly what failed and why
6. **Fixtures System** - Share test setup code cleanly
7. **Markers System** - Tag and run tests flexibly