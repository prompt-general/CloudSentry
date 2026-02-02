# CloudSentry Test Suite Documentation

This document provides comprehensive information about the CloudSentry test suite, including how to run tests, write new tests, and understand the testing architecture.

## Table of Contents

- [Overview](#overview)
- [Test Structure](#test-structure)
- [Running Tests](#running-tests)
- [Writing Tests](#writing-tests)
- [Test Categories](#test-categories)
- [Mocking and Fixtures](#mocking-and-fixtures)
- [Continuous Integration](#continuous-integration)
- [Troubleshooting](#troubleshooting)

## Overview

The CloudSentry test suite is designed to ensure the reliability, security, and performance of the cloud security auditing platform. It includes:

- **Unit Tests**: Test individual components in isolation
- **Integration Tests**: Test component interactions and workflows
- **API Tests**: Test REST API endpoints and WebSocket connections
- **Security Tests**: Verify security controls and middleware
- **Database Tests**: Test data models and database operations
- **Performance Tests**: Benchmark critical operations

### Test Coverage Goals

- **Minimum Coverage**: 80% line coverage across all modules
- **Critical Components**: 95%+ coverage for security-sensitive code
- **API Endpoints**: 100% coverage for all public endpoints

## Test Structure

```
tests/
├── conftest.py              # Shared fixtures and configuration
├── unit/                    # Unit tests
│   ├── test_models.py       # Database model tests
│   ├── test_api.py          # FastAPI endpoint tests
│   ├── test_security.py     # Security middleware tests
│   ├── test_aws_organizations.py  # AWS Organizations tests
│   ├── test_event_ingestor.py     # Event processing tests
│   ├── test_audit_scheduler.py     # Scheduler tests
│   └── test_rule_engine.py         # Rule engine tests
├── integration/             # Integration tests
│   ├── test_full_system.py  # End-to-end system tests
│   ├── test_api_integration.py  # API integration tests
│   └── test_database.py     # Database integration tests
├── run_tests.sh            # Test runner script
└── README.md              # This documentation
```

## Running Tests

### Quick Start

```bash
# Install test dependencies
pip install -r requirements-test.txt

# Run all tests
./tests/run_tests.sh

# Run unit tests only
./tests/run_tests.sh --unit

# Run integration tests only
./tests/run_tests.sh --integration

# Run tests with coverage
./tests/run_tests.sh --coverage

# Run tests in parallel
./tests/run_tests.sh --parallel

# Run tests with verbose output
./tests/run_tests.sh --verbose
```

### Using pytest Directly

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/unit/test_models.py

# Run specific test function
pytest tests/unit/test_models.py::TestModels::test_finding_model_creation

# Run tests with markers
pytest -m "unit"
pytest -m "integration"
pytest -m "api"
pytest -m "security"

# Run tests with coverage
pytest --cov=app --cov-report=html

# Run tests in parallel
pytest -n auto

# Run tests with specific markers
pytest -m "slow or database"
```

### Test Categories and Markers

| Marker | Description | Example |
|--------|-------------|---------|
| `unit` | Unit tests | `pytest -m unit` |
| `integration` | Integration tests | `pytest -m integration` |
| `api` | API tests | `pytest -m api` |
| `security` | Security tests | `pytest -m security` |
| `database` | Database tests | `pytest -m database` |
| `aws` | AWS service tests | `pytest -m aws` |
| `slow` | Slow running tests | `pytest -m slow` |

## Writing Tests

### Test Naming Conventions

- Test files: `test_*.py`
- Test classes: `Test*`
- Test methods: `test_*`

### Example Unit Test

```python
import pytest
from unittest.mock import AsyncMock, patch
from app.models import Finding
import uuid
from datetime import datetime

class TestFindingModel:
    """Test Finding model functionality"""
    
    def test_finding_creation(self):
        """Test finding model creation"""
        finding = Finding(
            rule_id="S3-001",
            resource_id="test-bucket",
            resource_type="s3",
            severity="HIGH",
            timestamp=datetime.utcnow()
        )
        
        assert finding.rule_id == "S3-001"
        assert finding.resource_id == "test-bucket"
        assert finding.severity == "HIGH"
    
    def test_finding_to_dict(self):
        """Test finding serialization"""
        finding = Finding(
            id=uuid.uuid4(),
            rule_id="S3-001",
            resource_id="test-bucket",
            resource_type="s3",
            severity="HIGH",
            timestamp=datetime.utcnow()
        )
        
        result = finding.to_dict()
        
        assert isinstance(result, dict)
        assert result["rule_id"] == "S3-001"
        assert "id" in result
```

### Example Async Test

```python
import pytest
from unittest.mock import AsyncMock, patch

@pytest.mark.asyncio
async def test_async_function():
    """Test async function with mocked dependencies"""
    with patch('app.module.AsyncSessionLocal') as mock_session:
        mock_session.return_value.__aenter__.return_value = AsyncMock()
        
        result = await some_async_function()
        
        assert result is not None
        mock_session.assert_called_once()
```

### Example Integration Test

```python
import pytest
from fastapi.testclient import TestClient
from app.main import app

@pytest.mark.integration
class TestAPIIntegration:
    """Test API integration"""
    
    def test_health_endpoint(self):
        """Test health check endpoint"""
        client = TestClient(app)
        response = client.get("/health")
        
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"
```

## Mocking and Fixtures

### Using Fixtures

Fixtures are defined in `conftest.py` and provide test data and mock objects:

```python
@pytest.fixture
def sample_cloudtrail_event():
    """Sample CloudTrail event for testing"""
    return {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "accountId": "123456789012"
        },
        "eventTime": "2024-01-15T12:00:00Z",
        "eventSource": "s3.amazonaws.com",
        "eventName": "CreateBucket",
        "eventID": "12345678-1234-1234-1234-123456789012"
    }

def test_event_processing(sample_cloudtrail_event):
    """Test event processing with sample data"""
    result = process_event(sample_cloudtrail_event)
    assert result is True
```

### Mocking AWS Services

```python
import pytest
from unittest.mock import patch
from moto import mock_s3, mock_iam

@pytest.mark.aws
@mock_s3
@mock_iam
def test_aws_integration():
    """Test AWS service integration with moto"""
    # Test code that uses AWS services
    pass
```

### Mocking Database

```python
@pytest.fixture
def mock_db_session():
    """Mock database session"""
    session = AsyncMock()
    session.add.return_value = None
    session.commit.return_value = None
    return session

def test_database_operation(mock_db_session):
    """Test database operation with mocked session"""
    with patch('app.database.AsyncSessionLocal', return_value=mock_db_session):
        result = create_finding(data)
        assert result is not None
```

## Test Categories

### Unit Tests

- Test individual functions and classes
- Use mocks for external dependencies
- Fast execution
- High isolation

### Integration Tests

- Test component interactions
- Use real database (test instance)
- Test workflows and use cases
- Medium execution time

### API Tests

- Test HTTP endpoints
- Test request/response validation
- Test authentication and authorization
- Test error handling

### Security Tests

- Test security middleware
- Test input validation
- Test access controls
- Test for vulnerabilities

### Database Tests

- Test model relationships
- Test data validation
- Test query performance
- Test transaction handling

## Continuous Integration

### GitHub Actions Configuration

```yaml
name: Tests
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: [3.9, 3.10, 3.11]
    
    steps:
    - uses: actions/checkout@v3
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: ${{ matrix.python-version }}
    
    - name: Install dependencies
      run: |
        pip install -r requirements.txt
        pip install -r requirements-test.txt
    
    - name: Run tests
      run: ./tests/run_tests.sh --coverage --parallel
    
    - name: Upload coverage
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage.xml
```

### Pre-commit Hooks

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: pytest
        name: pytest
        entry: ./tests/run_tests.sh --unit
        language: script
        pass_filenames: false
        always_run: true
```

## Troubleshooting

### Common Issues

#### Test Database Connection Errors

```bash
# Check if PostgreSQL is running
pg_isready -h localhost -p 5432

# Start PostgreSQL service
sudo systemctl start postgresql

# Create test database
createdb test_cloudsentry
```

#### AWS Credential Errors

```bash
# Set test credentials
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1
```

#### Import Errors

```bash
# Check Python path
export PYTHONPATH="${PYTHONPATH}:$(pwd)"

# Install package in development mode
pip install -e .
```

#### Timeout Errors

```bash
# Increase timeout for slow tests
pytest --timeout=600

# Run tests sequentially
pytest -n 0
```

### Debugging Tests

```bash
# Run with pdb debugger
pytest --pdb

# Run with verbose output
pytest -vv -s

# Stop on first failure
pytest -x

# Run specific test with output
pytest tests/unit/test_models.py::TestModels::test_finding_creation -v -s
```

### Performance Issues

```bash
# Run tests in parallel
pytest -n auto

# Profile slow tests
pytest --benchmark-only

# Use pytest-xdist for parallel execution
pip install pytest-xdist
pytest -n 4
```

## Best Practices

### Test Organization

1. **Group related tests** in the same class
2. **Use descriptive test names** that explain what is being tested
3. **Follow AAA pattern**: Arrange, Act, Assert
4. **Keep tests small** and focused on one thing
5. **Use fixtures** for common test data

### Test Data Management

1. **Use factories** for creating test data
2. **Clean up test data** after each test
3. **Use deterministic data** for reproducible tests
4. **Avoid hard-coded values** in tests

### Mocking Strategy

1. **Mock external dependencies** (AWS, database, network)
2. **Use realistic mocks** that behave like real services
3. **Verify mock interactions** when important
4. **Don't over-mock** - test real behavior when possible

### Async Testing

1. **Use pytest-asyncio** for async tests
2. **Mark async tests** with `@pytest.mark.asyncio`
3. **Use proper async fixtures** for async dependencies
4. **Handle async context managers** correctly

## Coverage Reports

### Viewing Coverage

```bash
# Generate HTML coverage report
pytest --cov=app --cov-report=html

# Open coverage report
open htmlcov/index.html
```

### Coverage Thresholds

The test suite enforces minimum coverage thresholds:

- **Overall**: 80% line coverage
- **Critical modules**: 95% coverage
- **New code**: 90% coverage

### Excluding Code from Coverage

```python
# pragma: no cover
if __name__ == "__main__":
    main()

# Debug code
if settings.DEBUG:
    logger.debug("Debug info")  # pragma: no cover
```

## Contributing

When adding new features:

1. **Write tests first** (TDD approach)
2. **Ensure all tests pass** before submitting
3. **Maintain or improve coverage**
4. **Add integration tests** for new workflows
5. **Document test scenarios** in comments

### Test Review Checklist

- [ ] Tests cover all new code paths
- [ ] Tests handle error conditions
- [ ] Tests use appropriate mocking
- [ ] Tests are deterministic and repeatable
- [ ] Tests follow naming conventions
- [ ] Tests have clear descriptions
- [ ] Coverage thresholds are met
