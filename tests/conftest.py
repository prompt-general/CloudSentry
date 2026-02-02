import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
import sys
import os

# Add the app directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app.database import AsyncSessionLocal, async_engine
from app.config import get_settings
import pytest_asyncio

# Test settings
@pytest.fixture
def test_settings():
    """Override settings for testing"""
    with patch('app.config.get_settings') as mock_settings:
        settings = MagicMock()
        settings.database_url = "postgresql+asyncpg://test:test@localhost:5432/test_db"
        settings.redis_url = "redis://localhost:6379/1"
        settings.aws_region = "us-east-1"
        settings.aws_access_key_id = "test-key"
        settings.aws_secret_access_key = "test-secret"
        settings.enable_multi_account = False
        settings.debug = True
        settings.allowed_origins = ["http://localhost:3000"]
        settings.allowed_hosts = ["localhost", "127.0.0.1"]
        mock_settings.return_value = settings
        yield settings

@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests"""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest_asyncio.fixture
async def db_session():
    """Create a test database session"""
    # Create test tables
    from app.models import Base
    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    async with AsyncSessionLocal() as session:
        yield session
        
        # Cleanup after test
        await session.rollback()
        await session.close()
    
    # Drop test tables
    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

@pytest.fixture
def sample_cloudtrail_event():
    """Sample CloudTrail event for testing"""
    return {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDACKCEVSQ6C2EXAMPLE",
            "arn": "arn:aws:iam::123456789012:user/test-user",
            "accountId": "123456789012",
            "userName": "test-user"
        },
        "eventTime": "2024-01-15T12:00:00Z",
        "eventSource": "s3.amazonaws.com",
        "eventName": "CreateBucket",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "192.0.2.0",
        "userAgent": "[aws-cli/2.0.0]",
        "requestParameters": {"bucketName": "test-bucket-123"},
        "responseElements": None,
        "eventID": "12345678-1234-1234-1234-123456789012",
        "readOnly": False,
        "eventType": "AwsApiCall",
        "managementEvent": True,
        "recipientAccountId": "123456789012"
    }

@pytest.fixture
def sample_finding():
    """Sample finding for testing"""
    from app.models import Finding
    import uuid
    from datetime import datetime
    
    return Finding(
        id=uuid.uuid4(),
        rule_id="S3-001",
        resource_id="test-bucket-123",
        resource_type="s3",
        severity="HIGH",
        event_id="12345678-1234-1234-1234-123456789012",
        timestamp=datetime.utcnow(),
        remediation_steps="Remove public access from bucket policy",
        account_id="123456789012",
        region="us-east-1",
        status="OPEN"
    )

@pytest.fixture
def mock_redis():
    """Mock Redis client for testing"""
    mock_redis = AsyncMock()
    mock_redis.ping.return_value = True
    mock_redis.get.return_value = None
    mock_redis.set.return_value = True
    mock_redis.delete.return_value = 1
    return mock_redis

@pytest.fixture
def mock_aws_client():
    """Mock AWS client for testing"""
    mock_client = AsyncMock()
    mock_client.get_paginator.return_value.paginate.return_value = [
        {
            'Accounts': [
                {
                    'Id': '123456789012',
                    'Arn': 'arn:aws:organizations::123456789012:account/o-example123456/a-example123456',
                    'Email': 'test@example.com',
                    'Name': 'Test Account',
                    'Status': 'ACTIVE',
                    'JoinedMethod': 'INVITED',
                    'JoinedTimestamp': '2024-01-01T00:00:00Z'
                }
            ]
        }
    ]
    return mock_client

@pytest.fixture
def sample_security_events():
    """Sample security events for testing"""
    return [
        {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "Root",
                "principalId": "123456789012",
                "arn": "arn:aws:iam::123456789012:root",
                "accountId": "123456789012"
            },
            "eventTime": "2024-01-15T12:00:00Z",
            "eventSource": "iam.amazonaws.com",
            "eventName": "CreateUser",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "192.0.2.0",
            "userAgent": "[aws-cli/2.0.0]",
            "requestParameters": {"userName": "new-user"},
            "responseElements": {
                "user": {
                    "path": "/",
                    "userName": "new-user",
                    "userId": "AIDACKCEVSQ6C2EXAMPLE",
                    "arn": "arn:aws:iam::123456789012:user/new-user",
                    "createDate": "2024-01-15T12:00:00Z"
                }
            },
            "eventID": "12345678-1234-1234-1234-123456789013",
            "eventType": "AwsApiCall",
            "managementEvent": True
        },
        {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": "AIDACKCEVSQ6C2EXAMPLE",
                "arn": "arn:aws:iam::123456789012:user/test-user",
                "accountId": "123456789012",
                "userName": "test-user"
            },
            "eventTime": "2024-01-15T12:05:00Z",
            "eventSource": "s3.amazonaws.com",
            "eventName": "PutObject",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "192.0.2.0",
            "userAgent": "[aws-cli/2.0.0]",
            "requestParameters": {
                "bucketName": "test-bucket-123",
                "key": "sensitive-data.txt"
            },
            "responseElements": None,
            "eventID": "12345678-1234-1234-1234-123456789014",
            "eventType": "AwsApiCall",
            "managementEvent": False
        }
    ]

@pytest.fixture
def sample_rules():
    """Sample security rules for testing"""
    return [
        {
            "id": "IAM-001",
            "description": "Root account usage detected",
            "severity": "CRITICAL",
            "resource_types": ["iam"],
            "enabled": True
        },
        {
            "id": "S3-001", 
            "description": "Public S3 bucket detected",
            "severity": "HIGH",
            "resource_types": ["s3"],
            "enabled": True
        },
        {
            "id": "EC2-001",
            "description": "Security group with open SSH access",
            "severity": "MEDIUM",
            "resource_types": ["ec2"],
            "enabled": True
        }
    ]

# Test database cleanup
@pytest.fixture(autouse=True)
async def cleanup_test_data():
    """Clean up test data after each test"""
    yield
    # This will run after each test
    pass

# Mock environment variables
@pytest.fixture
def mock_env_vars(monkeypatch):
    """Mock environment variables for testing"""
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test-key")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test-secret")
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/1")
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test_db")
