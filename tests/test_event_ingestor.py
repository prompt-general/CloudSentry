import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
from app.engine.event_ingestor import EventIngestor, CloudTrailNormalizer

@pytest.fixture
def event_ingestor():
    return EventIngestor()

@pytest.fixture
def sample_cloudtrail_event():
    return {
        'eventID': '12345678-1234-1234-1234-123456789012',
        'eventName': 'CreateBucket',
        'eventSource': 's3.amazonaws.com',
        'eventTime': '2024-01-15T12:00:00Z',
        'awsRegion': 'us-east-1',
        'userIdentity': {'accountId': '123456789012'},
        'requestParameters': {'bucketName': 'test-bucket-123'}
    }

def test_normalize_event(sample_cloudtrail_event):
    """Test CloudTrail event normalization"""
    normalized = CloudTrailNormalizer.normalize_event(sample_cloudtrail_event)
    
    assert normalized['event_id'] == '12345678-1234-1234-1234-123456789012'
    assert normalized['event_name'] == 'CreateBucket'
    assert normalized['event_source'] == 's3.amazonaws.com'
    assert normalized['resource_type'] == 's3'
    assert normalized['resource_id'] == 'test-bucket-123'
    assert normalized['account_id'] == '123456789012'
    assert normalized['region'] == 'us-east-1'

@pytest.mark.asyncio
async def test_event_ingestor_start_stop(event_ingestor):
    """Test event ingestor start/stop"""
    with patch.object(event_ingestor, '_generate_test_events', new_callable=AsyncMock) as mock_generate:
        event_ingestor.running = False
        await event_ingestor.start('test')
        assert event_ingestor.running == True
        
        await event_ingestor.stop()
        assert event_ingestor.running == False
        
        mock_generate.assert_called_once()

def test_resource_extraction():
    """Test resource extraction from various event types"""
    
    # S3 event
    s3_event = {
        'eventSource': 's3.amazonaws.com',
        'requestParameters': {'bucketName': 'my-bucket'}
    }
    resource_type, resource_id = CloudTrailNormalizer._extract_resource_info(s3_event)
    assert resource_type == 's3'
    assert resource_id == 'my-bucket'
    
    # EC2 event
    ec2_event = {
        'eventSource': 'ec2.amazonaws.com',
        'requestParameters': {'instanceId': 'i-12345678'}
    }
    resource_type, resource_id = CloudTrailNormalizer._extract_resource_info(ec2_event)
    assert resource_type == 'ec2'
    assert resource_id == 'i-12345678'
    
    # IAM event
    iam_event = {
        'eventSource': 'iam.amazonaws.com',
        'requestParameters': {'userName': 'test-user'}
    }
    resource_type, resource_id = CloudTrailNormalizer._extract_resource_info(iam_event)
    assert resource_type == 'iam'
    assert resource_id == 'test-user'
