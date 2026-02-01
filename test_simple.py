import asyncio
import sys
sys.path.append('.')  # Add current directory to path

from app.engine.event_ingestor import CloudTrailNormalizer

def test_cloudtrail_normalizer():
    """Test CloudTrail event normalization without Redis dependency"""
    print("Testing CloudTrail Normalizer...")
    
    sample_event = {
        'eventID': '12345678-1234-1234-1234-123456789012',
        'eventName': 'CreateBucket',
        'eventSource': 's3.amazonaws.com',
        'eventTime': '2024-01-15T12:00:00Z',
        'awsRegion': 'us-east-1',
        'userIdentity': {'accountId': '123456789012'},
        'requestParameters': {'bucketName': 'test-bucket-123'}
    }
    
    normalized = CloudTrailNormalizer.normalize_event(sample_event)
    
    print(f"✅ Event ID: {normalized['event_id']}")
    print(f"✅ Event Name: {normalized['event_name']}")
    print(f"✅ Resource Type: {normalized['resource_type']}")
    print(f"✅ Resource ID: {normalized['resource_id']}")
    print(f"✅ Account ID: {normalized['account_id']}")
    print(f"✅ Region: {normalized['region']}")
    
    # Test resource extraction
    resource_type, resource_id = CloudTrailNormalizer._extract_resource_info(sample_event)
    print(f"✅ Extracted Resource Type: {resource_type}")
    print(f"✅ Extracted Resource ID: {resource_id}")
    
    print("\nCloudTrail Normalizer test completed successfully!")

if __name__ == '__main__':
    test_cloudtrail_normalizer()
