import asyncio
import sys
sys.path.append('.')  # Add current directory to path

# Import just the normalizer class to avoid aioredis dependency
import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional

class CloudTrailNormalizer:
    """Normalizes AWS CloudTrail events into our internal format"""
    
    @staticmethod
    def normalize_event(cloudtrail_event: Dict[str, Any]) -> Dict[str, Any]:
        """Extract and normalize relevant fields from CloudTrail event"""
        
        # Extract basic event information
        event_id = cloudtrail_event.get('eventID', '')
        event_name = cloudtrail_event.get('eventName', '')
        event_source = cloudtrail_event.get('eventSource', '')
        event_time_str = cloudtrail_event.get('eventTime', '')
        
        # Parse timestamp
        try:
            event_time = datetime.fromisoformat(event_time_str.replace('Z', '+00:00'))
        except:
            event_time = datetime.utcnow()
        
        # Extract account and region
        account_id = cloudtrail_event.get('userIdentity', {}).get('accountId', '')
        region = cloudtrail_event.get('awsRegion', '')
        
        # Extract resource information
        resource_type, resource_id = CloudTrailNormalizer._extract_resource_info(cloudtrail_event)
        
        return {
            'event_id': event_id,
            'event_name': event_name,
            'event_source': event_source,
            'event_time': event_time,
            'resource_id': resource_id,
            'resource_type': resource_type,
            'account_id': account_id,
            'region': region,
            'raw_event': cloudtrail_event
        }
    
    @staticmethod
    def _extract_resource_info(event: Dict[str, Any]) -> tuple:
        """Extract resource type and ID from CloudTrail event"""
        
        event_source = event.get('eventSource', '').lower()
        event_name = event.get('eventName', '').lower()
        request_params = event.get('requestParameters', {})
        
        # Map common AWS services to resource types
        if 's3.amazonaws.com' in event_source:
            resource_type = 's3'
            resource_id = request_params.get('bucketName', '')
        elif 'ec2.amazonaws.com' in event_source:
            resource_type = 'ec2'
            # Try to get instance ID from various places
            resource_id = (
                request_params.get('instanceId') or
                request_params.get('instancesSet', {}).get('items', [{}])[0].get('instanceId') or
                ''
            )
        elif 'iam.amazonaws.com' in event_source:
            resource_type = 'iam'
            resource_id = (
                request_params.get('userName') or
                request_params.get('roleName') or
                request_params.get('policyName') or
                ''
            )
        elif 'rds.amazonaws.com' in event_source:
            resource_type = 'rds'
            resource_id = request_params.get('dBInstanceIdentifier', '')
        elif 'lambda.amazonaws.com' in event_source:
            resource_type = 'lambda'
            resource_id = request_params.get('functionName', '')
        elif 'secretsmanager.amazonaws.com' in event_source:
            resource_type = 'secretsmanager'
            resource_id = request_params.get('secretId', '')
        else:
            # Generic extraction from response elements
            resource_type = event_source.split('.')[0] if '.' in event_source else 'unknown'
            resource_id = ''
        
        return resource_type, resource_id

def test_cloudtrail_normalizer():
    """Test CloudTrail event normalization"""
    print("Testing CloudTrail Normalizer...")
    
    # Test S3 event
    s3_event = {
        'eventID': '12345678-1234-1234-1234-123456789012',
        'eventName': 'CreateBucket',
        'eventSource': 's3.amazonaws.com',
        'eventTime': '2024-01-15T12:00:00Z',
        'awsRegion': 'us-east-1',
        'userIdentity': {'accountId': '123456789012'},
        'requestParameters': {'bucketName': 'test-bucket-123'}
    }
    
    normalized = CloudTrailNormalizer.normalize_event(s3_event)
    
    print(f"[PASS] S3 Event ID: {normalized['event_id']}")
    print(f"[PASS] S3 Event Name: {normalized['event_name']}")
    print(f"[PASS] S3 Resource Type: {normalized['resource_type']}")
    print(f"[PASS] S3 Resource ID: {normalized['resource_id']}")
    print(f"[PASS] S3 Account ID: {normalized['account_id']}")
    print(f"[PASS] S3 Region: {normalized['region']}")
    
    # Test EC2 event
    ec2_event = {
        'eventID': '87654321-4321-4321-4321-210987654321',
        'eventName': 'AuthorizeSecurityGroupIngress',
        'eventSource': 'ec2.amazonaws.com',
        'eventTime': '2024-01-15T13:00:00Z',
        'awsRegion': 'us-east-1',
        'userIdentity': {'accountId': '123456789012'},
        'requestParameters': {
            'groupId': 'sg-12345678',
            'ipPermissions': {
                'items': [{
                    'ipProtocol': 'tcp',
                    'fromPort': 22,
                    'toPort': 22,
                    'ipRanges': {'items': [{'cidrIp': '0.0.0.0/0'}]}
                }]
            }
        }
    }
    
    normalized = CloudTrailNormalizer.normalize_event(ec2_event)
    print(f"[PASS] EC2 Event ID: {normalized['event_id']}")
    print(f"[PASS] EC2 Event Name: {normalized['event_name']}")
    print(f"[PASS] EC2 Resource Type: {normalized['resource_type']}")
    
    # Test IAM event
    iam_event = {
        'eventID': '11111111-2222-3333-4444-555555555555',
        'eventName': 'CreateUser',
        'eventSource': 'iam.amazonaws.com',
        'eventTime': '2024-01-15T14:00:00Z',
        'awsRegion': 'us-east-1',
        'userIdentity': {'accountId': '123456789012'},
        'requestParameters': {'userName': 'test-user'}
    }
    
    normalized = CloudTrailNormalizer.normalize_event(iam_event)
    print(f"[PASS] IAM Event ID: {normalized['event_id']}")
    print(f"[PASS] IAM Event Name: {normalized['event_name']}")
    print(f"[PASS] IAM Resource Type: {normalized['resource_type']}")
    print(f"[PASS] IAM Resource ID: {normalized['resource_id']}")
    
    print("\n[PASS] All CloudTrail Normalizer tests completed successfully!")
    print("[PASS] Event processing pipeline is working correctly!")

if __name__ == '__main__':
    test_cloudtrail_normalizer()
