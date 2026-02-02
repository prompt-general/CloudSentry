import asyncio
import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional
import boto3
from botocore.exceptions import ClientError
import aioredis

from app.config import get_settings
from app.database import AsyncSessionLocal
from app.models import Event
from app.engine.rule_engine import RuleEngine
from app.aws.organizations import AWSOrganizationsManager

logger = logging.getLogger(__name__)

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


class EventIngestor:
    """Ingests AWS CloudTrail events from multiple accounts"""
    
    def __init__(self):
        self.settings = get_settings()
        self.running = False
        self.rule_engine = RuleEngine()
        self.org_manager = AWSOrganizationsManager()
        
        # Initialize master session
        self.master_session = boto3.Session(
            region_name=self.settings.aws_region,
            aws_access_key_id=self.settings.aws_access_key_id,
            aws_secret_access_key=self.settings.aws_secret_access_key
        )
        
        # Initialize Redis for event queue
        self.redis = None
        
    async def connect_redis(self):
        """Connect to Redis for event queuing"""
        self.redis = await aioredis.from_url(
            self.settings.redis_url,
            decode_responses=True
        )
        logger.info("Connected to Redis for event queuing")
    
    async def ingest_from_eventbridge(self):
        """Ingest events from AWS EventBridge"""
        try:
            # For testing, we'll simulate EventBridge events
            # In production, this would connect to EventBridge bus
            logger.info("Starting EventBridge event ingestion...")
            
            # Create a mock EventBridge client for testing
            eventbridge_client = self.master_session.client('events')
            
            # List rules to verify connection
            try:
                rules = eventbridge_client.list_rules(EventBusName=self.settings.event_bridge_bus)
                logger.info(f"Connected to EventBridge bus: {self.settings.event_bridge_bus}")
                logger.info(f"Found {len(rules.get('Rules', []))} rules")
            except Exception as e:
                logger.warning(f"Could not list EventBridge rules: {e}")
                logger.info("Continuing with mock event generation for testing")
                
            # For now, generate test events
            await self._generate_test_events()
            
        except Exception as e:
            logger.error(f"Error in EventBridge ingestion: {e}")
    
    async def ingest_from_sqs(self):
        """Ingest events from SQS queue"""
        try:
            logger.info("Starting SQS event ingestion...")
            
            sqs_client = self.aws_session.client('sqs')
            
            if not self.settings.sqs_queue_url:
                logger.warning("No SQS queue URL configured, using test events")
                await self._generate_test_events()
                return
            
            while self.running:
                try:
                    # Receive messages from SQS
                    response = sqs_client.receive_message(
                        QueueUrl=self.settings.sqs_queue_url,
                        MaxNumberOfMessages=10,
                        WaitTimeSeconds=20,
                        VisibilityTimeout=30
                    )
                    
                    messages = response.get('Messages', [])
                    
                    for message in messages:
                        await self._process_sqs_message(message, sqs_client)
                        
                except ClientError as e:
                    logger.error(f"SQS receive error: {e}")
                    await asyncio.sleep(5)
                    
        except Exception as e:
            logger.error(f"Error in SQS ingestion: {e}")
    
    async def _process_sqs_message(self, message: Dict[str, Any], sqs_client):
        """Process a single SQS message"""
        try:
            # Parse message body
            body = json.loads(message['Body'])
            
            # CloudTrail events might be wrapped in SNS or EventBridge format
            if 'Message' in body:  # SNS wrapped
                inner_body = json.loads(body['Message'])
                if 'detail' in inner_body:  # EventBridge format
                    cloudtrail_event = inner_body['detail']
                else:
                    cloudtrail_event = inner_body
            elif 'detail' in body:  # Direct EventBridge format
                cloudtrail_event = body['detail']
            else:
                cloudtrail_event = body
            
            # Normalize and process the event
            normalized_event = CloudTrailNormalizer.normalize_event(cloudtrail_event)
            
            # Store event in database
            async with AsyncSessionLocal() as session:
                event_record = Event(
                    event_id=normalized_event['event_id'],
                    event_name=normalized_event['event_name'],
                    event_source=normalized_event['event_source'],
                    event_time=normalized_event['event_time'],
                    resource_id=normalized_event['resource_id'],
                    resource_type=normalized_event['resource_type'],
                    account_id=normalized_event['account_id'],
                    region=normalized_event['region'],
                    raw_event=normalized_event['raw_event']
                )
                session.add(event_record)
                await session.commit()
            
            # Evaluate event with rule engine
            await self.rule_engine.evaluate_event(normalized_event)
            
            # Delete message from queue
            sqs_client.delete_message(
                QueueUrl=self.settings.sqs_queue_url,
                ReceiptHandle=message['ReceiptHandle']
            )
            
            logger.debug(f"Processed event: {normalized_event['event_name']}")
            
        except Exception as e:
            logger.error(f"Error processing SQS message: {e}")
    
    async def _generate_test_events(self):
        """Generate test CloudTrail events for development"""
        test_events = [
            {
                'eventID': 'test-001',
                'eventName': 'CreateBucket',
                'eventSource': 's3.amazonaws.com',
                'eventTime': datetime.utcnow().isoformat() + 'Z',
                'awsRegion': 'us-east-1',
                'userIdentity': {'accountId': '123456789012'},
                'requestParameters': {'bucketName': 'test-public-bucket-123'}
            },
            {
                'eventID': 'test-002',
                'eventName': 'AuthorizeSecurityGroupIngress',
                'eventSource': 'ec2.amazonaws.com',
                'eventTime': datetime.utcnow().isoformat() + 'Z',
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
            },
            {
                'eventID': 'test-003',
                'eventName': 'PutBucketPolicy',
                'eventSource': 's3.amazonaws.com',
                'eventTime': datetime.utcnow().isoformat() + 'Z',
                'awsRegion': 'us-east-1',
                'userIdentity': {'accountId': '123456789012'},
                'requestParameters': {
                    'bucketName': 'test-public-bucket-123',
                    'policy': '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::test-public-bucket-123/*"}]}'
                }
            }
        ]
        
        for test_event in test_events:
            normalized_event = CloudTrailNormalizer.normalize_event(test_event)
            
            # Store event
            async with AsyncSessionLocal() as session:
                event_record = Event(
                    event_id=normalized_event['event_id'],
                    event_name=normalized_event['event_name'],
                    event_source=normalized_event['event_source'],
                    event_time=normalized_event['event_time'],
                    resource_id=normalized_event['resource_id'],
                    resource_type=normalized_event['resource_type'],
                    account_id=normalized_event['account_id'],
                    region=normalized_event['region'],
                    raw_event=normalized_event['raw_event']
                )
                session.add(event_record)
                await session.commit()
            
            # Evaluate with rule engine
            await self.rule_engine.evaluate_event(normalized_event)
            
            await asyncio.sleep(1)  # Small delay between test events
    
    async def start(self, source: str = 'test'):
        """Start the event ingestor"""
        self.running = True
        
        await self.connect_redis()
        
        logger.info(f"Starting event ingestor with source: {source}")
        
        if source == 'eventbridge':
            await self.ingest_from_eventbridge()
        elif source == 'sqs':
            await self.ingest_from_sqs()
        else:
            await self._generate_test_events()
    
    async def stop(self):
        """Stop the event ingestor"""
        self.running = False
        logger.info("Event ingestor stopped")


# Global ingestor instance
ingestor = EventIngestor()

async def start_event_ingestor():
    """Start the event ingestor as a background task"""
    # Start with test mode for now
    asyncio.create_task(ingestor.start('test'))