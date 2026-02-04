import asyncio
import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional
import uuid
import base64

from google.cloud import logging_v2
from google.cloud import pubsub_v1
from google.cloud import asset_v1
from google.cloud import securitycenter_v1
from google.oauth2 import service_account
import aiohttp

from app.config import get_settings
from app.database import AsyncSessionLocal
from app.models import Event
from app.engine.rule_engine import RuleEngine

logger = logging.getLogger(__name__)

class GCPAuditLogNormalizer:
    """Normalizes GCP Audit Log events into our internal format"""
    
    @staticmethod
    def normalize_event(gcp_event: Dict[str, Any]) -> Dict[str, Any]:
        """Extract and normalize relevant fields from GCP Audit Log"""
        
        # Extract payload (can be protoPayload or jsonPayload)
        payload = gcp_event.get('protoPayload') or gcp_event.get('jsonPayload') or {}
        
        # Extract basic event information
        method_name = payload.get('methodName', '')
        service_name = payload.get('serviceName', '')
        resource_name = payload.get('resourceName', '')
        event_time_str = gcp_event.get('timestamp', '')
        
        # Parse timestamp
        try:
            event_time = datetime.fromisoformat(event_time_str.replace('Z', '+00:00'))
        except:
            event_time = datetime.utcnow()
        
        # Extract project and resource information
        project_id = gcp_event.get('resource', {}).get('labels', {}).get('project_id', '')
        
        # Generate unique event ID
        event_id = gcp_event.get('insertId', f"gcp-{str(uuid.uuid4())}")
        
        # Extract resource type and name
        resource_type, resource_id = GCPAuditLogNormalizer._extract_resource_info(resource_name)
        
        # Extract region from resource labels or location
        region = gcp_event.get('resource', {}).get('labels', {}).get('location', '')
        
        return {
            'cloud_provider': 'gcp',
            'event_id': event_id,
            'event_name': method_name,
            'event_source': service_name,
            'event_time': event_time,
            'resource_id': resource_id,
            'resource_name': resource_id,
            'resource_type': resource_type,
            'account_id': project_id,
            'project_id': project_id,
            'region': region,
            'caller': payload.get('authenticationInfo', {}).get('principalEmail', ''),
            'raw_event': gcp_event
        }
    
    @staticmethod
    def _extract_resource_info(resource_name: str) -> tuple:
        """Extract resource type and ID from GCP resource name"""
        if not resource_name:
            return 'unknown', 'unknown'
        
        # Format: //{service}.googleapis.com/{resource_path}
        parts = resource_name.split('/')
        
        if len(parts) >= 2:
            service_part = parts[0]  # e.g., //compute.googleapis.com
            service_name = service_part.replace('//', '').replace('.googleapis.com', '')
            
            # Extract resource type from path
            resource_parts = parts[1:]
            if len(resource_parts) >= 2:
                resource_type = f"{service_name}/{resource_parts[0]}"
                resource_id = resource_parts[-1]
                return resource_type, resource_id
        
        return 'unknown', resource_name
    
    @staticmethod
    def map_gcp_resource_type(gcp_type: str) -> str:
        """Map GCP resource types to generic resource types"""
        type_mapping = {
            'compute.googleapis.com/Instance': 'compute-instance',
            'compute.googleapis.com/Firewall': 'firewall',
            'storage.googleapis.com/Bucket': 'storage-bucket',
            'cloudresourcemanager.googleapis.com/Project': 'project',
            'iam.googleapis.com/ServiceAccount': 'service-account',
            'cloudkms.googleapis.com/CryptoKey': 'kms-key',
            'sqladmin.googleapis.com/Instance': 'sql-instance',
            'bigquery.googleapis.com/Table': 'bigquery-table',
            'pubsub.googleapis.com/Topic': 'pubsub-topic',
            'container.googleapis.com/Cluster': 'kubernetes-cluster',
            'logging.googleapis.com/LogBucket': 'log-bucket',
            'secretmanager.googleapis.com/Secret': 'secret',
            'cloudfunctions.googleapis.com/CloudFunction': 'cloud-function',
            'appengine.googleapis.com/Application': 'app-engine-app',
            'cloudbuild.googleapis.com/Build': 'cloud-build',
        }
        return type_mapping.get(gcp_type, gcp_type)


class GCPEventIngestor:
    """Ingests GCP Audit Log events from multiple sources"""
    
    def __init__(self):
        self.settings = get_settings()
        self.running = False
        self.rule_engine = RuleEngine()
        self.credentials = None
        self.project_id = None
        
    async def initialize_gcp_connection(self):
        """Initialize GCP connection using service account or application default credentials"""
        try:
            # Check for service account key
            if self.settings.gcp_service_account_key:
                # Load from JSON string
                key_info = json.loads(self.settings.gcp_service_account_key)
                self.credentials = service_account.Credentials.from_service_account_info(key_info)
            else:
                # Use application default credentials
                import google.auth
                self.credentials, self.project_id = google.auth.default()
            
            # Get project ID from settings or credentials
            self.project_id = self.settings.gcp_project_id or self.project_id
            
            if not self.project_id:
                logger.error("No GCP project ID configured")
                return False
            
            logger.info(f"GCP connection initialized for project: {self.project_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error initializing GCP connection: {e}")
            return False
    
    async def ingest_from_pubsub(self):
        """Ingest events from GCP Pub/Sub (recommended for production)"""
        try:
            from google.cloud import pubsub_v1
            
            subscription_id = self.settings.gcp_pubsub_subscription_id
            if not subscription_id:
                logger.warning("GCP Pub/Sub subscription not configured, using mock events")
                await self._generate_gcp_test_events()
                return
            
            # Create subscriber client
            subscriber = pubsub_v1.SubscriberClient(credentials=self.credentials)
            subscription_path = subscriber.subscription_path(self.project_id, subscription_id)
            
            logger.info(f"Starting GCP Pub/Sub ingestion from {subscription_path}")
            
            def callback(message):
                try:
                    # Parse message data
                    event_data = json.loads(message.data.decode('utf-8'))
                    
                    # Extract log entry from Pub/Sub message
                    log_entry = event_data.get('logEntry') or event_data
                    
                    # Normalize GCP event
                    normalized_event = GCPAuditLogNormalizer.normalize_event(log_entry)
                    
                    # Store event in database
                    asyncio.create_task(self._store_and_process_event(normalized_event))
                    
                    # Acknowledge message
                    message.ack()
                    
                    logger.debug(f"Processed GCP event: {normalized_event['event_name']}")
                    
                except Exception as e:
                    logger.error(f"Error processing Pub/Sub message: {e}")
                    message.nack()
            
            # Start streaming
            streaming_pull_future = subscriber.subscribe(
                subscription_path,
                callback=callback
            )
            
            logger.info("Listening for messages on Pub/Sub...")
            
            # Keep the subscription alive
            with subscriber:
                try:
                    streaming_pull_future.result()
                except KeyboardInterrupt:
                    streaming_pull_future.cancel()
                    
        except Exception as e:
            logger.error(f"Error in Pub/Sub ingestion: {e}")
            await self._generate_gcp_test_events()
    
    async def ingest_from_logging_sink(self):
        """Ingest events from Logging sink (alternative method)"""
        try:
            logging_client = logging_v2.LoggingServiceV2Client(credentials=self.credentials)
            
            # Build filter for audit logs
            filter_str = (
                'logName:"cloudaudit.googleapis.com" AND '
                'protoPayload.serviceName=("compute.googleapis.com",'
                '"storage.googleapis.com",'
                '"cloudresourcemanager.googleapis.com",'
                '"iam.googleapis.com",'
                '"sqladmin.googleapis.com")'
            )
            
            logger.info("Starting GCP Logging API ingestion...")
            
            while self.running:
                try:
                    # List log entries
                    request = logging_v2.ListLogEntriesRequest(
                        resource_names=[f"projects/{self.project_id}"],
                        filter=filter_str,
                        page_size=100,
                        order_by="timestamp desc"
                    )
                    
                    entries = logging_client.list_log_entries(request)
                    
                    for entry in entries:
                        # Convert to dict
                        entry_dict = json.loads(logging_v2.LogEntry.to_json(entry))
                        
                        # Normalize event
                        normalized_event = GCPAuditLogNormalizer.normalize_event(entry_dict)
                        
                        # Store and process
                        await self._store_and_process_event(normalized_event)
                    
                    # Wait before next poll
                    await asyncio.sleep(300)  # 5 minutes
                    
                except Exception as e:
                    logger.error(f"Error querying logging API: {e}")
                    await asyncio.sleep(60)
                    
        except Exception as e:
            logger.error(f"Error in Logging API ingestion: {e}")
            await self._generate_gcp_test_events()
    
    async def _store_and_process_event(self, normalized_event: Dict[str, Any]):
        """Store event and process with rule engine"""
        try:
            # Store event in database
            async with AsyncSessionLocal() as session:
                event_record = Event(
                    cloud_provider='gcp',
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
            
        except Exception as e:
            logger.error(f"Error storing/processing GCP event: {e}")
    
    async def _generate_gcp_test_events(self):
        """Generate test GCP events for development"""
        test_events = [
            {
                'insertId': f'gcp-test-{uuid.uuid4()}',
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'resource': {
                    'type': 'gce_instance',
                    'labels': {
                        'project_id': 'test-project-123',
                        'zone': 'us-central1-a'
                    }
                },
                'protoPayload': {
                    '@type': 'type.googleapis.com/google.cloud.audit.AuditLog',
                    'serviceName': 'compute.googleapis.com',
                    'methodName': 'v1.compute.instances.insert',
                    'resourceName': 'projects/test-project-123/zones/us-central1-a/instances/test-vm',
                    'authenticationInfo': {
                        'principalEmail': 'testuser@example.com'
                    }
                }
            },
            {
                'insertId': f'gcp-test-{uuid.uuid4()}',
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'resource': {
                    'type': 'gcs_bucket',
                    'labels': {
                        'project_id': 'test-project-123',
                        'location': 'us-central1'
                    }
                },
                'protoPayload': {
                    '@type': 'type.googleapis.com/google.cloud.audit.AuditLog',
                    'serviceName': 'storage.googleapis.com',
                    'methodName': 'storage.buckets.create',
                    'resourceName': 'projects/_/buckets/test-bucket-123',
                    'authenticationInfo': {
                        'principalEmail': 'testuser@example.com'
                    }
                }
            },
            {
                'insertId': f'gcp-test-{uuid.uuid4()}',
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'resource': {
                    'type': 'gce_firewall_rule',
                    'labels': {
                        'project_id': 'test-project-123'
                    }
                },
                'protoPayload': {
                    '@type': 'type.googleapis.com/google.cloud.audit.AuditLog',
                    'serviceName': 'compute.googleapis.com',
                    'methodName': 'v1.compute.firewalls.insert',
                    'resourceName': 'projects/test-project-123/global/firewalls/test-firewall',
                    'authenticationInfo': {
                        'principalEmail': 'testuser@example.com'
                    }
                }
            }
        ]
        
        for test_event in test_events:
            normalized_event = GCPAuditLogNormalizer.normalize_event(test_event)
            await self._store_and_process_event(normalized_event)
            await asyncio.sleep(1)
    
    async def start(self, source: str = 'test'):
        """Start the GCP event ingestor"""
        self.running = True
        
        logger.info(f"Starting GCP event ingestor with source: {source}")
        
        if source == 'pubsub':
            await self.ingest_from_pubsub()
        elif source == 'logging':
            await self.ingest_from_logging_sink()
        else:
            await self._generate_gcp_test_events()
    
    async def stop(self):
        """Stop the GCP event ingestor"""
        self.running = False
        logger.info("GCP event ingestor stopped")


# Global GCP ingestor instance
gcp_ingestor = GCPEventIngestor()

async def start_gcp_event_ingestor():
    """Start the GCP event ingestor as a background task"""
    asyncio.create_task(gcp_ingestor.start('test'))