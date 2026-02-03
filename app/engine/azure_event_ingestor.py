import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
import uuid

from azure.mgmt.monitor import MonitorManagementClient
from azure.identity import DefaultAzureCredential
from azure.mgmt.resourcegraph import ResourceGraphClient
from azure.mgmt.resourcegraph.models import QueryRequest
import aiohttp

from app.config import get_settings
from app.database import AsyncSessionLocal
from app.models import Event
from app.engine.rule_engine import RuleEngine

logger = logging.getLogger(__name__)

class AzureActivityLogNormalizer:
    """Normalizes Azure Activity Log events into our internal format"""
    
    @staticmethod
    def normalize_event(azure_event: Dict[str, Any]) -> Dict[str, Any]:
        """Extract and normalize relevant fields from Azure Activity Log"""
        
        # Extract basic event information
        operation_name = azure_event.get('operationName', {}).get('value', '')
        event_source = azure_event.get('category', {}).get('value', '')
        event_time_str = azure_event.get('eventTimestamp', '')
        
        # Parse timestamp
        try:
            event_time = datetime.fromisoformat(event_time_str.replace('Z', '+00:00'))
        except:
            event_time = datetime.utcnow()
        
        # Extract subscription and resource group
        subscription_id = azure_event.get('subscriptionId', '')
        resource_group = azure_event.get('resourceGroup', '')
        
        # Extract resource information
        resource_id = azure_event.get('resourceId', '')
        resource_type, resource_name = AzureActivityLogNormalizer._extract_resource_info(resource_id)
        
        # Generate unique event ID if not present
        event_id = azure_event.get('id', f"azure-{str(uuid.uuid4())}")
        
        return {
            'cloud_provider': 'azure',
            'event_id': event_id,
            'event_name': operation_name,
            'event_source': event_source,
            'event_time': event_time,
            'resource_id': resource_id,
            'resource_name': resource_name,
            'resource_type': resource_type,
            'account_id': subscription_id,
            'tenant_id': azure_event.get('tenantId', ''),
            'resource_group': resource_group,
            'region': azure_event.get('resourceLocation', ''),
            'caller': azure_event.get('caller', ''),
            'operation_name': operation_name,
            'raw_event': azure_event
        }
    
    @staticmethod
    def _extract_resource_info(resource_id: str) -> tuple:
        """Extract resource type and name from Azure resource ID"""
        if not resource_id:
            return 'unknown', 'unknown'
        
        parts = resource_id.split('/')
        if len(parts) >= 9:
            # Format: /subscriptions/{sub}/resourceGroups/{rg}/providers/{provider}/{type}/{name}
            resource_type = parts[7]  # Resource type
            resource_name = parts[8]  # Resource name
            return resource_type, resource_name
        elif len(parts) >= 3:
            return parts[-2], parts[-1]
        else:
            return 'unknown', resource_id
    
    @staticmethod
    def map_azure_resource_type(azure_type: str) -> str:
        """Map Azure resource types to generic resource types"""
        type_mapping = {
            'Microsoft.Storage/storageAccounts': 'storage-account',
            'Microsoft.Compute/virtualMachines': 'virtual-machine',
            'Microsoft.Network/networkSecurityGroups': 'network-security-group',
            'Microsoft.Sql/servers': 'sql-server',
            'Microsoft.Web/sites': 'web-app',
            'Microsoft.ContainerService/managedClusters': 'kubernetes-service',
            'Microsoft.KeyVault/vaults': 'key-vault',
            'Microsoft.CognitiveServices/accounts': 'cognitive-services',
            'Microsoft.DBforPostgreSQL/servers': 'postgresql-server',
            'Microsoft.DBforMySQL/servers': 'mysql-server',
            'Microsoft.DBforMariaDB/servers': 'mariadb-server',
            'Microsoft.Cache/Redis': 'redis-cache',
            'Microsoft.EventHub/namespaces': 'event-hub',
            'Microsoft.ServiceBus/namespaces': 'service-bus',
            'Microsoft.DocumentDB/databaseAccounts': 'cosmos-db',
            'Microsoft.Resources/subscriptions': 'subscription',
            'Microsoft.Resources/resourceGroups': 'resource-group'
        }
        return type_mapping.get(azure_type, azure_type)


class AzureEventIngestor:
    """Ingests Azure Activity Log events from multiple sources"""
    
    def __init__(self):
        self.settings = get_settings()
        self.running = False
        self.rule_engine = RuleEngine()
        self.credential = None
        self.subscription_id = None
        
    async def initialize_azure_connection(self):
        """Initialize Azure connection using managed identity or service principal"""
        try:
            # Use DefaultAzureCredential which supports multiple authentication methods
            self.credential = DefaultAzureCredential()
            
            # Get subscription ID from settings or discover it
            self.subscription_id = self.settings.azure_subscription_id
            
            if not self.subscription_id:
                # Try to get first subscription
                from azure.mgmt.subscription import SubscriptionClient
                sub_client = SubscriptionClient(self.credential)
                subscriptions = list(sub_client.subscriptions.list())
                if subscriptions:
                    self.subscription_id = subscriptions[0].subscription_id
                    logger.info(f"Using subscription: {self.subscription_id}")
                else:
                    logger.error("No Azure subscriptions found")
                    return False
            
            logger.info(f"Azure connection initialized for subscription: {self.subscription_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error initializing Azure connection: {e}")
            return False
    
    async def ingest_from_event_hub(self):
        """Ingest events from Azure Event Hub (recommended for production)"""
        try:
            from azure.eventhub import EventHubConsumerClient
            from azure.eventhub.extensions.checkpointstoreblobaio import BlobCheckpointStore
            
            connection_str = self.settings.azure_eventhub_connection_string
            eventhub_name = self.settings.azure_eventhub_name
            storage_connection_str = self.settings.azure_storage_connection_string
            container_name = self.settings.azure_storage_container
            
            if not all([connection_str, eventhub_name, storage_connection_str]):
                logger.warning("Azure Event Hub configuration incomplete, using mock events")
                await self._generate_azure_test_events()
                return
            
            # Create checkpoint store for tracking processed events
            checkpoint_store = BlobCheckpointStore.from_connection_string(
                storage_connection_str,
                container_name
            )
            
            # Create consumer client
            consumer_client = EventHubConsumerClient.from_connection_string(
                connection_str,
                consumer_group="$Default",
                eventhub_name=eventhub_name,
                checkpoint_store=checkpoint_store
            )
            
            logger.info("Starting Azure Event Hub ingestion...")
            
            async def on_event(partition_context, event):
                try:
                    # Parse event data
                    event_body = json.loads(event.body_as_str())
                    
                    # Normalize Azure event
                    normalized_event = AzureActivityLogNormalizer.normalize_event(event_body)
                    
                    # Store event in database
                    async with AsyncSessionLocal() as session:
                        event_record = Event(
                            cloud_provider='azure',
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
                    
                    # Update checkpoint
                    await partition_context.update_checkpoint(event)
                    
                    logger.debug(f"Processed Azure event: {normalized_event['event_name']}")
                    
                except Exception as e:
                    logger.error(f"Error processing Azure Event Hub event: {e}")
            
            # Start consuming events
            async with consumer_client:
                await consumer_client.receive(
                    on_event=on_event,
                    starting_position="-1"  # Start from beginning
                )
                
        except ImportError:
            logger.error("Azure Event Hub libraries not installed. Install with: pip install azure-eventhub azure-eventhub-checkpointstoreblob-aio")
            await self._generate_azure_test_events()
        except Exception as e:
            logger.error(f"Error in Event Hub ingestion: {e}")
            await self._generate_azure_test_events()
    
    async def ingest_from_activity_logs_api(self):
        """Ingest events from Azure Activity Logs API (for smaller deployments)"""
        try:
            if not await self.initialize_azure_connection():
                logger.warning("Azure connection failed, using test events")
                await self._generate_azure_test_events()
                return
            
            monitor_client = MonitorManagementClient(self.credential, self.subscription_id)
            
            logger.info("Starting Azure Activity Logs API ingestion...")
            
            # Calculate time range (last 5 minutes)
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(minutes=5)
            
            # Filter for security-related events
            filter_str = (
                f"eventTimestamp ge '{start_time.isoformat()}' and "
                f"eventTimestamp le '{end_time.isoformat()}' and "
                "(category.value eq 'Administrative' or "
                "category.value eq 'Security' or "
                "category.value eq 'Policy' or "
                "category.value eq 'Write')"
            )
            
            while self.running:
                try:
                    # Query activity logs
                    logs = monitor_client.activity_logs.list(filter=filter_str)
                    
                    for log in logs:
                        # Convert to dict
                        log_dict = log.as_dict()
                        
                        # Normalize event
                        normalized_event = AzureActivityLogNormalizer.normalize_event(log_dict)
                        
                        # Store event
                        async with AsyncSessionLocal() as session:
                            event_record = Event(
                                cloud_provider='azure',
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
                        
                        logger.debug(f"Processed Azure activity log: {normalized_event['event_name']}")
                    
                    # Wait before next poll
                    await asyncio.sleep(300)  # 5 minutes
                    
                except Exception as e:
                    logger.error(f"Error querying activity logs: {e}")
                    await asyncio.sleep(60)
                    
        except Exception as e:
            logger.error(f"Error in Activity Logs API ingestion: {e}")
            await self._generate_azure_test_events()
    
    async def _generate_azure_test_events(self):
        """Generate test Azure events for development"""
        test_events = [
            {
                'id': f'azure-test-{uuid.uuid4()}',
                'operationName': {'value': 'Microsoft.Storage/storageAccounts/write'},
                'category': {'value': 'Write'},
                'eventTimestamp': datetime.utcnow().isoformat() + 'Z',
                'subscriptionId': 'test-subscription-123',
                'tenantId': 'test-tenant-123',
                'resourceGroup': 'test-rg',
                'resourceId': '/subscriptions/test-subscription-123/resourceGroups/test-rg/providers/Microsoft.Storage/storageAccounts/teststorage123',
                'resourceLocation': 'eastus',
                'caller': 'testuser@example.com',
                'properties': {
                    'statusCode': 'Created',
                    'serviceRequestId': 'test-request-id'
                }
            },
            {
                'id': f'azure-test-{uuid.uuid4()}',
                'operationName': {'value': 'Microsoft.Network/networkSecurityGroups/securityRules/write'},
                'category': {'value': 'Write'},
                'eventTimestamp': datetime.utcnow().isoformat() + 'Z',
                'subscriptionId': 'test-subscription-123',
                'resourceGroup': 'test-rg',
                'resourceId': '/subscriptions/test-subscription-123/resourceGroups/test-rg/providers/Microsoft.Network/networkSecurityGroups/test-nsg',
                'resourceLocation': 'eastus',
                'caller': 'testuser@example.com',
                'properties': {
                    'statusCode': 'OK',
                    'serviceRequestId': 'test-request-id-2'
                }
            },
            {
                'id': f'azure-test-{uuid.uuid4()}',
                'operationName': {'value': 'Microsoft.KeyVault/vaults/write'},
                'category': {'value': 'Write'},
                'eventTimestamp': datetime.utcnow().isoformat() + 'Z',
                'subscriptionId': 'test-subscription-123',
                'tenantId': 'test-tenant-123',
                'resourceGroup': 'test-rg',
                'resourceId': '/subscriptions/test-subscription-123/resourceGroups/test-rg/providers/Microsoft.KeyVault/vaults/test-kv',
                'resourceLocation': 'eastus',
                'caller': 'testuser@example.com',
                'properties': {
                    'statusCode': 'Created',
                    'serviceRequestId': 'test-request-id-3'
                }
            }
        ]
        
        for test_event in test_events:
            normalized_event = AzureActivityLogNormalizer.normalize_event(test_event)
            
            # Store event
            async with AsyncSessionLocal() as session:
                event_record = Event(
                    cloud_provider='azure',
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
            
            await asyncio.sleep(1)
    
    async def start(self, source: str = 'test'):
        """Start the Azure event ingestor"""
        self.running = True
        
        logger.info(f"Starting Azure event ingestor with source: {source}")
        
        if source == 'eventhub':
            await self.ingest_from_event_hub()
        elif source == 'activitylogs':
            await self.ingest_from_activity_logs_api()
        else:
            await self._generate_azure_test_events()
    
    async def stop(self):
        """Stop the Azure event ingestor"""
        self.running = False
        logger.info("Azure event ingestor stopped")


# Global Azure ingestor instance
azure_ingestor = AzureEventIngestor()

async def start_azure_event_ingestor():
    """Start the Azure event ingestor as a background task"""
    asyncio.create_task(azure_ingestor.start('test'))
