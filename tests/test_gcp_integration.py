import pytest
import json
from unittest.mock import Mock, patch, AsyncMock
from app.engine.gcp_event_ingestor import GCPAuditLogNormalizer, GCPEventIngestor
from app.engine.rules.gcp_rules import GCPBucketPublicAccessRule

@pytest.fixture
def sample_gcp_event():
    return {
        'insertId': 'test-gcp-id',
        'timestamp': '2024-01-15T12:00:00Z',
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
    }

def test_gcp_event_normalization(sample_gcp_event):
    """Test GCP Audit Log event normalization"""
    normalized = GCPAuditLogNormalizer.normalize_event(sample_gcp_event)
    
    assert normalized['cloud_provider'] == 'gcp'
    assert normalized['event_id'] == 'test-gcp-id'
    assert normalized['event_name'] == 'storage.buckets.create'
    assert normalized['event_source'] == 'storage.googleapis.com'
    assert normalized['resource_id'] == 'test-bucket-123'
    assert normalized['resource_type'] == 'storage.googleapis.com/Bucket'
    assert normalized['account_id'] == 'test-project-123'
    assert normalized['project_id'] == 'test-project-123'
    assert normalized['region'] == 'us-central1'

def test_gcp_resource_extraction():
    """Test GCP resource name parsing"""
    resource_name = 'projects/test-project-123/zones/us-central1-a/instances/test-vm'
    
    normalizer = GCPAuditLogNormalizer()
    resource_type, resource_id = normalizer._extract_resource_info(
        f'//compute.googleapis.com/{resource_name}'
    )
    
    assert resource_type == 'compute.googleapis.com/Instance'
    assert resource_id == 'test-vm'

@pytest.mark.asyncio
async def test_gcp_bucket_public_access_rule():
    """Test GCP bucket public access rule"""
    rule = GCPBucketPublicAccessRule()
    
    # Mock event
    event = {
        'cloud_provider': 'gcp',
        'resource_id': 'projects/_/buckets/test-bucket',
        'resource_type': 'storage.googleapis.com/Bucket',
        'event_id': 'test-001',
        'account_id': 'test-project-123',
        'project_id': 'test-project-123',
        'region': 'us-central1',
        'event_time': '2024-01-15T12:00:00Z'
    }
    
    # Mock GCP client
    with patch.object(rule, 'get_gcp_client') as mock_client:
        storage_mock = Mock()
        bucket_mock = Mock()
        policy_mock = Mock()
        
        # Mock bucket with public IAM policy
        binding_mock = Mock()
        binding_mock.members = ['allUsers']
        binding_mock.role = 'roles/storage.objectViewer'
        policy_mock.bindings = [binding_mock]
        
        bucket_mock.get_iam_policy.return_value = policy_mock
        storage_mock.get_bucket.return_value = bucket_mock
        mock_client.return_value = storage_mock
        
        finding = await rule.evaluate(event, {})
        
        assert finding is not None
        assert finding.rule_id == 'GCP-001'
        assert finding.severity == 'HIGH'
        assert finding.cloud_provider == 'gcp'

@pytest.mark.asyncio
async def test_gcp_event_ingestor_start_stop():
    """Test GCP event ingestor start and stop functionality"""
    ingestor = GCPEventIngestor()
    
    # Mock Pub/Sub subscription
    with patch.object(ingestor, '_setup_pubsub_subscription') as mock_setup:
        mock_setup.return_value = None
        
        # Test start
        await ingestor.start()
        assert ingestor.running is True
        
        # Test stop
        await ingestor.stop()
        assert ingestor.running is False

def test_gcp_event_normalizer_edge_cases():
    """Test GCP event normalizer with edge cases"""
    normalizer = GCPAuditLogNormalizer()
    
    # Test event with missing fields
    incomplete_event = {
        'insertId': 'test-id',
        'timestamp': '2024-01-15T12:00:00Z'
    }
    
    normalized = normalizer.normalize_event(incomplete_event)
    
    # Should handle missing fields gracefully
    assert normalized['cloud_provider'] == 'gcp'
    assert normalized['event_id'] == 'test-id'
    assert normalized.get('resource_id') is None
    assert normalized.get('account_id') is None

def test_gcp_resource_extraction_various_types():
    """Test GCP resource extraction for various resource types"""
    normalizer = GCPAuditLogNormalizer()
    
    test_cases = [
        {
            'resource_name': '//storage.googleapis.com/projects/_/buckets/my-bucket',
            'expected_type': 'storage.googleapis.com/Bucket',
            'expected_id': 'my-bucket'
        },
        {
            'resource_name': '//compute.googleapis.com/projects/my-project/zones/us-central1-a/instances/my-vm',
            'expected_type': 'compute.googleapis.com/Instance',
            'expected_id': 'my-vm'
        },
        {
            'resource_name': '//iam.googleapis.com/projects/my-project/serviceAccounts/my-sa@my-project.iam.gserviceaccount.com',
            'expected_type': 'iam.googleapis.com/ServiceAccount',
            'expected_id': 'my-sa@my-project.iam.gserviceaccount.com'
        }
    ]
    
    for case in test_cases:
        resource_type, resource_id = normalizer._extract_resource_info(case['resource_name'])
        assert resource_type == case['expected_type']
        assert resource_id == case['expected_id']

@pytest.mark.asyncio
async def test_gcp_firewall_rule():
    """Test GCP firewall open SSH rule"""
    from app.engine.rules.gcp_rules import GCPFirewallOpenSSHRule
    
    rule = GCPFirewallOpenSSHRule()
    
    # Mock event
    event = {
        'cloud_provider': 'gcp',
        'resource_id': 'projects/test-project/global/firewalls/allow-ssh',
        'resource_type': 'compute.googleapis.com/Firewall',
        'event_id': 'test-002',
        'account_id': 'test-project-123',
        'project_id': 'test-project-123',
        'region': 'global',
        'event_time': '2024-01-15T12:00:00Z'
    }
    
    # Mock GCP client
    with patch.object(rule, 'get_gcp_client') as mock_client:
        compute_mock = Mock()
        firewall_mock = Mock()
        
        # Mock firewall with open SSH rule
        firewall_mock.allowed = [
            {
                'IPProtocol': 'tcp',
                'ports': ['22']
            }
        ]
        firewall_mock.source_ranges = ['0.0.0.0/0']
        
        compute_mock.get_firewall.return_value = firewall_mock
        mock_client.return_value = compute_mock
        
        finding = await rule.evaluate(event, {})
        
        assert finding is not None
        assert finding.rule_id == 'GCP-002'
        assert finding.severity == 'HIGH'
        assert finding.cloud_provider == 'gcp'

def test_gcp_normalizer_timestamp_parsing():
    """Test GCP timestamp parsing"""
    normalizer = GCPAuditLogNormalizer()
    
    event = {
        'insertId': 'test-id',
        'timestamp': '2024-01-15T12:00:00.123456789Z',
        'resource': {},
        'protoPayload': {}
    }
    
    normalized = normalizer.normalize_event(event)
    
    # Should parse timestamp correctly
    assert 'event_time' in normalized
    assert normalized['event_time'] == '2024-01-15T12:00:00.123456789Z'

@pytest.mark.asyncio
async def test_gcp_ingestor_error_handling():
    """Test GCP ingestor error handling"""
    ingestor = GCPEventIngestor()
    
    # Mock Pub/Sub client that raises an exception
    with patch('google.cloud.pubsub_v1.SubscriberClient') as mock_client:
        mock_subscriber = Mock()
        mock_client.return_value = mock_subscriber
        mock_subscriber.subscribe.side_effect = Exception("Connection failed")
        
        # Should handle errors gracefully
        try:
            await ingestor.start()
        except Exception:
            # Expected to handle the error
            pass
        
        assert ingestor.running is False
