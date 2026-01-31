import pytest
from unittest.mock import Mock, patch, AsyncMock
from app.engine.rule_engine import RuleEngine
from app.engine.rules.s3_rules import S3BucketPublicReadRule

@pytest.fixture
def rule_engine():
    return RuleEngine()

@pytest.fixture
def sample_event():
    return {
        'event_id': 'test-001',
        'event_name': 'PutBucketPolicy',
        'event_source': 's3.amazonaws.com',
        'resource_id': 'test-bucket',
        'resource_type': 's3',
        'account_id': '123456789012',
        'region': 'us-east-1',
        'raw_event': {}
    }

def test_rule_engine_initialization(rule_engine):
    """Test rule engine loads rules properly"""
    assert len(rule_engine.rules) > 0
    assert any('S3' in rule.rule_id for rule in rule_engine.rules)

def test_is_rule_applicable(rule_engine, sample_event):
    """Test rule applicability checking"""
    s3_rule = next(rule for rule in rule_engine.rules if 'S3' in rule.rule_id)
    
    # S3 rule should apply to S3 event
    applicable = rule_engine._is_rule_applicable(s3_rule, sample_event)
    assert applicable == True
    
    # Non-S3 event
    non_s3_event = sample_event.copy()
    non_s3_event['resource_type'] = 'ec2'
    applicable = rule_engine._is_rule_applicable(s3_rule, non_s3_event)
    assert applicable == False

@pytest.mark.asyncio
async def test_s3_public_read_rule():
    """Test S3 public read rule evaluation"""
    rule = S3BucketPublicReadRule()
    
    # Mock event
    event = {
        'resource_id': 'test-bucket',
        'resource_type': 's3',
        'event_id': 'test-001',
        'account_id': '123456789012',
        'region': 'us-east-1',
        'event_time': '2024-01-15T12:00:00Z'
    }
    
    # Mock S3 client response
    with patch.object(rule, 's3_client') as mock_client:
        # Test with public policy
        mock_client.get_bucket_policy.return_value = {
            'Policy': '{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject"}]}'
        }
        
        finding = await rule.evaluate(event, {})
        assert finding is not None
        assert finding.rule_id == 'S3-001'
        assert finding.severity == 'HIGH'
        
        # Test without public policy
        mock_client.get_bucket_policy.side_effect = Exception('NoSuchBucketPolicy')
        finding = await rule.evaluate(event, {})
        assert finding is None
