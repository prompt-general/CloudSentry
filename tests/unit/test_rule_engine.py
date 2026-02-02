import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
import tempfile
import os
import json
from datetime import datetime

from app.rule_engine import RuleEngine
from app.models import Finding
import uuid


class TestRuleEngine:
    """Test rule engine functionality"""

    @pytest.fixture
    def rule_engine(self, test_settings):
        """Create rule engine instance"""
        with patch('app.rule_engine.get_settings') as mock_settings:
            mock_settings.return_value = test_settings
            return RuleEngine()

    @pytest.fixture
    def sample_security_rules(self):
        """Sample security rules"""
        return [
            {
                "id": "S3-001",
                "name": "Public S3 Bucket",
                "description": "Detects S3 buckets with public access",
                "severity": "HIGH",
                "resource_type": "s3",
                "conditions": [
                    {
                        "field": "bucket_acl",
                        "operator": "contains",
                        "value": "AllUsers"
                    }
                ],
                "enabled": True
            },
            {
                "id": "IAM-001",
                "name": "Root Account Usage",
                "description": "Detects root account usage",
                "severity": "CRITICAL",
                "resource_type": "iam",
                "conditions": [
                    {
                        "field": "user_type",
                        "operator": "equals",
                        "value": "Root"
                    }
                ],
                "enabled": True
            },
            {
                "id": "EC2-001",
                "name": "Open SSH Access",
                "description": "Detects security groups with open SSH access",
                "severity": "MEDIUM",
                "resource_type": "ec2",
                "conditions": [
                    {
                        "field": "protocol",
                        "operator": "equals",
                        "value": "tcp"
                    },
                    {
                        "field": "port",
                        "operator": "equals",
                        "value": 22
                    },
                    {
                        "field": "cidr",
                        "operator": "equals",
                        "value": "0.0.0.0/0"
                    }
                ],
                "enabled": True
            }
        ]

    @pytest.mark.asyncio
    async def test_process_event_s3_public_bucket(self, rule_engine, sample_cloudtrail_event, sample_security_rules):
        """Test processing S3 event that creates public bucket"""
        # Mock rule loading
        with patch.object(rule_engine, '_load_rules', return_value=sample_security_rules), \
             patch.object(rule_engine, '_evaluate_s3_rule') as mock_evaluate:
            
            mock_evaluate.return_value = Finding(
                id=uuid.uuid4(),
                rule_id="S3-001",
                resource_id="test-bucket-123",
                resource_type="s3",
                severity="HIGH",
                event_id=sample_cloudtrail_event["eventID"],
                timestamp=datetime.utcnow()
            )
            
            findings = await rule_engine.process_event(sample_cloudtrail_event)
            
            assert len(findings) == 1
            assert findings[0].rule_id == "S3-001"
            assert findings[0].resource_id == "test-bucket-123"
            mock_evaluate.assert_called_once()

    @pytest.mark.asyncio
    async def test_process_event_root_account_usage(self, rule_engine, sample_security_rules):
        """Test processing IAM event with root account usage"""
        root_event = {
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
            "eventID": "12345678-1234-1234-1234-123456789012",
            "eventType": "AwsApiCall",
            "managementEvent": True
        }
        
        with patch.object(rule_engine, '_load_rules', return_value=sample_security_rules), \
             patch.object(rule_engine, '_evaluate_iam_rule') as mock_evaluate:
            
            mock_evaluate.return_value = Finding(
                id=uuid.uuid4(),
                rule_id="IAM-001",
                resource_id="root-account",
                resource_type="iam",
                severity="CRITICAL",
                event_id=root_event["eventID"],
                timestamp=datetime.utcnow()
            )
            
            findings = await rule_engine.process_event(root_event)
            
            assert len(findings) == 1
            assert findings[0].rule_id == "IAM-001"
            assert findings[0].severity == "CRITICAL"

    @pytest.mark.asyncio
    async def test_process_event_no_findings(self, rule_engine, sample_cloudtrail_event, sample_security_rules):
        """Test processing event that generates no findings"""
        with patch.object(rule_engine, '_load_rules', return_value=sample_security_rules), \
             patch.object(rule_engine, '_evaluate_s3_rule') as mock_evaluate:
            
            mock_evaluate.return_value = []  # No findings
            
            findings = await rule_engine.process_event(sample_cloudtrail_event)
            
            assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_process_event_multiple_findings(self, rule_engine, sample_cloudtrail_event, sample_security_rules):
        """Test processing event that generates multiple findings"""
        with patch.object(rule_engine, '_load_rules', return_value=sample_security_rules), \
             patch.object(rule_engine, '_evaluate_s3_rule') as mock_evaluate:
            
            mock_evaluate.return_value = [
                Finding(
                    id=uuid.uuid4(),
                    rule_id="S3-001",
                    resource_id="test-bucket-123",
                    resource_type="s3",
                    severity="HIGH",
                    event_id=sample_cloudtrail_event["eventID"],
                    timestamp=datetime.utcnow()
                ),
                Finding(
                    id=uuid.uuid4(),
                    rule_id="S3-002",
                    resource_id="test-bucket-123",
                    resource_type="s3",
                    severity="MEDIUM",
                    event_id=sample_cloudtrail_event["eventID"],
                    timestamp=datetime.utcnow()
                )
            ]
            
            findings = await rule_engine.process_event(sample_cloudtrail_event)
            
            assert len(findings) == 2
            assert findings[0].rule_id == "S3-001"
            assert findings[1].rule_id == "S3-002"

    @pytest.mark.asyncio
    async def test_evaluate_s3_rule_public_bucket(self, rule_engine):
        """Test S3 rule evaluation for public bucket"""
        mock_session = MagicMock()
        mock_s3_client = MagicMock()
        mock_s3_client.get_bucket_acl.return_value = {
            'Grants': [
                {
                    'Grantee': {'Type': 'AllUsers'},
                    'Permission': 'READ'
                }
            ]
        }
        mock_session.client.return_value = mock_s3_client
        
        event = {
            "eventSource": "s3.amazonaws.com",
            "eventName": "CreateBucket",
            "requestParameters": {"bucketName": "test-bucket"},
            "awsRegion": "us-east-1",
            "userIdentity": {"accountId": "123456789012"}
        }
        
        rule = {
            "id": "S3-001",
            "conditions": [
                {"field": "bucket_acl", "operator": "contains", "value": "AllUsers"}
            ]
        }
        
        findings = await rule_engine._evaluate_s3_rule(mock_session, event, rule)
        
        assert len(findings) == 1
        assert findings[0].rule_id == "S3-001"
        assert findings[0].resource_id == "test-bucket"

    @pytest.mark.asyncio
    async def test_evaluate_s3_rule_private_bucket(self, rule_engine):
        """Test S3 rule evaluation for private bucket"""
        mock_session = MagicMock()
        mock_s3_client = MagicMock()
        mock_s3_client.get_bucket_acl.return_value = {
            'Grants': [
                {
                    'Grantee': {'Type': 'CanonicalUser', 'DisplayName': 'test-user'},
                    'Permission': 'FULL_CONTROL'
                }
            ]
        }
        mock_session.client.return_value = mock_s3_client
        
        event = {
            "eventSource": "s3.amazonaws.com",
            "eventName": "CreateBucket",
            "requestParameters": {"bucketName": "private-bucket"},
            "awsRegion": "us-east-1",
            "userIdentity": {"accountId": "123456789012"}
        }
        
        rule = {
            "id": "S3-001",
            "conditions": [
                {"field": "bucket_acl", "operator": "contains", "value": "AllUsers"}
            ]
        }
        
        findings = await rule_engine._evaluate_s3_rule(mock_session, event, rule)
        
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_evaluate_iam_rule_root_usage(self, rule_engine):
        """Test IAM rule evaluation for root account usage"""
        mock_session = MagicMock()
        
        event = {
            "eventSource": "iam.amazonaws.com",
            "eventName": "CreateUser",
            "userIdentity": {
                "type": "Root",
                "accountId": "123456789012"
            }
        }
        
        rule = {
            "id": "IAM-001",
            "conditions": [
                {"field": "user_type", "operator": "equals", "value": "Root"}
            ]
        }
        
        findings = await rule_engine._evaluate_iam_rule(mock_session, event, rule)
        
        assert len(findings) == 1
        assert findings[0].rule_id == "IAM-001"
        assert findings[0].severity == "CRITICAL"

    @pytest.mark.asyncio
    async def test_evaluate_ec2_rule_open_ssh(self, rule_engine):
        """Test EC2 rule evaluation for open SSH access"""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_ec2_client.describe_security_groups.return_value = {
            'SecurityGroups': [
                {
                    'GroupId': 'sg-12345678',
                    'GroupName': 'test-sg',
                    'IpPermissions': [
                        {
                            'IpProtocol': 'tcp',
                            'FromPort': 22,
                            'ToPort': 22,
                            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                        }
                    ]
                }
            ]
        }
        mock_session.client.return_value = mock_ec2_client
        
        event = {
            "eventSource": "ec2.amazonaws.com",
            "eventName": "AuthorizeSecurityGroupIngress",
            "requestParameters": {
                "groupId": "sg-12345678"
            },
            "awsRegion": "us-east-1",
            "userIdentity": {"accountId": "123456789012"}
        }
        
        rule = {
            "id": "EC2-001",
            "conditions": [
                {"field": "protocol", "operator": "equals", "value": "tcp"},
                {"field": "port", "operator": "equals", "value": 22},
                {"field": "cidr", "operator": "equals", "value": "0.0.0.0/0"}
            ]
        }
        
        findings = await rule_engine._evaluate_ec2_rule(mock_session, event, rule)
        
        assert len(findings) == 1
        assert findings[0].rule_id == "EC2-001"
        assert findings[0].resource_id == "sg-12345678"

    @pytest.mark.asyncio
    async def test_load_rules_from_database(self, rule_engine, mock_db_session):
        """Test loading rules from database"""
        # Mock database rules
        from app.models import RuleMetadata
        mock_rules = [
            RuleMetadata(
                id="S3-001",
                description="Public S3 bucket",
                severity="HIGH",
                resource_types=["s3"],
                enabled=True
            )
        ]
        
        mock_db_session.query.return_value.all.return_value = mock_rules
        
        with patch('app.rule_engine.AsyncSessionLocal') as mock_session_local:
            mock_session_local.return_value.__aenter__.return_value = mock_db_session
            
            rules = await rule_engine._load_rules()
            
            assert len(rules) == 1
            assert rules[0]["id"] == "S3-001"

    @pytest.mark.asyncio
    async def test_load_rules_from_file(self, rule_engine):
        """Test loading rules from configuration file"""
        # Create temporary rules file
        rules_data = [
            {
                "id": "S3-001",
                "name": "Public S3 Bucket",
                "description": "Detects public S3 buckets",
                "severity": "HIGH",
                "resource_type": "s3",
                "conditions": [
                    {"field": "bucket_acl", "operator": "contains", "value": "AllUsers"}
                ],
                "enabled": True
            }
        ]
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(rules_data, f)
            temp_file = f.name
        
        try:
            with patch.object(rule_engine, '_get_rules_file_path', return_value=temp_file):
                rules = await rule_engine._load_rules()
                
                assert len(rules) == 1
                assert rules[0]["id"] == "S3-001"
        finally:
            os.unlink(temp_file)

    @pytest.mark.asyncio
    async def test_condition_evaluation(self, rule_engine):
        """Test individual condition evaluation"""
        # Test equals condition
        condition = {"field": "severity", "operator": "equals", "value": "HIGH"}
        data = {"severity": "HIGH"}
        assert rule_engine._evaluate_condition(condition, data) is True
        
        # Test contains condition
        condition = {"field": "permissions", "operator": "contains", "value": "READ"}
        data = {"permissions": ["READ", "WRITE"]}
        assert rule_engine._evaluate_condition(condition, data) is True
        
        # Test in condition
        condition = {"field": "status", "operator": "in", "value": ["ACTIVE", "ENABLED"]}
        data = {"status": "ACTIVE"}
        assert rule_engine._evaluate_condition(condition, data) is True
        
        # Test greater_than condition
        condition = {"field": "count", "operator": "greater_than", "value": 5}
        data = {"count": 10}
        assert rule_engine._evaluate_condition(condition, data) is True
        
        # Test failed condition
        condition = {"field": "severity", "operator": "equals", "value": "LOW"}
        data = {"severity": "HIGH"}
        assert rule_engine._evaluate_condition(condition, data) is False

    @pytest.mark.asyncio
    async def test_rule_engine_error_handling(self, rule_engine, sample_cloudtrail_event):
        """Test rule engine error handling"""
        with patch.object(rule_engine, '_load_rules', side_effect=Exception("Failed to load rules")):
            findings = await rule_engine.process_event(sample_cloudtrail_event)
            
            # Should return empty list on error
            assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_rule_engine_caching(self, rule_engine, sample_security_rules):
        """Test rule engine caching functionality"""
        with patch.object(rule_engine, '_load_rules') as mock_load:
            mock_load.return_value = sample_security_rules
            
            # First call should load rules
            rules1 = await rule_engine._load_rules()
            
            # Second call should use cache
            rules2 = await rule_engine._load_rules()
            
            # Should only call load_rules once due to caching
            mock_load.assert_called_once()
            assert rules1 == rules2

    @pytest.mark.asyncio
    async def test_rule_engine_cache_invalidation(self, rule_engine, sample_security_rules):
        """Test rule engine cache invalidation"""
        with patch.object(rule_engine, '_load_rules') as mock_load:
            mock_load.return_value = sample_security_rules
            
            # Load rules
            await rule_engine._load_rules()
            
            # Invalidate cache
            rule_engine._rules_cache.clear()
            
            # Load rules again
            await rule_engine._load_rules()
            
            # Should call load_rules twice
            assert mock_load.call_count == 2

    @pytest.mark.asyncio
    async def test_get_rule_statistics(self, rule_engine, sample_security_rules):
        """Test getting rule engine statistics"""
        with patch.object(rule_engine, '_load_rules', return_value=sample_security_rules):
            stats = rule_engine.get_statistics()
            
            assert stats['total_rules'] == 3
            assert stats['enabled_rules'] == 3
            assert stats['rules_by_resource_type'] == {
                's3': 1,
                'iam': 1,
                'ec2': 1
            }
            assert stats['rules_by_severity'] == {
                'HIGH': 1,
                'CRITICAL': 1,
                'MEDIUM': 1
            }
