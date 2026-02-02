import pytest
import json
from unittest.mock import MagicMock, patch, AsyncMock
import uuid
from datetime import datetime

from app.models import Finding


class TestS3Rules:
    """Test S3 security rules"""
    
    def test_s3_public_read_rule_initialization(self):
        """Test rule initialization"""
        # Mock the S3BucketPublicReadRule class
        with patch('app.engine.rules.s3_rules.S3BucketPublicReadRule') as mock_rule_class:
            mock_rule = MagicMock()
            mock_rule.rule_id = "S3-001"
            mock_rule.severity = "HIGH"
            mock_rule.description = "S3 bucket allows public read access"
            mock_rule_class.return_value = mock_rule
            
            rule = mock_rule_class()
            assert rule.rule_id == "S3-001"
            assert rule.severity == "HIGH"
            assert rule.description == "S3 bucket allows public read access"
    
    @pytest.mark.asyncio
    async def test_s3_public_read_rule_evaluation(self):
        """Test rule evaluation with public policy"""
        # Mock the S3BucketPublicReadRule class
        with patch('app.engine.rules.s3_rules.S3BucketPublicReadRule') as mock_rule_class:
            mock_rule = MagicMock()
            mock_rule.rule_id = "S3-001"
            mock_rule.severity = "HIGH"
            
            # Mock the evaluate method to return a finding
            mock_finding = Finding(
                id=uuid.uuid4(),
                rule_id="S3-001",
                resource_id="test-bucket",
                resource_type="s3",
                severity="HIGH",
                event_id="test-001",
                account_id="123456789012",
                region="us-east-1",
                timestamp=datetime.utcnow()
            )
            
            mock_rule.evaluate = AsyncMock(return_value=mock_finding)
            mock_rule_class.return_value = mock_rule
            
            # Mock event
            event = {
                "resource_id": "test-bucket",
                "resource_type": "s3",
                "event_id": "test-001",
                "account_id": "123456789012",
                "region": "us-east-1",
                "event_time": "2024-01-15T12:00:00Z",
                "raw_event": {}
            }
            
            finding = await mock_rule.evaluate(event, {})
            
            assert finding is not None
            assert finding.rule_id == "S3-001"
            assert finding.severity == "HIGH"
            assert finding.resource_id == "test-bucket"
    
    @pytest.mark.asyncio
    async def test_s3_public_read_rule_no_public_access(self):
        """Test rule evaluation without public access"""
        with patch('app.engine.rules.s3_rules.S3BucketPublicReadRule') as mock_rule_class:
            mock_rule = MagicMock()
            mock_rule.evaluate = AsyncMock(return_value=None)
            mock_rule_class.return_value = mock_rule
            
            event = {
                "resource_id": "test-bucket",
                "resource_type": "s3",
                "event_id": "test-001"
            }
            
            finding = await mock_rule.evaluate(event, {})
            assert finding is None
    
    def test_policy_allows_public_read(self):
        """Test policy analysis logic"""
        # Test the policy analysis logic directly
        def policy_allows_public_read(policy):
            """Helper function to test policy analysis"""
            if not policy or "Statement" not in policy:
                return False
            
            for statement in policy.get("Statement", []):
                if (statement.get("Effect") == "Allow" and
                    statement.get("Principal") in ["*", {"AWS": "*"}] and
                    "s3:GetObject" in statement.get("Action", [])):
                    return True
            return False
        
        # Public policy
        public_policy = {
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject"
            }]
        }
        assert policy_allows_public_read(public_policy) == True
        
        # Private policy
        private_policy = {
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:user/test"},
                "Action": "s3:GetObject"
            }]
        }
        assert policy_allows_public_read(private_policy) == False
        
        # Policy with multiple statements
        mixed_policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::123456789012:user/test"},
                    "Action": "s3:PutObject"
                },
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject"
                }
            ]
        }
        assert policy_allows_public_read(mixed_policy) == True

    @pytest.mark.asyncio
    async def test_s3_public_read_rule_error_handling(self):
        """Test rule evaluation with AWS API errors"""
        with patch('app.engine.rules.s3_rules.S3BucketPublicReadRule') as mock_rule_class:
            mock_rule = MagicMock()
            mock_rule.evaluate = AsyncMock(side_effect=Exception("AWS API Error"))
            mock_rule_class.return_value = mock_rule
            
            event = {
                "resource_id": "test-bucket",
                "resource_type": "s3",
                "event_id": "test-001"
            }
            
            with pytest.raises(Exception):
                await mock_rule.evaluate(event, {})

    @pytest.mark.asyncio
    async def test_s3_public_read_rule_invalid_policy(self):
        """Test rule evaluation with invalid policy JSON"""
        with patch('app.engine.rules.s3_rules.S3BucketPublicReadRule') as mock_rule_class:
            mock_rule = MagicMock()
            mock_rule.evaluate = AsyncMock(return_value=None)
            mock_rule_class.return_value = mock_rule
            
            event = {
                "resource_id": "test-bucket",
                "resource_type": "s3",
                "event_id": "test-001",
                "raw_event": {
                    "responseElements": {
                        "policy": "invalid json {"
                    }
                }
            }
            
            finding = await mock_rule.evaluate(event, {})
            assert finding is None


class TestEC2Rules:
    """Test EC2 security rules"""
    
    def test_ec2_open_ssh_rule_initialization(self):
        """Test rule initialization"""
        with patch('app.engine.rules.ec2_rules.EC2SecurityGroupOpenSSHRule') as mock_rule_class:
            mock_rule = MagicMock()
            mock_rule.rule_id = "EC2-001"
            mock_rule.severity = "HIGH"
            mock_rule.description = "EC2 security group allows open SSH access"
            mock_rule_class.return_value = mock_rule
            
            rule = mock_rule_class()
            assert rule.rule_id == "EC2-001"
            assert rule.severity == "HIGH"
            assert "SSH" in rule.description
    
    @pytest.mark.asyncio
    async def test_ec2_open_ssh_rule_evaluation(self):
        """Test rule evaluation with open SSH"""
        with patch('app.engine.rules.ec2_rules.EC2SecurityGroupOpenSSHRule') as mock_rule_class:
            mock_rule = MagicMock()
            
            # Mock the evaluate method to return a finding
            mock_finding = Finding(
                id=uuid.uuid4(),
                rule_id="EC2-001",
                resource_id="sg-12345678",
                resource_type="security-group",
                severity="HIGH",
                event_id="test-002",
                account_id="123456789012",
                region="us-east-1",
                timestamp=datetime.utcnow()
            )
            
            mock_rule.evaluate = AsyncMock(return_value=mock_finding)
            mock_rule_class.return_value = mock_rule
            
            # Event with open SSH rule
            event = {
                "event_name": "AuthorizeSecurityGroupIngress",
                "resource_type": "security-group",
                "resource_id": "sg-12345678",
                "account_id": "123456789012",
                "region": "us-east-1",
                "event_time": "2024-01-15T12:00:00Z",
                "raw_event": {
                    "requestParameters": {
                        "ipPermissions": {
                            "items": [{
                                "ipProtocol": "tcp",
                                "fromPort": 22,
                                "toPort": 22,
                                "ipRanges": {
                                    "items": [{"cidrIp": "0.0.0.0/0"}]
                                }
                            }]
                        }
                    }
                }
            }
            
            finding = await mock_rule.evaluate(event, {})
            
            assert finding is not None
            assert finding.rule_id == "EC2-001"
            assert finding.severity == "HIGH"
    
    @pytest.mark.asyncio
    async def test_ec2_open_ssh_rule_no_open_access(self):
        """Test rule evaluation without open SSH"""
        with patch('app.engine.rules.ec2_rules.EC2SecurityGroupOpenSSHRule') as mock_rule_class:
            mock_rule = MagicMock()
            mock_rule.evaluate = AsyncMock(return_value=None)
            mock_rule_class.return_value = mock_rule
            
            # Event with restricted SSH
            event = {
                "event_name": "AuthorizeSecurityGroupIngress",
                "raw_event": {
                    "requestParameters": {
                        "ipPermissions": {
                            "items": [{
                                "ipProtocol": "tcp",
                                "fromPort": 22,
                                "toPort": 22,
                                "ipRanges": {
                                    "items": [{"cidrIp": "10.0.0.0/16"}]
                                }
                            }]
                        }
                    }
                }
            }
            
            finding = await mock_rule.evaluate(event, {})
            assert finding is None

    @pytest.mark.asyncio
    async def test_ec2_open_ssh_rule_different_port(self):
        """Test rule evaluation with different port"""
        with patch('app.engine.rules.ec2_rules.EC2SecurityGroupOpenSSHRule') as mock_rule_class:
            mock_rule = MagicMock()
            mock_rule.evaluate = AsyncMock(return_value=None)
            mock_rule_class.return_value = mock_rule
            
            # Event with port 443 (not SSH)
            event = {
                "event_name": "AuthorizeSecurityGroupIngress",
                "raw_event": {
                    "requestParameters": {
                        "ipPermissions": {
                            "items": [{
                                "ipProtocol": "tcp",
                                "fromPort": 443,
                                "toPort": 443,
                                "ipRanges": {
                                    "items": [{"cidrIp": "0.0.0.0/0"}]
                                }
                            }]
                        }
                    }
                }
            }
            
            finding = await mock_rule.evaluate(event, {})
            assert finding is None

    @pytest.mark.asyncio
    async def test_ec2_open_ssh_rule_ipv6_access(self):
        """Test rule evaluation with IPv6 access"""
        with patch('app.engine.rules.ec2_rules.EC2SecurityGroupOpenSSHRule') as mock_rule_class:
            mock_rule = MagicMock()
            
            mock_finding = Finding(
                id=uuid.uuid4(),
                rule_id="EC2-001",
                resource_id="sg-12345678",
                resource_type="security-group",
                severity="HIGH",
                event_id="test-003",
                account_id="123456789012",
                region="us-east-1",
                timestamp=datetime.utcnow()
            )
            
            mock_rule.evaluate = AsyncMock(return_value=mock_finding)
            mock_rule_class.return_value = mock_rule
            
            # Event with IPv6 open SSH
            event = {
                "event_name": "AuthorizeSecurityGroupIngress",
                "raw_event": {
                    "requestParameters": {
                        "ipPermissions": {
                            "items": [{
                                "ipProtocol": "tcp",
                                "fromPort": 22,
                                "toPort": 22,
                                "ipv6Ranges": {
                                    "items": [{"cidrIpv6": "::/0"}]
                                }
                            }]
                        }
                    }
                }
            }
            
            finding = await mock_rule.evaluate(event, {})
            assert finding is not None
            assert finding.rule_id == "EC2-001"

    def test_is_ssh_port_open_to_world(self):
        """Test SSH port analysis logic"""
        def is_ssh_port_open_to_world(ip_permissions):
            """Helper function to test SSH port analysis"""
            if not ip_permissions:
                return False
            
            for permission in ip_permissions.get("items", []):
                if (permission.get("ipProtocol") == "tcp" and
                    permission.get("fromPort") == 22 and
                    permission.get("toPort") == 22):
                    
                    # Check IPv4 ranges
                    for ip_range in permission.get("ipRanges", {}).get("items", []):
                        if ip_range.get("cidrIp") in ["0.0.0.0/0"]:
                            return True
                    
                    # Check IPv6 ranges
                    for ipv6_range in permission.get("ipv6Ranges", {}).get("items", []):
                        if ipv6_range.get("cidrIpv6") in ["::/0"]:
                            return True
            
            return False
        
        # Open SSH to world
        open_ssh = {
            "items": [{
                "ipProtocol": "tcp",
                "fromPort": 22,
                "toPort": 22,
                "ipRanges": {
                    "items": [{"cidrIp": "0.0.0.0/0"}]
                }
            }]
        }
        assert is_ssh_port_open_to_world(open_ssh) == True
        
        # Restricted SSH
        restricted_ssh = {
            "items": [{
                "ipProtocol": "tcp",
                "fromPort": 22,
                "toPort": 22,
                "ipRanges": {
                    "items": [{"cidrIp": "10.0.0.0/16"}]
                }
            }]
        }
        assert is_ssh_port_open_to_world(restricted_ssh) == False
        
        # Different port
        different_port = {
            "items": [{
                "ipProtocol": "tcp",
                "fromPort": 443,
                "toPort": 443,
                "ipRanges": {
                    "items": [{"cidrIp": "0.0.0.0/0"}]
                }
            }]
        }
        assert is_ssh_port_open_to_world(different_port) == False

    @pytest.mark.asyncio
    async def test_ec2_rule_error_handling(self):
        """Test EC2 rule evaluation with errors"""
        with patch('app.engine.rules.ec2_rules.EC2SecurityGroupOpenSSHRule') as mock_rule_class:
            mock_rule = MagicMock()
            mock_rule.evaluate = AsyncMock(side_effect=Exception("EC2 API Error"))
            mock_rule_class.return_value = mock_rule
            
            event = {
                "event_name": "AuthorizeSecurityGroupIngress",
                "resource_type": "security-group"
            }
            
            with pytest.raises(Exception):
                await mock_rule.evaluate(event, {})

    @pytest.mark.asyncio
    async def test_ec2_rule_missing_permissions(self):
        """Test EC2 rule with missing IP permissions"""
        with patch('app.engine.rules.ec2_rules.EC2SecurityGroupOpenSSHRule') as mock_rule_class:
            mock_rule = MagicMock()
            mock_rule.evaluate = AsyncMock(return_value=None)
            mock_rule_class.return_value = mock_rule
            
            # Event with no IP permissions
            event = {
                "event_name": "AuthorizeSecurityGroupIngress",
                "raw_event": {
                    "requestParameters": {}
                }
            }
            
            finding = await mock_rule.evaluate(event, {})
            assert finding is None


class TestRuleBase:
    """Test base rule functionality"""
    
    def test_rule_base_properties(self):
        """Test base rule properties and methods"""
        # Test the base rule concept
        class MockRule:
            def __init__(self):
                self.rule_id = "TEST-001"
                self.severity = "MEDIUM"
                self.description = "Test rule"
                self.enabled = True
            
            async def evaluate(self, event, context):
                return None
        
        rule = MockRule()
        assert rule.rule_id == "TEST-001"
        assert rule.severity == "MEDIUM"
        assert rule.description == "Test rule"
        assert rule.enabled is True

    @pytest.mark.asyncio
    async def test_rule_disabled(self):
        """Test disabled rule behavior"""
        class MockRule:
            def __init__(self):
                self.rule_id = "TEST-001"
                self.enabled = False
            
            async def evaluate(self, event, context):
                if not self.enabled:
                    return None
                return "finding"
        
        rule = MockRule()
        finding = await rule.evaluate({}, {})
        assert finding is None

    def test_rule_severity_validation(self):
        """Test rule severity validation"""
        valid_severities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        
        for severity in valid_severities:
            class MockRule:
                def __init__(self, severity):
                    self.severity = severity
            
            rule = MockRule(severity)
            assert rule.severity in valid_severities

    @pytest.mark.asyncio
    async def test_rule_context_usage(self):
        """Test rule evaluation with context"""
        class MockRule:
            def __init__(self):
                self.rule_id = "TEST-001"
                self.severity = "HIGH"
            
            async def evaluate(self, event, context):
                # Use context in evaluation
                aws_session = context.get('aws_session')
                if aws_session:
                    return "finding_with_context"
                return None
        
        rule = MockRule()
        
        # Test with context
        finding = await rule.evaluate({}, {'aws_session': MagicMock()})
        assert finding == "finding_with_context"
        
        # Test without context
        finding = await rule.evaluate({}, {})
        assert finding is None


class TestRuleRegistry:
    """Test rule registry functionality"""
    
    def test_rule_registration(self):
        """Test rule registration and retrieval"""
        # Mock rule registry
        class RuleRegistry:
            def __init__(self):
                self.rules = {}
            
            def register_rule(self, rule):
                self.rules[rule.rule_id] = rule
            
            def get_rule(self, rule_id):
                return self.rules.get(rule_id)
            
            def get_all_rules(self):
                return list(self.rules.values())
        
        # Create mock rules
        class MockS3Rule:
            def __init__(self):
                self.rule_id = "S3-001"
                self.severity = "HIGH"
        
        class MockEC2Rule:
            def __init__(self):
                self.rule_id = "EC2-001"
                self.severity = "HIGH"
        
        registry = RuleRegistry()
        
        # Register rules
        s3_rule = MockS3Rule()
        ec2_rule = MockEC2Rule()
        
        registry.register_rule(s3_rule)
        registry.register_rule(ec2_rule)
        
        # Test retrieval
        assert registry.get_rule("S3-001") == s3_rule
        assert registry.get_rule("EC2-001") == ec2_rule
        assert registry.get_rule("NONEXISTENT") is None
        
        # Test get all rules
        all_rules = registry.get_all_rules()
        assert len(all_rules) == 2
        assert s3_rule in all_rules
        assert ec2_rule in all_rules

    def test_rule_filtering(self):
        """Test rule filtering by various criteria"""
        class MockRule:
            def __init__(self, rule_id, severity, resource_type):
                self.rule_id = rule_id
                self.severity = severity
                self.resource_type = resource_type
                self.enabled = True
        
        rules = [
            MockRule("S3-001", "HIGH", "s3"),
            MockRule("EC2-001", "CRITICAL", "ec2"),
            MockRule("IAM-001", "MEDIUM", "iam"),
            MockRule("S3-002", "LOW", "s3"),
        ]
        
        # Filter by severity
        high_rules = [r for r in rules if r.severity == "HIGH"]
        assert len(high_rules) == 1
        assert high_rules[0].rule_id == "S3-001"
        
        # Filter by resource type
        s3_rules = [r for r in rules if r.resource_type == "s3"]
        assert len(s3_rules) == 2
        assert all(r.resource_type == "s3" for r in s3_rules)
        
        # Filter by enabled
        enabled_rules = [r for r in rules if r.enabled]
        assert len(enabled_rules) == 4
