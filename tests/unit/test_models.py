import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime
import uuid

from app.models import Finding, Event, RuleMetadata, AuditLog


class TestModels:
    """Test database models"""

    def test_finding_model_creation(self):
        """Test Finding model creation and attributes"""
        finding_id = uuid.uuid4()
        finding = Finding(
            id=finding_id,
            rule_id="S3-001",
            resource_id="test-bucket-123",
            resource_type="s3",
            severity="HIGH",
            event_id="event-123",
            timestamp=datetime.utcnow(),
            remediation_steps="Remove public access",
            account_id="123456789012",
            region="us-east-1",
            status="OPEN"
        )
        
        assert finding.id == finding_id
        assert finding.rule_id == "S3-001"
        assert finding.resource_id == "test-bucket-123"
        assert finding.resource_type == "s3"
        assert finding.severity == "HIGH"
        assert finding.event_id == "event-123"
        assert finding.status == "OPEN"
        assert finding.account_id == "123456789012"
        assert finding.region == "us-east-1"

    def test_finding_to_dict(self):
        """Test Finding model to_dict method"""
        finding_id = uuid.uuid4()
        test_time = datetime.utcnow()
        
        finding = Finding(
            id=finding_id,
            rule_id="S3-001",
            resource_id="test-bucket-123",
            resource_type="s3",
            severity="HIGH",
            timestamp=test_time,
            account_id="123456789012",
            region="us-east-1"
        )
        
        result = finding.to_dict()
        
        assert result['id'] == str(finding_id)
        assert result['rule_id'] == "S3-001"
        assert result['resource_id'] == "test-bucket-123"
        assert result['resource_type'] == "s3"
        assert result['severity'] == "HIGH"
        assert result['account_id'] == "123456789012"
        assert result['region'] == "us-east-1"
        assert result['timestamp'] == test_time.isoformat()

    def test_event_model_creation(self):
        """Test Event model creation"""
        event_id = uuid.uuid4()
        event_time = datetime.utcnow()
        
        event = Event(
            id=event_id,
            event_id="cloudtrail-event-123",
            event_name="CreateBucket",
            event_source="s3.amazonaws.com",
            event_time=event_time,
            resource_id="test-bucket",
            resource_type="s3",
            account_id="123456789012",
            region="us-east-1",
            raw_event={"key": "value"}
        )
        
        assert event.id == event_id
        assert event.event_id == "cloudtrail-event-123"
        assert event.event_name == "CreateBucket"
        assert event.event_source == "s3.amazonaws.com"
        assert event.event_time == event_time
        assert event.resource_id == "test-bucket"
        assert event.resource_type == "s3"
        assert event.account_id == "123456789012"
        assert event.region == "us-east-1"
        assert event.raw_event == {"key": "value"}

    def test_rule_metadata_model_creation(self):
        """Test RuleMetadata model creation"""
        rule = RuleMetadata(
            id="S3-001",
            description="Public S3 bucket detected",
            severity="HIGH",
            resource_types=["s3"],
            enabled=True
        )
        
        assert rule.id == "S3-001"
        assert rule.description == "Public S3 bucket detected"
        assert rule.severity == "HIGH"
        assert rule.resource_types == ["s3"]
        assert rule.enabled is True

    def test_audit_log_model_creation(self):
        """Test AuditLog model creation"""
        start_time = datetime.utcnow()
        audit_log = AuditLog(
            audit_type="security",
            account_id="123456789012",
            start_time=start_time,
            status="IN_PROGRESS",
            findings_count=5
        )
        
        assert audit_log.audit_type == "security"
        assert audit_log.account_id == "123456789012"
        assert audit_log.start_time == start_time
        assert audit_log.status == "IN_PROGRESS"
        assert audit_log.findings_count == 5
