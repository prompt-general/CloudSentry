import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient
import json
import uuid
from datetime import datetime, timedelta

from app.main import app
from app.models import Finding, Event


class TestAPIEndpoints:
    """Test API endpoints with database integration"""

    @pytest.fixture
    def client(self):
        """Create test client"""
        return TestClient(app)

    @pytest.fixture
    def mock_db_session(self):
        """Mock database session"""
        session = AsyncMock()
        session.execute.return_value = AsyncMock()
        session.add.return_value = None
        session.commit.return_value = None
        session.refresh.return_value = None
        session.query.return_value.filter.return_value.all.return_value = []
        session.query.return_value.filter.return_value.first.return_value = None
        return session

    @pytest.fixture
    def sample_findings(self):
        """Sample findings for testing"""
        return [
            Finding(
                id=uuid.uuid4(),
                rule_id="S3-001",
                resource_id="test-bucket-1",
                resource_type="s3",
                severity="HIGH",
                timestamp=datetime.utcnow(),
                account_id="123456789012",
                region="us-east-1",
                status="OPEN"
            ),
            Finding(
                id=uuid.uuid4(),
                rule_id="IAM-001",
                resource_id="test-user",
                resource_type="iam",
                severity="CRITICAL",
                timestamp=datetime.utcnow(),
                account_id="123456789012",
                region="us-east-1",
                status="OPEN"
            )
        ]

    def test_get_findings_endpoint(self, client, mock_db_session, sample_findings):
        """Test GET /api/v1/findings endpoint"""
        with patch('app.api.rest.get_db') as mock_get_db:
            mock_get_db.return_value = mock_db_session
            mock_db_session.query.return_value.filter.return_value.all.return_value = sample_findings
            
            response = client.get("/api/v1/findings")
            assert response.status_code == 200
            
            data = response.json()
            assert len(data) == 2
            assert data[0]["rule_id"] == "S3-001"
            assert data[1]["rule_id"] == "IAM-001"

    def test_get_findings_with_filters(self, client, mock_db_session, sample_findings):
        """Test GET /api/v1/findings with query parameters"""
        with patch('app.api.rest.get_db') as mock_get_db:
            mock_get_db.return_value = mock_db_session
            mock_db_session.query.return_value.filter.return_value.all.return_value = [sample_findings[0]]
            
            response = client.get("/api/v1/findings?severity=HIGH&status=OPEN")
            assert response.status_code == 200
            
            data = response.json()
            assert len(data) == 1
            assert data[0]["severity"] == "HIGH"

    def test_get_finding_by_id(self, client, mock_db_session, sample_findings):
        """Test GET /api/v1/findings/{finding_id} endpoint"""
        with patch('app.api.rest.get_db') as mock_get_db:
            mock_get_db.return_value = mock_db_session
            mock_db_session.query.return_value.filter.return_value.first.return_value = sample_findings[0]
            
            finding_id = sample_findings[0].id
            response = client.get(f"/api/v1/findings/{finding_id}")
            assert response.status_code == 200
            
            data = response.json()
            assert data["id"] == str(finding_id)
            assert data["rule_id"] == "S3-001"

    def test_get_finding_not_found(self, client, mock_db_session):
        """Test GET /api/v1/findings/{finding_id} for non-existent finding"""
        with patch('app.api.rest.get_db') as mock_get_db:
            mock_get_db.return_value = mock_db_session
            mock_db_session.query.return_value.filter.return_value.first.return_value = None
            
            finding_id = uuid.uuid4()
            response = client.get(f"/api/v1/findings/{finding_id}")
            assert response.status_code == 404

    def test_create_finding(self, client, mock_db_session):
        """Test POST /api/v1/findings endpoint"""
        with patch('app.api.rest.get_db') as mock_get_db:
            mock_get_db.return_value = mock_db_session
            
            finding_data = {
                "rule_id": "S3-001",
                "resource_id": "new-bucket",
                "resource_type": "s3",
                "severity": "HIGH",
                "account_id": "123456789012",
                "region": "us-east-1",
                "remediation_steps": "Remove public access"
            }
            
            response = client.post("/api/v1/findings", json=finding_data)
            assert response.status_code == 201
            
            data = response.json()
            assert data["rule_id"] == "S3-001"
            assert data["resource_id"] == "new-bucket"
            assert "id" in data
            mock_db_session.add.assert_called()
            mock_db_session.commit.assert_called()

    def test_update_finding_status(self, client, mock_db_session, sample_findings):
        """Test PATCH /api/v1/findings/{finding_id}/status endpoint"""
        with patch('app.api.rest.get_db') as mock_get_db:
            mock_get_db.return_value = mock_db_session
            mock_db_session.query.return_value.filter.return_value.first.return_value = sample_findings[0]
            
            finding_id = sample_findings[0].id
            update_data = {"status": "RESOLVED"}
            
            response = client.patch(f"/api/v1/findings/{finding_id}/status", json=update_data)
            assert response.status_code == 200
            
            data = response.json()
            assert data["status"] == "RESOLVED"
            mock_db_session.commit.assert_called()

    def test_get_events_endpoint(self, client, mock_db_session):
        """Test GET /api/v1/events endpoint"""
        with patch('app.api.rest.get_db') as mock_get_db:
            mock_get_db.return_value = mock_db_session
            
            # Mock events
            events = [
                Event(
                    id=uuid.uuid4(),
                    event_id="event-1",
                    event_name="CreateBucket",
                    event_source="s3.amazonaws.com",
                    event_time=datetime.utcnow(),
                    account_id="123456789012",
                    region="us-east-1"
                )
            ]
            
            mock_db_session.query.return_value.filter.return_value.all.return_value = events
            
            response = client.get("/api/v1/events")
            assert response.status_code == 200
            
            data = response.json()
            assert len(data) == 1
            assert data[0]["event_name"] == "CreateBucket"

    def test_get_audit_logs_endpoint(self, client, mock_db_session):
        """Test GET /api/v1/audits endpoint"""
        with patch('app.api.rest.get_db') as mock_get_db:
            mock_get_db.return_value = mock_db_session
            
            # Mock audit logs
            from app.models import AuditLog
            audit_logs = [
                AuditLog(
                    id=uuid.uuid4(),
                    audit_type="security",
                    account_id="123456789012",
                    start_time=datetime.utcnow() - timedelta(hours=1),
                    end_time=datetime.utcnow(),
                    status="COMPLETED",
                    findings_count=5
                )
            ]
            
            mock_db_session.query.return_value.filter.return_value.all.return_value = audit_logs
            
            response = client.get("/api/v1/audits")
            assert response.status_code == 200
            
            data = response.json()
            assert len(data) == 1
            assert data[0]["audit_type"] == "security"
            assert data[0]["status"] == "COMPLETED"

    def test_trigger_audit_endpoint(self, client, mock_db_session):
        """Test POST /api/v1/audits/trigger endpoint"""
        with patch('app.api.rest.get_db') as mock_get_db, \
             patch('app.scheduler.audit_scheduler.AuditScheduler') as mock_scheduler_class:
            
            mock_get_db.return_value = mock_db_session
            
            # Mock scheduler
            mock_scheduler = MagicMock()
            mock_audit_log = MagicMock()
            mock_audit_log.id = uuid.uuid4()
            mock_audit_log.status = "SCHEDULED"
            mock_scheduler.run_security_audit.return_value = mock_audit_log
            mock_scheduler_class.return_value = mock_scheduler
            
            audit_data = {
                "audit_type": "security",
                "accounts": ["123456789012"],
                "regions": ["us-east-1"]
            }
            
            response = client.post("/api/v1/audits/trigger", json=audit_data)
            assert response.status_code == 202
            
            data = response.json()
            assert "audit_id" in data
            assert data["status"] == "SCHEDULED"

    def test_get_statistics_endpoint(self, client, mock_db_session):
        """Test GET /api/v1/statistics endpoint"""
        with patch('app.api.rest.get_db') as mock_get_db:
            mock_get_db.return_value = mock_db_session
            
            # Mock statistics
            mock_db_session.execute.return_value.fetchall.return_value = [
                (100,),  # total_findings
                (25,),   # critical_findings
                (50,),   # high_findings
                (25,),   # medium_findings
                (10,)    # low_findings
            ]
            
            response = client.get("/api/v1/statistics")
            assert response.status_code == 200
            
            data = response.json()
            assert "total_findings" in data
            assert "findings_by_severity" in data
            assert data["total_findings"] == 100

    def test_get_rules_endpoint(self, client, mock_db_session):
        """Test GET /api/v1/rules endpoint"""
        with patch('app.api.rest.get_db') as mock_get_db:
            mock_get_db.return_value = mock_db_session
            
            # Mock rules
            from app.models import RuleMetadata
            rules = [
                RuleMetadata(
                    id="S3-001",
                    description="Public S3 bucket detected",
                    severity="HIGH",
                    resource_types=["s3"],
                    enabled=True
                )
            ]
            
            mock_db_session.query.return_value.all.return_value = rules
            
            response = client.get("/api/v1/rules")
            assert response.status_code == 200
            
            data = response.json()
            assert len(data) == 1
            assert data[0]["id"] == "S3-001"
            assert data[0]["severity"] == "HIGH"

    def test_update_rule_endpoint(self, client, mock_db_session):
        """Test PATCH /api/v1/rules/{rule_id} endpoint"""
        with patch('app.api.rest.get_db') as mock_get_db:
            mock_get_db.return_value = mock_db_session
            
            # Mock existing rule
            from app.models import RuleMetadata
            existing_rule = RuleMetadata(
                id="S3-001",
                description="Public S3 bucket detected",
                severity="HIGH",
                resource_types=["s3"],
                enabled=True
            )
            
            mock_db_session.query.return_value.filter.return_value.first.return_value = existing_rule
            
            update_data = {"enabled": False}
            
            response = client.patch("/api/v1/rules/S3-001", json=update_data)
            assert response.status_code == 200
            
            data = response.json()
            assert data["enabled"] is False
            mock_db_session.commit.assert_called()

    def test_websocket_connection(self, client):
        """Test WebSocket connection establishment"""
        # WebSocket testing requires websocket-client library
        # For now, just verify the endpoint exists
        from app.main import app
        routes = [route.path for route in app.routes]
        assert any("/ws" in route for route in routes)

    def test_api_error_handling(self, client, mock_db_session):
        """Test API error handling"""
        with patch('app.api.rest.get_db') as mock_get_db:
            mock_get_db.return_value = mock_db_session
            mock_db_session.query.return_value.filter.return_value.first.side_effect = Exception("Database error")
            
            response = client.get("/api/v1/findings/123")
            assert response.status_code == 500

    def test_api_validation_error(self, client):
        """Test API validation error handling"""
        # Send invalid data
        invalid_data = {
            "rule_id": "",  # Empty string should fail validation
            "resource_id": "test",
            "resource_type": "s3",
            "severity": "INVALID"  # Invalid severity
        }
        
        response = client.post("/api/v1/findings", json=invalid_data)
        assert response.status_code == 422

    def test_api_rate_limiting(self, client):
        """Test API rate limiting"""
        # This test would require setting up rate limiting middleware
        # For now, just verify the endpoint responds
        for i in range(10):
            response = client.get("/")
            assert response.status_code == 200

    def test_api_authentication(self, client):
        """Test API authentication (if implemented)"""
        # This test would depend on authentication implementation
        # For now, just verify endpoints are accessible
        response = client.get("/api/v1/findings")
        # Should return 200 or 401/403 depending on auth implementation
        assert response.status_code in [200, 401, 403]
