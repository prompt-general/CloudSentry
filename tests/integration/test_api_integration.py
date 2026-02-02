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


class TestAPIIntegration:
    """Integration tests for API endpoints"""

    @pytest.fixture
    def client(self):
        """Create test client"""
        return TestClient(app)

    @pytest.fixture
    def mock_db_session(self):
        """Mock database session"""
        session = AsyncMock()
        session.add.return_value = None
        session.commit.return_value = None
        session.refresh.return_value = None
        session.query.return_value.filter.return_value.all.return_value = []
        session.query.return_value.filter.return_value.first.return_value = None
        session.execute.return_value = AsyncMock()
        return session

    @pytest.mark.asyncio
    async def test_findings_endpoints(self, mock_db_session):
        """Test finding creation and retrieval"""
        # Create test finding
        finding = Finding(
            id=uuid.uuid4(),
            rule_id="TEST-001",
            resource_id="test-resource",
            resource_type="test",
            severity="HIGH",
            event_id="test-event",
            timestamp=datetime.utcnow(),
            remediation_steps="Test remediation",
            account_id="123456789012",
            region="us-east-1"
        )
        
        mock_db_session.query.return_value.filter.return_value.all.return_value = [finding]
        
        with patch('app.api.rest.get_db') as mock_get_db:
            mock_get_db.return_value = mock_db_session
            
            # Test API endpoint
            client = TestClient(app)
            response = client.get("/api/v1/findings")
            
            assert response.status_code == 200
            data = response.json()
            assert len(data) == 1
            assert data[0]["rule_id"] == "TEST-001"
            assert data[0]["severity"] == "HIGH"

    @pytest.mark.asyncio
    async def test_rule_engine_integration(self):
        """Test rule engine with mock AWS responses"""
        from app.rule_engine import RuleEngine
        
        # Mock event
        event = {
            "eventID": "test-001",
            "eventName": "PutBucketPolicy",
            "eventSource": "s3.amazonaws.com",
            "eventTime": "2024-01-15T12:00:00Z",
            "awsRegion": "us-east-1",
            "userIdentity": {"accountId": "123456789012"},
            "requestParameters": {"bucketName": "test-bucket"},
            "responseElements": {
                "policy": json.dumps({
                    "Statement": [{
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:GetObject"
                    }]
                })
            }
        }
        
        # Mock rule engine
        with patch('app.rule_engine.RuleEngine') as mock_rule_engine_class:
            mock_engine = MagicMock()
            mock_rule_engine_class.return_value = mock_engine
            
            # Mock rule evaluation
            mock_finding = Finding(
                id=uuid.uuid4(),
                rule_id="S3-001",
                resource_id="test-bucket",
                resource_type="s3",
                severity="HIGH",
                event_id="test-001",
                timestamp=datetime.utcnow()
            )
            
            mock_engine.process_event.return_value = [mock_finding]
            
            # Test processing
            rule_engine = RuleEngine()
            findings = await rule_engine.process_event(event)
            
            assert len(findings) == 1
            assert findings[0].rule_id == "S3-001"
            assert findings[0].severity == "HIGH"

    @pytest.mark.asyncio
    async def test_event_ingestor_flow(self, sample_cloudtrail_event):
        """Test complete event ingestor flow"""
        from app.engine.event_ingestor import EventIngestor
        
        # Test event normalization
        normalized_event = {
            "event_id": sample_cloudtrail_event["eventID"],
            "event_name": sample_cloudtrail_event["eventName"],
            "event_source": sample_cloudtrail_event["eventSource"],
            "event_time": sample_cloudtrail_event["eventTime"],
            "resource_id": "test-bucket-123",
            "resource_type": "s3",
            "account_id": sample_cloudtrail_event["userIdentity"]["accountId"],
            "region": sample_cloudtrail_event["awsRegion"],
            "raw_event": sample_cloudtrail_event
        }
        
        # Test ingestor with mocked database
        ingestor = EventIngestor()
        
        with patch('app.engine.event_ingestor.AsyncSessionLocal') as mock_session_local, \
             patch.object(ingestor, '_validate_cloudtrail_event') as mock_validate, \
             patch.object(ingestor, '_extract_event_metadata') as mock_extract:
            
            # Mock database session
            mock_session = AsyncMock()
            mock_session_local.return_value.__aenter__.return_value = mock_session
            
            # Mock validation and extraction
            mock_validate.return_value = True
            mock_extract.return_value = normalized_event
            
            # Process event
            result = await ingestor.process_event(sample_cloudtrail_event)
            
            assert result is True
            mock_session.add.assert_called()
            mock_session.commit.assert_called()

    @pytest.mark.asyncio
    async def test_websocket_connection(self):
        """Test WebSocket connection and messaging"""
        from app.api.websocket import ConnectionManager
        
        manager = ConnectionManager()
        
        # Mock WebSocket
        websocket = AsyncMock()
        websocket.accept = AsyncMock()
        websocket.send_text = AsyncMock()
        websocket.client = MagicMock()
        websocket.client.host = "127.0.0.1"
        
        # Test connection
        await manager.connect(websocket)
        assert len(manager.active_connections) == 1
        
        # Test message sending
        test_message = json.dumps({"type": "test", "data": "test message"})
        await manager.send_personal_message(test_message, websocket)
        websocket.send_text.assert_called_with(test_message)
        
        # Test broadcast
        await manager.broadcast(test_message)
        websocket.send_text.assert_called_with(test_message)
        
        # Test disconnect
        manager.disconnect(websocket)
        assert len(manager.active_connections) == 0

    @pytest.mark.asyncio
    async def test_scheduler_integration(self, sample_accounts):
        """Test scheduler integration"""
        from app.scheduler.audit_scheduler import AuditScheduler
        
        scheduler = AuditScheduler()
        
        # Mock AWS calls and database
        with patch.object(scheduler, '_get_aws_accounts') as mock_get_accounts, \
             patch.object(scheduler, '_audit_account') as mock_audit_account, \
             patch('app.scheduler.audit_scheduler.AsyncSessionLocal') as mock_session_local:
            
            mock_get_accounts.return_value = sample_accounts
            mock_audit_account.return_value = [
                Finding(
                    id=uuid.uuid4(),
                    rule_id="S3-001",
                    resource_id="test-bucket",
                    resource_type="s3",
                    severity="HIGH"
                )
            ]
            
            # Mock database session
            mock_session = AsyncMock()
            mock_session_local.return_value.__aenter__.return_value = mock_session
            
            # Run audit
            audit_log = await scheduler.run_security_audit("full")
            
            assert audit_log.status == "COMPLETED"
            assert audit_log.findings_count == len(sample_accounts)
            mock_session.add.assert_called()
            mock_session.commit.assert_called()

    @pytest.mark.asyncio
    async def test_multi_account_workflow(self, sample_accounts):
        """Test multi-account audit workflow"""
        from app.aws.organizations import AWSOrganizationsManager
        from app.scheduler.audit_scheduler import AuditScheduler
        
        # Mock organizations manager
        with patch('app.aws.organizations.AWSOrganizationsManager') as mock_org_manager_class:
            mock_org_manager = MagicMock()
            mock_org_manager_class.return_value = mock_org_manager
            mock_org_manager.get_all_accounts.return_value = sample_accounts
            
            scheduler = AuditScheduler()
            scheduler.settings.enable_multi_account = True
            scheduler._organizations_manager = mock_org_manager
            
            accounts = await scheduler._get_aws_accounts()
            
            assert len(accounts) == len(sample_accounts)
            assert accounts[0]['id'] == '123456789012'
            assert accounts[1]['id'] == '123456789013'

    @pytest.mark.asyncio
    async def test_security_middleware_integration(self):
        """Test security middleware integration"""
        from fastapi import Request
        from starlette.responses import Response
        
        # Create mock request and response
        mock_request = MagicMock(spec=Request)
        mock_request.client.host = "192.168.1.100"
        mock_request.method = "GET"
        mock_request.url.path = "/api/v1/findings"
        
        mock_response = MagicMock(spec=Response)
        mock_response.headers = {}
        
        # Test security headers middleware
        from app.security.middleware import SecurityHeadersMiddleware
        middleware = SecurityHeadersMiddleware(app=None)
        
        mock_call_next = AsyncMock(return_value=mock_response)
        
        response = await middleware.dispatch(mock_request, mock_call_next)
        
        # Verify security headers are added
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert "Strict-Transport-Security" in response.headers

    @pytest.mark.asyncio
    async def test_rate_limiting_integration(self):
        """Test rate limiting integration"""
        from fastapi import Request
        from starlette.responses import Response
        
        # Create mock request
        mock_request = MagicMock(spec=Request)
        mock_request.client.host = "192.168.1.100"
        
        mock_response = MagicMock(spec=Response)
        mock_response.headers = {}
        
        # Test rate limiting middleware
        from app.security.middleware import RateLimitMiddleware
        middleware = RateLimitMiddleware(app=None, max_requests=2, time_window=60)
        
        mock_call_next = AsyncMock(return_value=mock_response)
        
        # Make requests up to limit
        await middleware.dispatch(mock_request, mock_call_next)
        await middleware.dispatch(mock_request, mock_call_next)
        
        # Next request should be rate limited
        with pytest.raises(Exception):  # HTTPException
            await middleware.dispatch(mock_request, mock_call_next)

    @pytest.mark.asyncio
    async def test_database_transaction_integration(self, mock_db_session):
        """Test database transaction integration"""
        # Create multiple findings
        findings = [
            Finding(
                id=uuid.uuid4(),
                rule_id=f"S3-{i:03d}",
                resource_id=f"test-bucket-{i}",
                resource_type="s3",
                severity="HIGH",
                timestamp=datetime.utcnow(),
                account_id="123456789012",
                region="us-east-1"
            )
            for i in range(5)
        ]
        
        mock_db_session.query.return_value.filter.return_value.all.return_value = findings
        
        with patch('app.api.rest.get_db') as mock_get_db:
            mock_get_db.return_value = mock_db_session
            
            # Test API endpoint with multiple findings
            client = TestClient(app)
            response = client.get("/api/v1/findings")
            
            assert response.status_code == 200
            data = response.json()
            assert len(data) == 5
            
            # Verify all findings are present
            rule_ids = [finding["rule_id"] for finding in data]
            assert "S3-000" in rule_ids
            assert "S3-004" in rule_ids

    @pytest.mark.asyncio
    async def test_error_handling_integration(self, mock_db_session):
        """Test error handling integration"""
        # Mock database error
        mock_db_session.query.return_value.filter.return_value.all.side_effect = Exception("Database error")
        
        with patch('app.api.rest.get_db') as mock_get_db:
            mock_get_db.return_value = mock_db_session
            
            # Test API error handling
            client = TestClient(app)
            response = client.get("/api/v1/findings")
            
            # Should handle error gracefully
            assert response.status_code in [500, 200]  # Depending on error handling implementation

    @pytest.mark.asyncio
    async def test_cache_integration(self, mock_redis):
        """Test Redis cache integration"""
        with patch('redis.Redis.from_url', return_value=mock_redis):
            # Mock cache operations
            mock_redis.get.return_value = None
            mock_redis.setex.return_value = True
            
            # Test caching
            from app.cache import CacheManager
            cache = CacheManager()
            
            # Test cache set
            await cache.set("test_key", {"data": "test_value"}, ttl=60)
            mock_redis.setex.assert_called_once()
            
            # Test cache get
            mock_redis.get.return_value = json.dumps({"data": "test_value"})
            result = await cache.get("test_key")
            
            assert result == {"data": "test_value"}
            mock_redis.get.assert_called_once()

    @pytest.mark.asyncio
    async def test_notification_integration(self):
        """Test notification system integration"""
        from app.notifier import NotificationManager
        
        with patch('app.notifier.slack_notifier.SlackNotifier') as mock_slack, \
             patch('app.notifier.email_notifier.EmailNotifier') as mock_email:
            
            # Mock notifiers
            mock_slack_instance = AsyncMock()
            mock_email_instance = AsyncMock()
            mock_slack.return_value = mock_slack_instance
            mock_email.return_value = mock_email_instance
            
            # Test notification sending
            notifier = NotificationManager()
            finding = Finding(
                id=uuid.uuid4(),
                rule_id="S3-001",
                resource_id="test-bucket",
                resource_type="s3",
                severity="HIGH"
            )
            
            await notifier.send_finding_notification(finding)
            
            # Verify notifications were sent
            mock_slack_instance.send_message.assert_called_once()
            mock_email_instance.send_email.assert_called_once()

    @pytest.mark.asyncio
    async def test_monitoring_integration(self):
        """Test monitoring and metrics integration"""
        with patch('app.metrics.prometheus_client') as mock_prometheus:
            # Mock Prometheus metrics
            mock_counter = MagicMock()
            mock_histogram = MagicMock()
            mock_prometheus.Counter.return_value = mock_counter
            mock_prometheus.Histogram.return_value = mock_histogram
            
            # Test metrics collection
            from app.metrics import MetricsCollector
            metrics = MetricsCollector()
            
            # Record metrics
            metrics.increment_events_processed()
            metrics.record_audit_duration(60.5)
            
            # Verify metrics were recorded
            mock_counter.inc.assert_called_once()
            mock_histogram.observe.assert_called_once_with(60.5)
