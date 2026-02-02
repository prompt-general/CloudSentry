import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient
import json
import uuid
from datetime import datetime

from app.main import app
from app.models import Finding, Event


class TestIntegration:
    """Integration tests for the complete system"""

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
        return session

    @pytest.mark.asyncio
    async def test_full_event_processing_pipeline(self, sample_cloudtrail_event):
        """Test complete event processing from ingestion to finding generation"""
        with patch('app.engine.event_ingestor.AsyncSessionLocal') as mock_session_local, \
             patch('app.rule_engine.RuleEngine') as mock_rule_engine:
            
            # Mock database session
            mock_session = AsyncMock()
            mock_session_local.return_value.__aenter__.return_value = mock_session
            
            # Mock rule engine to generate findings
            mock_engine = MagicMock()
            mock_engine.process_event.return_value = [
                Finding(
                    id=uuid.uuid4(),
                    rule_id="S3-001",
                    resource_id="test-bucket-123",
                    resource_type="s3",
                    severity="HIGH",
                    event_id=sample_cloudtrail_event["eventID"],
                    timestamp=datetime.utcnow()
                )
            ]
            mock_rule_engine.return_value = mock_engine
            
            # Import and test event ingestor
            from app.engine.event_ingestor import EventIngestor
            ingestor = EventIngestor()
            
            # Process event
            result = await ingestor.process_event(sample_cloudtrail_event)
            
            assert result is True
            mock_session.add.assert_called()
            mock_session.commit.assert_called()

    @pytest.mark.asyncio
    async def test_security_audit_workflow(self, sample_accounts):
        """Test complete security audit workflow"""
        with patch('app.scheduler.audit_scheduler.AsyncSessionLocal') as mock_session_local, \
             patch('app.aws.organizations.AWSOrganizationsManager') as mock_org_manager:
            
            # Mock database session
            mock_session = AsyncMock()
            mock_session_local.return_value.__aenter__.return_value = mock_session
            
            # Mock organizations manager
            mock_org = MagicMock()
            mock_org.get_all_accounts.return_value = sample_accounts
            mock_org_manager.return_value = mock_org
            
            # Import and test audit scheduler
            from app.scheduler.audit_scheduler import AuditScheduler
            scheduler = AuditScheduler()
            
            # Mock account auditing
            with patch.object(scheduler, '_audit_account') as mock_audit_account:
                mock_audit_account.return_value = [
                    Finding(
                        id=uuid.uuid4(),
                        rule_id="S3-001",
                        resource_id="test-bucket",
                        resource_type="s3",
                        severity="HIGH"
                    )
                ]
                
                # Run audit
                audit_log = await scheduler.run_security_audit("full")
                
                assert audit_log.status == "COMPLETED"
                assert audit_log.findings_count == len(sample_accounts)
                mock_session.add.assert_called()

    def test_api_endpoints_integration(self, client, mock_db_session, mock_redis):
        """Test API endpoints integration"""
        with patch('app.main.get_db') as mock_get_db, \
             patch('redis.Redis.from_url') as mock_redis_client:
            
            mock_get_db.return_value = mock_db_session
            mock_redis_instance = AsyncMock()
            mock_redis_instance.ping.return_value = True
            mock_redis_instance.close.return_value = None
            mock_redis_client.return_value = mock_redis_instance
            
            # Test root endpoint
            response = client.get("/")
            assert response.status_code == 200
            assert response.json()["service"] == "CloudSentry"
            
            # Test health endpoint
            response = client.get("/health")
            assert response.status_code == 200
            assert response.json()["status"] == "healthy"
            
            # Test metrics endpoint
            response = client.get("/metrics")
            assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_middleware_integration(self):
        """Test security middleware integration"""
        from fastapi import Request
        from starlette.responses import Response
        
        # Create mock request and response
        mock_request = MagicMock(spec=Request)
        mock_request.client.host = "192.168.1.100"
        mock_request.method = "GET"
        mock_request.url.path = "/test"
        
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

    @pytest.mark.asyncio
    async def test_multi_account_workflow(self, sample_accounts):
        """Test multi-account audit workflow"""
        with patch('app.aws.organizations.AWSOrganizationsManager') as mock_org_manager, \
             patch('app.scheduler.audit_scheduler.AsyncSessionLocal') as mock_session_local:
            
            # Mock organizations manager
            mock_org = MagicMock()
            mock_org.get_all_accounts.return_value = sample_accounts
            mock_org.get_account_session.return_value = MagicMock()
            mock_org_manager.return_value = mock_org
            
            # Mock database session
            mock_session = AsyncMock()
            mock_session_local.return_value.__aenter__.return_value = mock_session
            
            # Test multi-account audit
            from app.scheduler.audit_scheduler import AuditScheduler
            scheduler = AuditScheduler()
            scheduler.settings.enable_multi_account = True
            scheduler._organizations_manager = mock_org
            
            with patch.object(scheduler, '_run_security_rules') as mock_rules:
                mock_rules.return_value = [
                    Finding(
                        id=uuid.uuid4(),
                        rule_id="S3-001",
                        resource_id="test-bucket",
                        resource_type="s3",
                        severity="HIGH"
                    )
                ]
                
                accounts = await scheduler._get_aws_accounts()
                assert len(accounts) == len(sample_accounts)
                
                # Audit each account
                for account in accounts:
                    findings = await scheduler._audit_account(account, "full")
                    assert isinstance(findings, list)

    @pytest.mark.asyncio
    async def test_error_handling_integration(self, sample_cloudtrail_event):
        """Test error handling across the system"""
        with patch('app.engine.event_ingestor.AsyncSessionLocal') as mock_session_local:
            # Mock database failure
            mock_session = AsyncMock()
            mock_session.commit.side_effect = Exception("Database connection failed")
            mock_session_local.return_value.__aenter__.return_value = mock_session
            
            # Test event processing with database error
            from app.engine.event_ingestor import EventIngestor
            ingestor = EventIngestor()
            
            result = await ingestor.process_event(sample_cloudtrail_event)
            assert result is False

    @pytest.mark.asyncio
    async def test_concurrent_event_processing(self, sample_security_events):
        """Test concurrent event processing"""
        with patch('app.engine.event_ingestor.AsyncSessionLocal') as mock_session_local:
            # Mock database session
            mock_session = AsyncMock()
            mock_session_local.return_value.__aenter__.return_value = mock_session
            
            # Test batch processing
            from app.engine.event_ingestor import EventIngestor
            ingestor = EventIngestor()
            
            # Process events concurrently
            tasks = [
                ingestor.process_event(event) 
                for event in sample_security_events
            ]
            
            results = await asyncio.gather(*tasks)
            
            # All events should be processed
            assert len(results) == len(sample_security_events)
            assert all(isinstance(result, bool) for result in results)

    @pytest.mark.asyncio
    async def test_notification_integration(self):
        """Test notification system integration"""
        with patch('app.notifier.slack_notifier.SlackNotifier') as mock_slack, \
             patch('app.notifier.email_notifier.EmailNotifier') as mock_email:
            
            # Mock notifiers
            mock_slack_instance = AsyncMock()
            mock_email_instance = AsyncMock()
            mock_slack.return_value = mock_slack_instance
            mock_email.return_value = mock_email_instance
            
            # Test notification sending
            from app.notifier import NotificationManager
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
    async def test_caching_integration(self, mock_redis):
        """Test Redis caching integration"""
        with patch('redis.Redis.from_url', return_value=mock_redis):
            # Test cache operations
            from app.cache import CacheManager
            
            cache = CacheManager()
            
            # Test cache set and get
            await cache.set("test_key", {"data": "test_value"}, ttl=60)
            mock_redis.setex.assert_called_once()
            
            mock_redis.get.return_value = json.dumps({"data": "test_value"})
            result = await cache.get("test_key")
            
            assert result == {"data": "test_value"}
            mock_redis.get.assert_called_once()

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

    @pytest.mark.asyncio
    async def test_configuration_integration(self, test_settings):
        """Test configuration system integration"""
        with patch('app.config.get_settings', return_value=test_settings):
            from app.config import get_settings
            
            settings = get_settings()
            
            assert settings.database_url == "postgresql+asyncpg://test:test@localhost:5432/test_db"
            assert settings.aws_region == "us-east-1"
            assert settings.enable_multi_account is False

    def test_cors_integration(self, client):
        """Test CORS integration"""
        # Test preflight request
        response = client.options("/health", headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "Content-Type"
        })
        
        assert response.status_code == 200
        assert "access-control-allow-origin" in response.headers

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
