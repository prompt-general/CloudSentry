import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import asyncio
from datetime import datetime, timedelta

from app.engine.event_ingestor import EventIngestor
from app.models import Event, Finding
import uuid


class TestEventIngestor:
    """Test event ingestor functionality"""

    @pytest.fixture
    def event_ingestor(self, test_settings):
        """Create event ingestor instance"""
        with patch('app.engine.event_ingestor.get_settings') as mock_settings:
            mock_settings.return_value = test_settings
            return EventIngestor()

    @pytest.fixture
    def mock_db_session(self):
        """Mock database session"""
        session = AsyncMock()
        session.add.return_value = None
        session.commit.return_value = None
        session.refresh.return_value = None
        session.execute.return_value = AsyncMock()
        return session

    @pytest.mark.asyncio
    async def test_process_cloudtrail_event_success(self, event_ingestor, mock_db_session, sample_cloudtrail_event):
        """Test successful CloudTrail event processing"""
        with patch('app.engine.event_ingestor.AsyncSessionLocal') as mock_session_local:
            mock_session_local.return_value.__aenter__.return_value = mock_db_session
            
            result = await event_ingestor.process_event(sample_cloudtrail_event)
            
            assert result is True
            mock_db_session.add.assert_called()
            mock_db_session.commit.assert_called()

    @pytest.mark.asyncio
    async def test_process_cloudtrail_event_duplicate(self, event_ingestor, mock_db_session, sample_cloudtrail_event):
        """Test handling of duplicate events"""
        # Mock duplicate event error
        mock_db_session.commit.side_effect = Exception("Unique violation")
        
        with patch('app.engine.event_ingestor.AsyncSessionLocal') as mock_session_local:
            mock_session_local.return_value.__aenter__.return_value = mock_db_session
            
            result = await event_ingestor.process_event(sample_cloudtrail_event)
            
            assert result is False

    @pytest.mark.asyncio
    async def test_process_cloudtrail_event_invalid_format(self, event_ingestor, mock_db_session):
        """Test handling of invalid event format"""
        invalid_event = {"invalid": "event"}
        
        with patch('app.engine.event_ingestor.AsyncSessionLocal') as mock_session_local:
            mock_session_local.return_value.__aenter__.return_value = mock_db_session
            
            result = await event_ingestor.process_event(invalid_event)
            
            assert result is False

    @pytest.mark.asyncio
    async def test_process_cloudtrail_event_missing_required_fields(self, event_ingestor, mock_db_session):
        """Test handling of events missing required fields"""
        incomplete_event = {
            "eventVersion": "1.08",
            "eventTime": "2024-01-15T12:00:00Z",
            # Missing required fields like eventSource, eventName, etc.
        }
        
        with patch('app.engine.event_ingestor.AsyncSessionLocal') as mock_session_local:
            mock_session_local.return_value.__aenter__.return_value = mock_db_session
            
            result = await event_ingestor.process_event(incomplete_event)
            
            assert result is False

    @pytest.mark.asyncio
    async def test_extract_event_metadata(self, event_ingestor, sample_cloudtrail_event):
        """Test event metadata extraction"""
        metadata = event_ingestor._extract_event_metadata(sample_cloudtrail_event)
        
        assert metadata['event_id'] == "12345678-1234-1234-1234-123456789012"
        assert metadata['event_name'] == "CreateBucket"
        assert metadata['event_source'] == "s3.amazonaws.com"
        assert metadata['account_id'] == "123456789012"
        assert metadata['region'] == "us-east-1"
        assert metadata['resource_id'] == "test-bucket-123"
        assert metadata['resource_type'] == "s3"

    @pytest.mark.asyncio
    async def test_extract_event_metadata_no_resource(self, event_ingestor):
        """Test metadata extraction for events without resources"""
        event_no_resource = {
            "eventVersion": "1.08",
            "eventTime": "2024-01-15T12:00:00Z",
            "eventSource": "iam.amazonaws.com",
            "eventName": "CreateUser",
            "awsRegion": "us-east-1",
            "userIdentity": {
                "accountId": "123456789012"
            },
            "eventID": "12345678-1234-1234-1234-123456789012"
        }
        
        metadata = event_ingestor._extract_event_metadata(event_no_resource)
        
        assert metadata['event_id'] == "12345678-1234-1234-1234-123456789012"
        assert metadata['event_name'] == "CreateUser"
        assert metadata['event_source'] == "iam.amazonaws.com"
        assert metadata['account_id'] == "123456789012"
        assert metadata['region'] == "us-east-1"
        assert metadata['resource_id'] is None
        assert metadata['resource_type'] == "iam"

    @pytest.mark.asyncio
    async def test_validate_cloudtrail_event_valid(self, event_ingestor, sample_cloudtrail_event):
        """Test CloudTrail event validation for valid events"""
        is_valid = event_ingestor._validate_cloudtrail_event(sample_cloudtrail_event)
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_validate_cloudtrail_event_invalid_version(self, event_ingestor):
        """Test CloudTrail event validation for invalid version"""
        invalid_event = {
            "eventVersion": "1.0",  # Invalid version
            "eventTime": "2024-01-15T12:00:00Z",
            "eventSource": "s3.amazonaws.com",
            "eventName": "CreateBucket",
            "eventID": "12345678-1234-1234-1234-123456789012"
        }
        
        is_valid = event_ingestor._validate_cloudtrail_event(invalid_event)
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_validate_cloudtrail_event_missing_fields(self, event_ingestor):
        """Test CloudTrail event validation for missing required fields"""
        incomplete_event = {
            "eventVersion": "1.08",
            # Missing required fields
        }
        
        is_valid = event_ingestor._validate_cloudtrail_event(incomplete_event)
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_process_event_batch(self, event_ingestor, mock_db_session, sample_security_events):
        """Test processing multiple events in batch"""
        with patch('app.engine.event_ingestor.AsyncSessionLocal') as mock_session_local:
            mock_session_local.return_value.__aenter__.return_value = mock_db_session
            
            results = await event_ingestor.process_event_batch(sample_security_events)
            
            assert len(results) == len(sample_security_events)
            assert all(result is True for result in results)

    @pytest.mark.asyncio
    async def test_process_event_batch_mixed_results(self, event_ingestor, mock_db_session, sample_cloudtrail_event):
        """Test processing batch with mixed success/failure"""
        events = [
            sample_cloudtrail_event,
            {"invalid": "event"},  # This should fail
            sample_cloudtrail_event  # This should succeed
        ]
        
        with patch('app.engine.event_ingestor.AsyncSessionLocal') as mock_session_local:
            mock_session_local.return_value.__aenter__.return_value = mock_db_session
            
            results = await event_ingestor.process_event_batch(events)
            
            assert len(results) == 3
            assert results[0] is True
            assert results[1] is False
            assert results[2] is True

    @pytest.mark.asyncio
    async def test_start_event_ingestor(self, event_ingestor):
        """Test starting the event ingestor service"""
        with patch('app.engine.event_ingestor.asyncio.create_task') as mock_create_task, \
             patch.object(event_ingestor, '_process_events_queue') as mock_process:
            
            mock_process.return_value = None
            
            await event_ingestor.start()
            
            mock_create_task.assert_called()

    @pytest.mark.asyncio
    async def test_stop_event_ingestor(self, event_ingestor):
        """Test stopping the event ingestor service"""
        event_ingestor._running = True
        event_ingestor._task = AsyncMock()
        
        await event_ingestor.stop()
        
        assert event_ingestor._running is False
        event_ingestor._task.cancel.assert_called()

    @pytest.mark.asyncio
    async def test_get_ingestion_stats(self, event_ingestor):
        """Test getting ingestion statistics"""
        event_ingestor._stats = {
            'events_processed': 100,
            'events_failed': 5,
            'events_per_second': 10.5,
            'last_processed': datetime.utcnow()
        }
        
        stats = event_ingestor.get_stats()
        
        assert stats['events_processed'] == 100
        assert stats['events_failed'] == 5
        assert stats['events_per_second'] == 10.5
        assert 'last_processed' in stats

    @pytest.mark.asyncio
    async def test_reset_stats(self, event_ingestor):
        """Test resetting ingestion statistics"""
        event_ingestor._stats = {
            'events_processed': 100,
            'events_failed': 5
        }
        
        event_ingestor.reset_stats()
        
        stats = event_ingestor.get_stats()
        assert stats['events_processed'] == 0
        assert stats['events_failed'] == 0

    @pytest.mark.asyncio
    async def test_handle_database_error(self, event_ingestor, sample_cloudtrail_event):
        """Test handling of database errors during event processing"""
        with patch('app.engine.event_ingestor.AsyncSessionLocal') as mock_session_local:
            mock_session = AsyncMock()
            mock_session.add.side_effect = Exception("Database connection failed")
            mock_session_local.return_value.__aenter__.return_value = mock_session
            
            result = await event_ingestor.process_event(sample_cloudtrail_event)
            
            assert result is False

    @pytest.mark.asyncio
    async def test_process_events_from_sqs(self, event_ingestor, mock_db_session, sample_security_events):
        """Test processing events from SQS queue"""
        # Mock SQS message
        mock_message = MagicMock()
        mock_message.body = json.dumps(sample_security_events[0])
        mock_message.delete = AsyncMock()
        
        mock_sqs = AsyncMock()
        mock_sqs.receive_message.return_value = {
            'Messages': [mock_message]
        }
        
        with patch('boto3.client', return_value=mock_sqs), \
             patch('app.engine.event_ingestor.AsyncSessionLocal') as mock_session_local:
            
            mock_session_local.return_value.__aenter__.return_value = mock_db_session
            
            # Process one message
            await event_ingestor._process_sqs_messages()
            
            # Verify message was processed and deleted
            mock_db_session.add.assert_called()
            mock_message.delete.assert_called()

    @pytest.mark.asyncio
    async def test_process_events_from_sqs_empty_queue(self, event_ingestor):
        """Test handling empty SQS queue"""
        mock_sqs = AsyncMock()
        mock_sqs.receive_message.return_value = {'Messages': []}
        
        with patch('boto3.client', return_value=mock_sqs):
            # Should not raise any errors
            await event_ingestor._process_sqs_messages()

    @pytest.mark.asyncio
    async def test_process_events_from_sqs_error(self, event_ingestor):
        """Test handling SQS errors"""
        mock_sqs = AsyncMock()
        mock_sqs.receive_message.side_effect = Exception("SQS connection failed")
        
        with patch('boto3.client', return_value=mock_sqs), \
             patch('app.engine.event_ingestor.logger') as mock_logger:
            
            await event_ingestor._process_sqs_messages()
            
            # Should log the error
            mock_logger.error.assert_called()
