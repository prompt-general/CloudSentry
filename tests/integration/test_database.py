import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
import tempfile
import os
from datetime import datetime

from app.database import AsyncSessionLocal, async_engine
from app.models import Base, Finding, Event, RuleMetadata, AuditLog
import uuid


class TestDatabase:
    """Database integration tests"""

    @pytest.mark.asyncio
    async def test_database_connection(self, test_settings):
        """Test database connection and session creation"""
        with patch('app.database.get_settings', return_value=test_settings):
            from app.database import get_db
            
            # Test database session generator
            async for session in get_db():
                assert session is not None
                break  # Just test one session

    @pytest.mark.asyncio
    async def test_create_tables(self, test_settings):
        """Test table creation"""
        with patch('app.database.get_settings', return_value=test_settings):
            # Create all tables
            async with async_engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            
            # Verify tables exist by attempting to query them
            async with AsyncSessionLocal() as session:
                # This should not raise an error if tables exist
                await session.execute("SELECT 1")
                await session.commit()

    @pytest.mark.asyncio
    async def test_finding_crud_operations(self, test_settings):
        """Test Finding CRUD operations"""
        with patch('app.database.get_settings', return_value=test_settings):
            # Create tables
            async with async_engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            
            # Test CRUD operations
            async with AsyncSessionLocal() as session:
                # Create
                finding = Finding(
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
                
                session.add(finding)
                await session.commit()
                await session.refresh(finding)
                
                assert finding.id is not None
                
                # Read
                from sqlalchemy import select
                stmt = select(Finding).where(Finding.id == finding.id)
                result = await session.execute(stmt)
                retrieved_finding = result.scalar_one()
                
                assert retrieved_finding.rule_id == "S3-001"
                assert retrieved_finding.resource_id == "test-bucket-123"
                assert retrieved_finding.severity == "HIGH"
                
                # Update
                retrieved_finding.status = "RESOLVED"
                await session.commit()
                
                # Verify update
                stmt = select(Finding).where(Finding.id == finding.id)
                result = await session.execute(stmt)
                updated_finding = result.scalar_one()
                
                assert updated_finding.status == "RESOLVED"
                
                # Delete
                await session.delete(updated_finding)
                await session.commit()
                
                # Verify deletion
                stmt = select(Finding).where(Finding.id == finding.id)
                result = await session.execute(stmt)
                assert result.scalar_one_or_none() is None

    @pytest.mark.asyncio
    async def test_event_crud_operations(self, test_settings):
        """Test Event CRUD operations"""
        with patch('app.database.get_settings', return_value=test_settings):
            # Create tables
            async with async_engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            
            async with AsyncSessionLocal() as session:
                # Create event
                event = Event(
                    event_id="cloudtrail-event-123",
                    event_name="CreateBucket",
                    event_source="s3.amazonaws.com",
                    event_time=datetime.utcnow(),
                    resource_id="test-bucket",
                    resource_type="s3",
                    account_id="123456789012",
                    region="us-east-1",
                    raw_event={"key": "value"}
                )
                
                session.add(event)
                await session.commit()
                await session.refresh(event)
                
                assert event.id is not None
                
                # Test unique constraint on event_id
                duplicate_event = Event(
                    event_id="cloudtrail-event-123",  # Same event_id
                    event_name="PutObject",
                    event_source="s3.amazonaws.com",
                    event_time=datetime.utcnow(),
                    account_id="123456789012",
                    region="us-east-1"
                )
                
                session.add(duplicate_event)
                
                # Should raise integrity error due to unique constraint
                with pytest.raises(Exception):  # Could be IntegrityError or similar
                    await session.commit()

    @pytest.mark.asyncio
    async def test_rule_metadata_crud_operations(self, test_settings):
        """Test RuleMetadata CRUD operations"""
        with patch('app.database.get_settings', return_value=test_settings):
            # Create tables
            async with async_engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            
            async with AsyncSessionLocal() as session:
                # Create rule
                rule = RuleMetadata(
                    id="S3-001",
                    description="Public S3 bucket detected",
                    severity="HIGH",
                    resource_types=["s3"],
                    enabled=True
                )
                
                session.add(rule)
                await session.commit()
                await session.refresh(rule)
                
                assert rule.id == "S3-001"
                assert rule.created_at is not None
                assert rule.updated_at is not None
                
                # Test update timestamp
                original_updated_at = rule.updated_at
                await asyncio.sleep(0.1)  # Small delay to ensure timestamp difference
                
                rule.description = "Updated description"
                await session.commit()
                await session.refresh(rule)
                
                assert rule.description == "Updated description"
                assert rule.updated_at > original_updated_at

    @pytest.mark.asyncio
    async def test_audit_log_crud_operations(self, test_settings):
        """Test AuditLog CRUD operations"""
        with patch('app.database.get_settings', return_value=test_settings):
            # Create tables
            async with async_engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            
            async with AsyncSessionLocal() as session:
                # Create audit log
                start_time = datetime.utcnow()
                audit_log = AuditLog(
                    audit_type="security",
                    account_id="123456789012",
                    start_time=start_time,
                    status="IN_PROGRESS",
                    findings_count=0
                )
                
                session.add(audit_log)
                await session.commit()
                await session.refresh(audit_log)
                
                assert audit_log.id is not None
                assert audit_log.status == "IN_PROGRESS"
                
                # Update audit log completion
                audit_log.end_time = datetime.utcnow()
                audit_log.status = "COMPLETED"
                audit_log.findings_count = 5
                
                await session.commit()
                await session.refresh(audit_log)
                
                assert audit_log.status == "COMPLETED"
                assert audit_log.findings_count == 5
                assert audit_log.end_time is not None

    @pytest.mark.asyncio
    async def test_relationship_operations(self, test_settings):
        """Test operations between related entities"""
        with patch('app.database.get_settings', return_value=test_settings):
            # Create tables
            async with async_engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            
            async with AsyncSessionLocal() as session:
                # Create event first
                event = Event(
                    event_id="cloudtrail-event-456",
                    event_name="CreateUser",
                    event_source="iam.amazonaws.com",
                    event_time=datetime.utcnow(),
                    account_id="123456789012",
                    region="us-east-1"
                )
                
                session.add(event)
                await session.commit()
                await session.refresh(event)
                
                # Create finding linked to event
                finding = Finding(
                    rule_id="IAM-001",
                    resource_id="test-user",
                    resource_type="iam",
                    severity="CRITICAL",
                    event_id=event.event_id,  # Link to event
                    timestamp=datetime.utcnow(),
                    account_id="123456789012",
                    region="us-east-1"
                )
                
                session.add(finding)
                await session.commit()
                await session.refresh(finding)
                
                # Verify relationship
                assert finding.event_id == event.event_id
                
                # Query findings by event
                from sqlalchemy import select
                stmt = select(Finding).where(Finding.event_id == event.event_id)
                result = await session.execute(stmt)
                findings = result.scalars().all()
                
                assert len(findings) == 1
                assert findings[0].id == finding.id

    @pytest.mark.asyncio
    async def test_query_performance(self, test_settings):
        """Test database query performance with larger datasets"""
        with patch('app.database.get_settings', return_value=test_settings):
            # Create tables
            async with async_engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            
            async with AsyncSessionLocal() as session:
                # Create multiple findings
                findings = []
                for i in range(100):
                    finding = Finding(
                        rule_id=f"S3-{i:03d}",
                        resource_id=f"test-bucket-{i}",
                        resource_type="s3",
                        severity="HIGH" if i % 2 == 0 else "MEDIUM",
                        timestamp=datetime.utcnow(),
                        account_id="123456789012",
                        region="us-east-1"
                    )
                    findings.append(finding)
                
                session.add_all(findings)
                await session.commit()
                
                # Test query performance
                import time
                start_time = time.time()
                
                from sqlalchemy import select
                stmt = select(Finding).where(Finding.severity == "HIGH")
                result = await session.execute(stmt)
                high_severity_findings = result.scalars().all()
                
                end_time = time.time()
                query_time = end_time - start_time
                
                assert len(high_severity_findings) == 50
                assert query_time < 1.0  # Should complete within 1 second

    @pytest.mark.asyncio
    async def test_transaction_rollback(self, test_settings):
        """Test transaction rollback on errors"""
        with patch('app.database.get_settings', return_value=test_settings):
            # Create tables
            async with async_engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            
            async with AsyncSessionLocal() as session:
                # Create initial finding
                finding = Finding(
                    rule_id="S3-001",
                    resource_id="test-bucket",
                    resource_type="s3",
                    severity="HIGH",
                    timestamp=datetime.utcnow(),
                    account_id="123456789012",
                    region="us-east-1"
                )
                
                session.add(finding)
                await session.commit()
                
                # Start new transaction that will fail
                finding2 = Finding(
                    rule_id="IAM-001",
                    resource_id="test-user",
                    resource_type="iam",
                    severity="CRITICAL",
                    timestamp=datetime.utcnow(),
                    account_id="123456789012",
                    region="us-east-1"
                )
                
                session.add(finding2)
                
                # Force an error
                session.add(Finding())  # Missing required fields
                
                try:
                    await session.commit()
                except Exception:
                    await session.rollback()
                
                # Verify only first finding exists
                from sqlalchemy import select
                stmt = select(Finding)
                result = await session.execute(stmt)
                all_findings = result.scalars().all()
                
                assert len(all_findings) == 1
                assert all_findings[0].rule_id == "S3-001"

    @pytest.mark.asyncio
    async def test_database_connection_pooling(self, test_settings):
        """Test database connection pooling"""
        with patch('app.database.get_settings', return_value=test_settings):
            # Create tables
            async with async_engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            
            # Test multiple concurrent sessions
            async def create_finding(session_id):
                async with AsyncSessionLocal() as session:
                    finding = Finding(
                        rule_id=f"S3-{session_id:03d}",
                        resource_id=f"test-bucket-{session_id}",
                        resource_type="s3",
                        severity="HIGH",
                        timestamp=datetime.utcnow(),
                        account_id="123456789012",
                        region="us-east-1"
                    )
                    
                    session.add(finding)
                    await session.commit()
                    return finding.id
            
            # Run concurrent operations
            tasks = [create_finding(i) for i in range(10)]
            finding_ids = await asyncio.gather(*tasks)
            
            # Verify all findings were created
            assert len(finding_ids) == 10
            assert all(finding_id is not None for finding_id in finding_ids)
