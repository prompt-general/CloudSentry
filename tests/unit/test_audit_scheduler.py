import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import asyncio
from datetime import datetime, timedelta

from app.scheduler.audit_scheduler import AuditScheduler
from app.models import AuditLog, Finding
import uuid


class TestAuditScheduler:
    """Test audit scheduler functionality"""

    @pytest.fixture
    def audit_scheduler(self, test_settings):
        """Create audit scheduler instance"""
        with patch('app.scheduler.audit_scheduler.get_settings') as mock_settings:
            mock_settings.return_value = test_settings
            return AuditScheduler()

    @pytest.fixture
    def mock_db_session(self):
        """Mock database session"""
        session = AsyncMock()
        session.add.return_value = None
        session.commit.return_value = None
        session.refresh.return_value = None
        session.execute.return_value = AsyncMock()
        session.query.return_value.filter.return_value.all.return_value = []
        return session

    @pytest.fixture
    def sample_accounts(self):
        """Sample AWS accounts for testing"""
        return [
            {
                'id': '123456789012',
                'name': 'Production Account',
                'email': 'prod@example.com',
                'status': 'ACTIVE'
            },
            {
                'id': '123456789013',
                'name': 'Development Account',
                'email': 'dev@example.com',
                'status': 'ACTIVE'
            }
        ]

    @pytest.mark.asyncio
    async def test_init_scheduler(self, audit_scheduler):
        """Test scheduler initialization"""
        with patch('celery.Celery') as mock_celery:
            mock_celery_instance = MagicMock()
            mock_celery.return_value = mock_celery_instance
            
            init_scheduler()
            
            mock_celery.assert_called_once()
            mock_celery_instance.conf.update.assert_called()

    @pytest.mark.asyncio
    async def test_run_security_audit_success(self, audit_scheduler, mock_db_session, sample_accounts):
        """Test successful security audit execution"""
        with patch('app.scheduler.audit_scheduler.AsyncSessionLocal') as mock_session_local, \
             patch.object(audit_scheduler, '_get_aws_accounts') as mock_get_accounts, \
             patch.object(audit_scheduler, '_audit_account') as mock_audit_account:
            
            mock_session_local.return_value.__aenter__.return_value = mock_db_session
            mock_get_accounts.return_value = sample_accounts
            mock_audit_account.return_value = [Finding(id=uuid.uuid4(), rule_id="S3-001", severity="HIGH")]
            
            audit_log = await audit_scheduler.run_security_audit("full")
            
            assert audit_log.status == "COMPLETED"
            assert audit_log.findings_count == 2  # 2 accounts * 1 finding each
            mock_db_session.add.assert_called()
            mock_db_session.commit.assert_called()

    @pytest.mark.asyncio
    async def test_run_security_audit_failure(self, audit_scheduler, mock_db_session):
        """Test security audit failure handling"""
        with patch('app.scheduler.audit_scheduler.AsyncSessionLocal') as mock_session_local, \
             patch.object(audit_scheduler, '_get_aws_accounts') as mock_get_accounts:
            
            mock_session_local.return_value.__aenter__.return_value = mock_db_session
            mock_get_accounts.side_effect = Exception("AWS API error")
            
            audit_log = await audit_scheduler.run_security_audit("full")
            
            assert audit_log.status == "FAILED"
            assert "AWS API error" in audit_log.error_message
            mock_db_session.add.assert_called()
            mock_db_session.commit.assert_called()

    @pytest.mark.asyncio
    async def test_audit_account_success(self, audit_scheduler, mock_db_session):
        """Test successful account audit"""
        account = {
            'id': '123456789012',
            'name': 'Test Account',
            'email': 'test@example.com',
            'status': 'ACTIVE'
        }
        
        with patch.object(audit_scheduler, '_get_account_session') as mock_get_session, \
             patch.object(audit_scheduler, '_run_security_rules') as mock_rules:
            
            mock_session = MagicMock()
            mock_get_session.return_value = mock_session
            mock_rules.return_value = [
                Finding(id=uuid.uuid4(), rule_id="S3-001", severity="HIGH"),
                Finding(id=uuid.uuid4(), rule_id="IAM-001", severity="CRITICAL")
            ]
            
            findings = await audit_scheduler._audit_account(account, "full")
            
            assert len(findings) == 2
            mock_get_session.assert_called_with('123456789012')
            mock_rules.assert_called_with(mock_session, account)

    @pytest.mark.asyncio
    async def test_audit_account_session_failure(self, audit_scheduler):
        """Test account audit with session failure"""
        account = {
            'id': '123456789012',
            'name': 'Test Account',
            'status': 'ACTIVE'
        }
        
        with patch.object(audit_scheduler, '_get_account_session') as mock_get_session:
            mock_get_session.side_effect = Exception("Session creation failed")
            
            findings = await audit_scheduler._audit_account(account, "full")
            
            assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_run_security_rules(self, audit_scheduler):
        """Test security rule execution"""
        mock_session = MagicMock()
        account = {
            'id': '123456789012',
            'name': 'Test Account',
            'region': 'us-east-1'
        }
        
        with patch.object(audit_scheduler, '_check_s3_security') as mock_s3, \
             patch.object(audit_scheduler, '_check_iam_security') as mock_iam, \
             patch.object(audit_scheduler, '_check_ec2_security') as mock_ec2:
            
            mock_s3.return_value = [Finding(id=uuid.uuid4(), rule_id="S3-001", severity="HIGH")]
            mock_iam.return_value = [Finding(id=uuid.uuid4(), rule_id="IAM-001", severity="CRITICAL")]
            mock_ec2.return_value = []  # No findings
            
            findings = await audit_scheduler._run_security_rules(mock_session, account)
            
            assert len(findings) == 2
            assert any(f.rule_id == "S3-001" for f in findings)
            assert any(f.rule_id == "IAM-001" for f in findings)

    @pytest.mark.asyncio
    async def test_check_s3_security_findings(self, audit_scheduler):
        """Test S3 security checks"""
        mock_session = MagicMock()
        account = {
            'id': '123456789012',
            'name': 'Test Account',
            'region': 'us-east-1'
        }
        
        # Mock S3 client response
        mock_s3_client = MagicMock()
        mock_s3_client.list_buckets.return_value = {
            'Buckets': [
                {'Name': 'public-bucket'},
                {'Name': 'private-bucket'}
            ]
        }
        
        # Mock bucket ACL check
        mock_s3_client.get_bucket_acl.return_value = {
            'Grants': [
                {
                    'Grantee': {'Type': 'AllUsers'},
                    'Permission': 'READ'
                }
            ]
        }
        
        mock_session.client.return_value = mock_s3_client
        
        findings = await audit_scheduler._check_s3_security(mock_session, account)
        
        assert len(findings) >= 1  # At least one finding for public bucket
        assert any(f.rule_id.startswith("S3-") for f in findings)

    @pytest.mark.asyncio
    async def test_check_iam_security_findings(self, audit_scheduler):
        """Test IAM security checks"""
        mock_session = MagicMock()
        account = {
            'id': '123456789012',
            'name': 'Test Account',
            'region': 'us-east-1'
        }
        
        # Mock IAM client response
        mock_iam_client = MagicMock()
        mock_iam_client.get_account_authorization_details.return_value = {
            'UserDetailList': [
                {
                    'UserName': 'test-user',
                    'CreateDate': datetime.utcnow(),
                    'AttachedManagedPolicies': []
                }
            ],
            'GroupDetailList': [],
            'RoleDetailList': [],
            'Policies': []
        }
        
        mock_session.client.return_value = mock_iam_client
        
        findings = await audit_scheduler._check_iam_security(mock_session, account)
        
        # Should generate findings for any security issues
        assert isinstance(findings, list)

    @pytest.mark.asyncio
    async def test_check_ec2_security_findings(self, audit_scheduler):
        """Test EC2 security checks"""
        mock_session = MagicMock()
        account = {
            'id': '123456789012',
            'name': 'Test Account',
            'region': 'us-east-1'
        }
        
        # Mock EC2 client response
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
        
        findings = await audit_scheduler._check_ec2_security(mock_session, account)
        
        # Should generate finding for open SSH access
        assert len(findings) >= 1
        assert any(f.rule_id.startswith("EC2-") for f in findings)

    @pytest.mark.asyncio
    async def test_get_aws_accounts_multi_account_enabled(self, audit_scheduler, sample_accounts):
        """Test getting AWS accounts when multi-account is enabled"""
        audit_scheduler.settings.enable_multi_account = True
        
        with patch.object(audit_scheduler, '_organizations_manager') as mock_org_manager:
            mock_org_manager.get_all_accounts.return_value = sample_accounts
            
            accounts = await audit_scheduler._get_aws_accounts()
            
            assert len(accounts) == 2
            assert accounts[0]['id'] == '123456789012'
            assert accounts[1]['id'] == '123456789013'

    @pytest.mark.asyncio
    async def test_get_aws_accounts_multi_account_disabled(self, audit_scheduler):
        """Test getting AWS accounts when multi-account is disabled"""
        audit_scheduler.settings.enable_multi_account = False
        
        accounts = await audit_scheduler._get_aws_accounts()
        
        assert len(accounts) == 1
        assert accounts[0]['id'] == 'master'
        assert accounts[0]['name'] == 'Master Account'

    @pytest.mark.asyncio
    async def test_get_account_session(self, audit_scheduler):
        """Test getting account session"""
        with patch.object(audit_scheduler, '_organizations_manager') as mock_org_manager:
            mock_session = MagicMock()
            mock_org_manager.get_account_session.return_value = mock_session
            
            session = await audit_scheduler._get_account_session('123456789012')
            
            assert session == mock_session
            mock_org_manager.get_account_session.assert_called_with('123456789012')

    @pytest.mark.asyncio
    async def test_schedule_audit_task(self, audit_scheduler):
        """Test scheduling audit task"""
        with patch('app.scheduler.audit_scheduler.celery_app') as mock_celery:
            mock_task = MagicMock()
            mock_celery.send_task.return_value = mock_task
            
            task_id = audit_scheduler.schedule_audit("full", schedule_in_minutes=60)
            
            assert task_id is not None
            mock_celery.send_task.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_scheduled_audits(self, audit_scheduler, mock_db_session):
        """Test getting scheduled audits"""
        # Mock database query response
        mock_audit_logs = [
            AuditLog(
                id=uuid.uuid4(),
                audit_type="security",
                status="SCHEDULED",
                start_time=datetime.utcnow() + timedelta(hours=1)
            ),
            AuditLog(
                id=uuid.uuid4(),
                audit_type="security", 
                status="COMPLETED",
                start_time=datetime.utcnow() - timedelta(hours=1)
            )
        ]
        
        mock_db_session.query.return_value.filter.return_value.all.return_value = mock_audit_logs
        
        with patch('app.scheduler.audit_scheduler.AsyncSessionLocal') as mock_session_local:
            mock_session_local.return_value.__aenter__.return_value = mock_db_session
            
            audits = await audit_scheduler.get_scheduled_audits()
            
            assert len(audits) == 2
            assert audits[0].status == "SCHEDULED"
            assert audits[1].status == "COMPLETED"

    @pytest.mark.asyncio
    async def test_cancel_scheduled_audit(self, audit_scheduler, mock_db_session):
        """Test canceling scheduled audit"""
        audit_id = uuid.uuid4()
        
        # Mock existing audit log
        mock_audit_log = AuditLog(
            id=audit_id,
            audit_type="security",
            status="SCHEDULED",
            start_time=datetime.utcnow() + timedelta(hours=1)
        )
        
        mock_db_session.query.return_value.filter.return_value.first.return_value = mock_audit_log
        
        with patch('app.scheduler.audit_scheduler.AsyncSessionLocal') as mock_session_local, \
             patch('app.scheduler.audit_scheduler.celery_app') as mock_celery:
            
            mock_session_local.return_value.__aenter__.return_value = mock_db_session
            mock_celery.control.revoke.return_value = None
            
            result = await audit_scheduler.cancel_scheduled_audit(audit_id)
            
            assert result is True
            assert mock_audit_log.status == "CANCELLED"
            mock_db_session.commit.assert_called()

    @pytest.mark.asyncio
    async def test_get_audit_statistics(self, audit_scheduler, mock_db_session):
        """Test getting audit statistics"""
        # Mock statistics query
        mock_stats = {
            'total_audits': 100,
            'completed_audits': 80,
            'failed_audits': 5,
            'scheduled_audits': 15,
            'avg_findings_per_audit': 3.5
        }
        
        mock_db_session.execute.return_value.fetchall.return_value = [
            (100,), (80,), (5,), (15,), (3.5,)
        ]
        
        with patch('app.scheduler.audit_scheduler.AsyncSessionLocal') as mock_session_local:
            mock_session_local.return_value.__aenter__.return_value = mock_db_session
            
            stats = await audit_scheduler.get_audit_statistics()
            
            assert stats['total_audits'] == 100
            assert stats['completed_audits'] == 80
            assert stats['failed_audits'] == 5
            assert stats['scheduled_audits'] == 15
            assert stats['avg_findings_per_audit'] == 3.5
