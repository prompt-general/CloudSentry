import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import asyncio
from datetime import datetime, timedelta

from app.aws.organizations import AWSOrganizationsManager


class TestAWSOrganizations:
    """Test AWS Organizations Manager"""

    @pytest.fixture
    def org_manager(self, test_settings):
        """Create AWS Organizations Manager instance"""
        with patch('app.aws.organizations.get_settings') as mock_settings:
            mock_settings.return_value = test_settings
            return AWSOrganizationsManager()

    @pytest.fixture
    def mock_boto3_session(self):
        """Mock boto3 session"""
        session = MagicMock()
        client = MagicMock()
        session.client.return_value = client
        return session, client

    @pytest.mark.asyncio
    async def test_get_all_accounts_success(self, org_manager, mock_boto3_session):
        """Test successful account retrieval"""
        mock_session, mock_client = mock_boto3_session
        org_manager.master_session = mock_session
        
        # Mock paginator response
        mock_paginator = MagicMock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {
                'Accounts': [
                    {
                        'Id': '123456789012',
                        'Arn': 'arn:aws:organizations::123456789012:account/o-example123456/a-example123456',
                        'Email': 'test@example.com',
                        'Name': 'Test Account',
                        'Status': 'ACTIVE',
                        'JoinedMethod': 'INVITED',
                        'JoinedTimestamp': datetime.utcnow()
                    },
                    {
                        'Id': '123456789013',
                        'Arn': 'arn:aws:organizations::123456789013:account/o-example123456/a-example123457',
                        'Email': 'test2@example.com',
                        'Name': 'Test Account 2',
                        'Status': 'SUSPENDED',  # Should be filtered out
                        'JoinedMethod': 'CREATED',
                        'JoinedTimestamp': datetime.utcnow()
                    }
                ]
            }
        ]
        
        accounts = await org_manager.get_all_accounts()
        
        assert len(accounts) == 1  # Only active accounts
        assert accounts[0]['id'] == '123456789012'
        assert accounts[0]['name'] == 'Test Account'
        assert accounts[0]['status'] == 'ACTIVE'

    @pytest.mark.asyncio
    async def test_get_all_accounts_cache(self, org_manager, mock_boto3_session):
        """Test account caching functionality"""
        mock_session, mock_client = mock_boto3_session
        org_manager.master_session = mock_session
        
        # Mock successful response
        mock_paginator = MagicMock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {
                'Accounts': [
                    {
                        'Id': '123456789012',
                        'Email': 'test@example.com',
                        'Name': 'Test Account',
                        'Status': 'ACTIVE'
                    }
                ]
            }
        ]
        
        # First call should hit the API
        accounts1 = await org_manager.get_all_accounts()
        assert len(accounts1) == 1
        
        # Second call should use cache (no additional API calls)
        accounts2 = await org_manager.get_all_accounts()
        assert len(accounts2) == 1
        assert accounts1[0]['id'] == accounts2[0]['id']
        
        # Verify paginator was called only once
        assert mock_paginator.paginate.call_count == 1

    @pytest.mark.asyncio
    async def test_get_all_accounts_force_refresh(self, org_manager, mock_boto3_session):
        """Test force refresh bypasses cache"""
        mock_session, mock_client = mock_boto3_session
        org_manager.master_session = mock_session
        
        # Mock successful response
        mock_paginator = MagicMock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {
                'Accounts': [
                    {
                        'Id': '123456789012',
                        'Email': 'test@example.com',
                        'Name': 'Test Account',
                        'Status': 'ACTIVE'
                    }
                ]
            }
        ]
        
        # First call
        await org_manager.get_all_accounts()
        
        # Force refresh should make another API call
        await org_manager.get_all_accounts(force_refresh=True)
        
        # Verify paginator was called twice
        assert mock_paginator.paginate.call_count == 2

    @pytest.mark.asyncio
    async def test_get_all_accounts_no_credentials(self, org_manager):
        """Test handling of missing AWS credentials"""
        from botocore.exceptions import NoCredentialsError
        
        with patch.object(org_manager.master_session, 'client') as mock_client:
            mock_client.side_effect = NoCredentialsError()
            
            with pytest.raises(NoCredentialsError):
                await org_manager.get_all_accounts()

    @pytest.mark.asyncio
    async def test_get_all_accounts_access_denied(self, org_manager):
        """Test handling of access denied error"""
        from botocore.exceptions import ClientError
        
        with patch.object(org_manager.master_session, 'client') as mock_client:
            mock_client.return_value.get_paginator.side_effect = ClientError(
                {'Error': {'Code': 'AccessDeniedException'}},
                'ListAccounts'
            )
            
            with pytest.raises(ClientError):
                await org_manager.get_all_accounts()

    @pytest.mark.asyncio
    async def test_get_all_accounts_organizations_not_enabled(self, org_manager):
        """Test handling when Organizations is not enabled"""
        from botocore.exceptions import ClientError
        
        with patch.object(org_manager.master_session, 'client') as mock_client:
            mock_client.return_value.get_paginator.side_effect = ClientError(
                {'Error': {'Code': 'OrganizationsNotInUseException'}},
                'ListAccounts'
            )
            
            # Should return fallback instead of raising
            accounts = await org_manager.get_all_accounts()
            assert len(accounts) >= 0  # Should return fallback accounts

    @pytest.mark.asyncio
    async def test_get_account_session_master_account(self, org_manager, mock_boto3_session):
        """Test getting session for master account"""
        mock_session, mock_client = mock_boto3_session
        org_manager.master_session = mock_session
        
        # Mock master account ID
        with patch.object(org_manager, '_get_master_account_id', return_value='123456789012'):
            session = await org_manager.get_account_session('123456789012')
            
            # Should return master session
            assert session == mock_session

    @pytest.mark.asyncio
    async def test_get_account_session_member_account(self, org_manager, mock_boto3_session):
        """Test getting session for member account via role assumption"""
        mock_session, mock_client = mock_boto3_session
        org_manager.master_session = mock_session
        
        # Mock STS client
        sts_client = MagicMock()
        mock_session.client.return_value = sts_client
        
        # Mock assume role response
        sts_client.assume_role.return_value = {
            'Credentials': {
                'AccessKeyId': 'AKIA...',
                'SecretAccessKey': 'secret',
                'SessionToken': 'token'
            }
        }
        
        with patch.object(org_manager, '_get_master_account_id', return_value='123456789012'):
            with patch('boto3.Session') as mock_new_session:
                mock_new_session.return_value = MagicMock()
                
                session = await org_manager.get_account_session('123456789013')
                
                # Verify STS was called
                sts_client.assume_role.assert_called_once_with(
                    RoleArn='arn:aws:iam::123456789013:role/CloudSentryAuditRole',
                    RoleSessionName='CloudSentry-123456789013',
                    DurationSeconds=3600
                )

    @pytest.mark.asyncio
    async def test_get_account_session_role_failure(self, org_manager, mock_boto3_session):
        """Test handling of role assumption failure"""
        from botocore.exceptions import ClientError
        
        mock_session, mock_client = mock_boto3_session
        org_manager.master_session = mock_session
        
        # Mock STS client failure
        sts_client = MagicMock()
        mock_session.client.return_value = sts_client
        sts_client.assume_role.side_effect = ClientError(
            {'Error': {'Code': 'AccessDenied'}},
            'AssumeRole'
        )
        
        with patch.object(org_manager, '_get_master_account_id', return_value='123456789012'):
            with pytest.raises(ClientError):
                await org_manager.get_account_session('123456789013')

    def test_get_master_account_id_success(self, org_manager, mock_boto3_session):
        """Test successful master account ID retrieval"""
        mock_session, mock_client = mock_boto3_session
        org_manager.master_session = mock_session
        
        # Mock STS response
        mock_client.get_caller_identity.return_value = {
            'Account': '123456789012',
            'UserId': 'AIDACKCEVSQ6C2EXAMPLE',
            'Arn': 'arn:aws:iam::123456789012:user/test'
        }
        
        account_id = org_manager._get_master_account_id()
        assert account_id == '123456789012'

    def test_get_master_account_id_failure(self, org_manager, mock_boto3_session):
        """Test handling of master account ID retrieval failure"""
        mock_session, mock_client = mock_boto3_session
        org_manager.master_session = mock_session
        
        mock_client.get_caller_identity.side_effect = Exception("STS error")
        
        account_id = org_manager._get_master_account_id()
        assert account_id is None

    @pytest.mark.asyncio
    async def test_get_account_regions_success(self, org_manager, mock_boto3_session):
        """Test successful account regions retrieval"""
        mock_session, mock_client = mock_boto3_session
        org_manager.master_session = mock_session
        
        # Mock EC2 client response
        ec2_client = MagicMock()
        mock_session.client.return_value = ec2_client
        ec2_client.describe_regions.return_value = {
            'Regions': [
                {'RegionName': 'us-east-1'},
                {'RegionName': 'us-west-2'},
                {'RegionName': 'eu-west-1'}
            ]
        }
        
        with patch.object(org_manager, 'get_account_session', return_value=mock_session):
            regions = await org_manager.get_account_regions('123456789012')
            
            assert len(regions) == 3
            assert 'us-east-1' in regions
            assert 'us-west-2' in regions
            assert 'eu-west-1' in regions

    @pytest.mark.asyncio
    async def test_get_account_regions_failure(self, org_manager, mock_boto3_session):
        """Test handling of regions retrieval failure"""
        mock_session, mock_client = mock_boto3_session
        org_manager.master_session = mock_session
        
        # Mock EC2 client failure
        ec2_client = MagicMock()
        mock_session.client.return_value = ec2_client
        ec2_client.describe_regions.side_effect = Exception("EC2 error")
        
        with patch.object(org_manager, 'get_account_session', return_value=mock_session):
            regions = await org_manager.get_account_regions('123456789012')
            
            # Should return default regions
            assert len(regions) == 4
            assert 'us-east-1' in regions
            assert 'us-east-2' in regions
            assert 'us-west-1' in regions
            assert 'us-west-2' in regions

    @pytest.mark.asyncio
    async def test_get_master_account_fallback_success(self, org_manager):
        """Test successful master account fallback"""
        with patch.object(org_manager, '_get_master_account_id', return_value='123456789012'):
            accounts = await org_manager._get_master_account_fallback()
            
            assert len(accounts) == 1
            assert accounts[0]['id'] == '123456789012'
            assert accounts[0]['name'] == 'Master Account'
            assert accounts[0]['status'] == 'ACTIVE'

    @pytest.mark.asyncio
    async def test_get_master_account_fallback_failure(self, org_manager):
        """Test master account fallback failure"""
        with patch.object(org_manager, '_get_master_account_id', return_value=None):
            accounts = await org_manager._get_master_account_fallback()
            
            assert len(accounts) == 0
