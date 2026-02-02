import asyncio
import logging
from typing import List, Dict, Any, Optional
import boto3
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError, BotoCoreError

from app.config import get_settings

logger = logging.getLogger(__name__)

class AWSOrganizationsManager:
    """Manage multiple AWS accounts via Organizations"""
    
    def __init__(self):
        self.settings = get_settings()
        self.accounts_cache = {}
        self.last_refresh = None
        
        # Master account session
        self.master_session = boto3.Session(
            region_name=self.settings.aws_region,
            aws_access_key_id=self.settings.aws_access_key_id,
            aws_secret_access_key=self.settings.aws_secret_access_key
        )
    
    async def get_all_accounts(self, force_refresh: bool = False) -> List[Dict[str, Any]]:
        """Get all AWS accounts in the organization"""
        
        # Cache accounts for 1 hour
        if not force_refresh and self.accounts_cache:
            import time
            if time.time() - self.last_refresh < 3600:
                return list(self.accounts_cache.values())
        
        try:
            org_client = self.master_session.client('organizations')
            accounts = []
            
            # Paginate through accounts
            paginator = org_client.get_paginator('list_accounts')
            for page in paginator.paginate():
                for account in page.get('Accounts', []):
                    # Filter out suspended accounts
                    if account.get('Status') == 'ACTIVE':
                        accounts.append({
                            'id': account.get('Id'),
                            'arn': account.get('Arn'),
                            'email': account.get('Email'),
                            'name': account.get('Name'),
                            'status': account.get('Status'),
                            'joined_method': account.get('JoinedMethod'),
                            'joined_timestamp': account.get('JoinedTimestamp')
                        })
            
            # Cache the results
            self.accounts_cache = {acc['id']: acc for acc in accounts}
            self.last_refresh = time.time()
            
            logger.info(f"Found {len(accounts)} active AWS accounts")
            return accounts
            
        except NoCredentialsError:
            logger.error("AWS credentials not found - please configure credentials")
            raise
        except PartialCredentialsError:
            logger.error("Incomplete AWS credentials - please check your configuration")
            raise
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'AccessDeniedException':
                logger.error("Access denied to AWS Organizations API - check IAM permissions")
            elif error_code == 'OrganizationsNotInUseException':
                logger.warning("AWS Organizations not enabled - returning master account only")
                return await self._get_master_account_fallback()
            else:
                logger.error(f"AWS Organizations API error: {e}")
            raise
        except BotoCoreError as e:
            logger.error(f"AWS SDK error: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error fetching AWS accounts: {e}")
            # Last resort fallback
            return await self._get_master_account_fallback()
    
    async def _get_master_account_fallback(self) -> List[Dict[str, Any]]:
        """Fallback method to return master account info"""
        try:
            master_account_id = self._get_master_account_id()
            return [{
                'id': master_account_id or 'master',
                'name': 'Master Account',
                'email': 'master@example.com',
                'status': 'ACTIVE'
            }]
        except Exception as e:
            logger.error(f"Failed to get master account info: {e}")
            return []
    
    async def get_account_session(self, account_id: str, role_name: str = "CloudSentryAuditRole"):
        """Assume role in target account and return session"""
        
        # If this is the master account, return master session
        if account_id == 'master' or account_id == self._get_master_account_id():
            return self.master_session
        
        try:
            sts_client = self.master_session.client('sts')
            
            # Assume role in target account
            role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
            
            response = sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName=f"CloudSentry-{account_id}",
                DurationSeconds=3600  # 1 hour
            )
            
            credentials = response['Credentials']
            
            # Create session with assumed role
            session = boto3.Session(
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken'],
                region_name=self.settings.aws_region
            )
            
            logger.debug(f"Assumed role in account {account_id}")
            return session
            
        except ClientError as e:
            logger.error(f"Failed to assume role in account {account_id}: {e}")
            raise
    
    def _get_master_account_id(self) -> Optional[str]:
        """Get the master account ID"""
        try:
            sts_client = self.master_session.client('sts')
            identity = sts_client.get_caller_identity()
            return identity.get('Account')
        except Exception as e:
            logger.error(f"Error getting master account ID: {e}")
            return None
    
    async def get_account_regions(self, account_id: str) -> List[str]:
        """Get enabled regions for an account"""
        try:
            session = await self.get_account_session(account_id)
            ec2_client = session.client('ec2', region_name='us-east-1')
            
            response = ec2_client.describe_regions(
                AllRegions=False  # Only enabled regions
            )
            
            regions = [region['RegionName'] for region in response.get('Regions', [])]
            return regions
            
        except Exception as e:
            logger.error(f"Error getting regions for account {account_id}: {e}")
            # Return default regions
            return ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2']
