import json
import logging
from typing import Dict, Any, Optional
import boto3

from app.engine.rules.base_rule import BaseRule
from app.models import Finding

logger = logging.getLogger(__name__)

class S3BucketPublicReadRule(BaseRule):
    """Detects S3 buckets with public read access"""
    
    def __init__(self):
        super().__init__(
            rule_id="S3-001",
            description="S3 bucket allows public read access",
            severity="HIGH",
            resource_types=["s3"]
        )
        
        self.s3_client = None
    
    def get_remediation_steps(self) -> str:
        return """1. Navigate to the S3 bucket in AWS Console
2. Click on 'Permissions' tab
3. Edit the bucket policy to remove 'Principal': '*'
4. Alternatively, use AWS CLI: aws s3api delete-bucket-policy --bucket <bucket-name>
5. Enable Block Public Access settings for the bucket"""
    
    async def evaluate(self, event: Dict[str, Any], resource_state: Dict[str, Any]) -> Optional[Finding]:
        try:
            bucket_name = event.get('resource_id')
            if not bucket_name:
                return None
            
            # Get bucket policy
            if not self.s3_client:
                self.s3_client = boto3.client('s3')
            
            try:
                policy_response = self.s3_client.get_bucket_policy(Bucket=bucket_name)
                policy = json.loads(policy_response.get('Policy', '{}'))
                
                # Check for public read access
                if self._policy_allows_public_read(policy):
                    return self.create_finding(event)
                    
            except self.s3_client.exceptions.NoSuchBucketPolicy:
                # No policy means no explicit public access (good)
                pass
            except Exception as e:
                logger.error(f"Error checking bucket policy for {bucket_name}: {e}")
            
            # Check bucket ACL
            try:
                acl = self.s3_client.get_bucket_acl(Bucket=bucket_name)
                if self._acl_allows_public_read(acl):
                    return self.create_finding(event)
            except Exception as e:
                logger.error(f"Error checking bucket ACL for {bucket_name}: {e}")
            
            return None
            
        except Exception as e:
            logger.error(f"Error in S3BucketPublicReadRule: {e}")
            return None
    
    def _policy_allows_public_read(self, policy: Dict[str, Any]) -> bool:
        """Check if policy allows public read access"""
        try:
            statements = policy.get('Statement', [])
            if not isinstance(statements, list):
                statements = [statements]
            
            for statement in statements:
                # Check for Allow effect
                if statement.get('Effect') != 'Allow':
                    continue
                
                # Check for public principal
                principal = statement.get('Principal', {})
                if principal == '*' or principal.get('AWS') == '*':
                    # Check for read actions
                    actions = statement.get('Action', [])
                    if not isinstance(actions, list):
                        actions = [actions]
                    
                    read_actions = ['s3:GetObject', 's3:GetObject*', 's3:*', '*']
                    for action in actions:
                        if any(read_action in str(action) for read_action in read_actions):
                            return True
                            
        except Exception as e:
            logger.error(f"Error parsing policy: {e}")
        
        return False
    
    def _acl_allows_public_read(self, acl: Dict[str, Any]) -> bool:
        """Check if ACL allows public read"""
        try:
            grants = acl.get('Grants', [])
            for grant in grants:
                grantee = grant.get('Grantee', {})
                permission = grant.get('Permission', '')
                
                # Check for AllUsers or AuthenticatedUsers groups
                if grantee.get('Type') == 'Group':
                    uri = grantee.get('URI', '')
                    if 'AllUsers' in uri or 'AuthenticatedUsers' in uri:
                        if permission in ['READ', 'READ_ACP', 'FULL_CONTROL']:
                            return True
                            
        except Exception as e:
            logger.error(f"Error parsing ACL: {e}")
        
        return False


class S3BucketEncryptionRule(BaseRule):
    """Detects S3 buckets without encryption"""
    
    def __init__(self):
        super().__init__(
            rule_id="S3-002",
            description="S3 bucket has no encryption enabled",
            severity="MEDIUM",
            resource_types=["s3"]
        )
    
    def get_remediation_steps(self) -> str:
        return """1. Navigate to the S3 bucket in AWS Console
2. Click on 'Properties' tab
3. Scroll to 'Default encryption'
4. Click 'Edit' and enable encryption (SSE-S3 or SSE-KMS)
5. Apply the settings"""
    
    async def evaluate(self, event: Dict[str, Any], resource_state: Dict[str, Any]) -> Optional[Finding]:
        # Implementation for S3 encryption check
        # This would check if bucket encryption is enabled
        pass
