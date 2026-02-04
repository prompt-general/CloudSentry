import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
import boto3
import aioredis
from datetime import datetime
import json

from app.config import get_settings
from app.database import AsyncSessionLocal
from app.models import Finding
from app.notifier import notify_new_finding
from app.engine.rules.base_rule import BaseRule
from app.aws.organizations import AWSOrganizationsManager

logger = logging.getLogger(__name__)

class Rule(ABC):
    """Base class for all security rules"""
    
    def __init__(self, rule_id: str, description: str, severity: str):
        self.rule_id = rule_id
        self.description = description
        self.severity = severity
        self.settings = get_settings()
        self.org_manager = AWSOrganizationsManager()
        
        # AWS session for this rule
        self.aws_session = boto3.Session(
            region_name=self.settings.aws_region,
            aws_access_key_id=self.settings.aws_access_key_id,
            aws_secret_access_key=self.settings.aws_secret_access_key
        )
    
    @abstractmethod
    async def evaluate(self, event: Dict[str, Any], resource_state: Dict[str, Any]) -> Optional[Finding]:
        """Evaluate the event and resource state for security issues"""
        pass
    
    def get_aws_client(self, account_id: str, service_name: str, region: str = None):
        """Get an AWS client for a specific account and region"""
        try:
            # Get session for the account
            session = asyncio.run(self.org_manager.get_account_session(account_id))
            
            # Use provided region or default
            client_region = region or self.settings.aws_region
            
            return session.client(service_name, region_name=client_region)
            
        except Exception as e:
            logger.error(f"Error getting AWS client for account {account_id}: {e}")
            # Fall back to master account
            return self.aws_session.client(service_name, region_name=region or self.settings.aws_region)
    
    async def fetch_resource_state(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Fetch the current state of the affected resource"""
        account_id = event.get('account_id', 'master')
        resource_state = {'account_id': account_id}
        
        try:
            if event.get('resource_type') == 's3':
                bucket_name = event.get('resource_id')
                if bucket_name:
                    s3_client = self.get_aws_client(account_id, 's3')
                    
                    # Get bucket policy
                    try:
                        policy_response = s3_client.get_bucket_policy(Bucket=bucket_name)
                        resource_state['policy'] = policy_response.get('Policy')
                    except s3_client.exceptions.NoSuchBucketPolicy:
                        resource_state['policy'] = None
                    except Exception as e:
                        logger.error(f"Error getting bucket policy: {e}")
                        resource_state['policy'] = None
                    
                    # Get bucket ACL
                    try:
                        acl_response = s3_client.get_bucket_acl(Bucket=bucket_name)
                        resource_state['acl'] = acl_response
                    except Exception as e:
                        logger.error(f"Error getting bucket ACL: {e}")
                        resource_state['acl'] = None
            
            elif event.get('resource_type') == 'security-group':
                sg_id = event.get('resource_id')
                if sg_id:
                    ec2_client = self.get_aws_client(account_id, 'ec2', event.get('region'))
                    
                    try:
                        response = ec2_client.describe_security_groups(GroupIds=[sg_id])
                        resource_state['security_group'] = response.get('SecurityGroups', [])[0] if response.get('SecurityGroups') else None
                    except Exception as e:
                        logger.error(f"Error getting security group: {e}")
                        resource_state['security_group'] = None
        
        except Exception as e:
            logger.error(f"Error fetching resource state: {e}")
        
        return resource_state


class RuleEngine:
    """Main rule engine that evaluates events against security rules"""
    
    def __init__(self):
        self.settings = get_settings()
        self.rules: List[BaseRule] = []
        self.redis = None
        self._load_rules()
    
    async def connect_redis(self):
        """Connect to Redis for real-time streaming"""
        self.redis = await aioredis.from_url(
            self.settings.redis_url,
            decode_responses=True
        )
    
    def _load_rules(self):
        """Load all available security rules for all cloud providers"""
        try:
            # AWS Rules
            from app.engine.rules.s3_rules import S3BucketPublicReadRule
            from app.engine.rules.ec2_rules import EC2SecurityGroupOpenSSHRule
            from app.engine.rules.ec2_rules import EC2SecurityGroupOpenRDPRule
            from app.engine.rules.iam_rules import IAMUserNoMFARule
            
            # Azure Rules
            from app.engine.rules.azure_rules import (
                AzureStoragePublicAccessRule,
                AzureNSGOpenSSHRule,
                AzureVMNoDiskEncryptionRule,
                AzureKeyVaultNoFirewallRule,
                AzureSQLServerNoFirewallRule,
                AzureStorageNoHTTPSRule
            )
            
            # GCP Rules
            from app.engine.rules.gcp_rules import (
                GCPBucketPublicAccessRule,
                GCPFirewallOpenSSHRule,
                GCPInstanceNoServiceAccountRule,
                GCPBucketNoVersioningRule,
                GCPKMSKeyNoRotationRule,
                GCPBucketNoLoggingRule,
                GCPPublicCloudSQLRule,
                GCPDefaultNetworkRule
            )
            
            self.rules = [
                # AWS Rules
                S3BucketPublicReadRule(),
                EC2SecurityGroupOpenSSHRule(),
                EC2SecurityGroupOpenRDPRule(),
                IAMUserNoMFARule(),
                
                # Azure Rules
                AzureStoragePublicAccessRule(),
                AzureNSGOpenSSHRule(),
                AzureVMNoDiskEncryptionRule(),
                AzureKeyVaultNoFirewallRule(),
                AzureSQLServerNoFirewallRule(),
                AzureStorageNoHTTPSRule(),
                
                # GCP Rules
                GCPBucketPublicAccessRule(),
                GCPFirewallOpenSSHRule(),
                GCPInstanceNoServiceAccountRule(),
                GCPBucketNoVersioningRule(),
                GCPKMSKeyNoRotationRule(),
                GCPBucketNoLoggingRule(),
                GCPPublicCloudSQLRule(),
                GCPDefaultNetworkRule()
            ]
            
            logger.info(f"Loaded {len(self.rules)} security rules across AWS, Azure, and GCP")
            
        except ImportError as e:
            logger.error(f"Error loading rules: {e}")
            self.rules = []
    
    async def evaluate_event(self, event: Dict[str, Any]):
        """Evaluate a single event against all rules"""
        findings = []
        
        for rule in self.rules:
            try:
                # Check if rule is applicable to this event type
                if not self._is_rule_applicable(rule, event):
                    continue
                
                # Fetch current resource state
                resource_state = await rule.fetch_resource_state(event)
                
                # Evaluate the rule
                finding = await rule.evaluate(event, resource_state)
                
                if finding:
                    findings.append(finding)
                    logger.info(f"Rule {rule.rule_id} triggered for {event.get('resource_id', 'unknown')}")
                    
            except Exception as e:
                logger.error(f"Error evaluating rule {rule.rule_id}: {e}")
                continue
        
        # Process all findings
        for finding in findings:
            await self._process_finding(finding)
    
    def _is_rule_applicable(self, rule: BaseRule, event: Dict[str, Any]) -> bool:
        """Check if a rule is applicable to the given event"""
        # Check cloud provider match
        event_cloud = event.get('cloud_provider', 'aws')
        if rule.cloud_provider != event_cloud:
            return False
        
        # Check resource type match
        resource_type = event.get('resource_type', '').lower()
        rule_resource_types = [rt.lower() for rt in rule.resource_types]
        
        # Check if any rule resource type matches
        for rule_type in rule_resource_types:
            if rule_type in resource_type or resource_type in rule_type:
                return True
        
        # Azure specific type mapping
        if event_cloud == 'azure':
            azure_type = event.get('raw_event', {}).get('resourceType', '')
            if azure_type in rule.resource_types:
                return True
        
        # GCP specific type mapping
        if event_cloud == 'gcp':
            # Check GCP service name
            service_name = event.get('event_source', '')
            if service_name in rule.resource_types:
                return True
            
            # Check GCP resource type from resource_name
            resource_name = event.get('resource_id', '')
            if resource_name and any(rt in resource_name for rt in rule.resource_types):
                return True
        
        return False
    
    async def _process_finding(self, finding: Finding):
        """Process and store a finding"""
        # Store in database
        
        # Publish to Redis for real-time streaming
        await self._publish_finding(finding)
        
        # Send notifications for high/critical findings
        if finding.severity in ['HIGH', 'CRITICAL']:
            finding_dict = finding.to_dict()
            asyncio.create_task(notify_new_finding(finding_dict))
    
    async def _store_finding(self, finding: Finding):
        """Store finding in database"""
        try:
            async with AsyncSessionLocal() as session:
                session.add(finding)
                await session.commit()
                logger.debug(f"Stored finding: {finding.rule_id} for {finding.resource_id}")
        except Exception as e:
            logger.error(f"Error storing finding: {e}")
    
    async def _publish_finding(self, finding: Finding):
        """Publish finding to Redis for real-time streaming"""
        try:
            if not self.redis:
                await self.connect_redis()
            
            # Convert finding to dict
            finding_dict = {
                'id': str(finding.id),
                'rule_id': finding.rule_id,
                'resource_id': finding.resource_id,
                'resource_type': finding.resource_type,
                'severity': finding.severity,
                'timestamp': finding.timestamp.isoformat() if finding.timestamp else None,
                'account_id': finding.account_id,
                'region': finding.region
            }
            
            # Publish to Redis channel
            await self.redis.publish('cloudsentry:findings', json.dumps(finding_dict))
            logger.debug(f"Published finding to Redis: {finding.rule_id}")
            
        except Exception as e:
            logger.error(f"Error publishing finding to Redis: {e}")
    
    async def _check_notifications(self, finding: Finding):
        """Check if notification should be sent for this finding"""
        # High severity findings trigger notifications
        if finding.severity in ['HIGH', 'CRITICAL']:
            logger.info(f"High severity finding: {finding.rule_id} - {finding.resource_id}")
            # Notification logic will be implemented separately
            pass
    
    async def run_full_audit(self, account_id: str = None):
        """Run a full audit of AWS resources"""
        logger.info("Starting full audit...")
        
        # This will be implemented in the scheduler
        # For now, log that it's called
        pass


# Global rule engine instance
rule_engine = RuleEngine()