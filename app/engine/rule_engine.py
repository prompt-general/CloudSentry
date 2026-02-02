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

logger = logging.getLogger(__name__)

class Rule(ABC):
    """Base class for all security rules"""
    
    def __init__(self, rule_id: str, description: str, severity: str):
        self.rule_id = rule_id
        self.description = description
        self.severity = severity
        self.settings = get_settings()
        
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
    
    def get_aws_client(self, service_name: str):
        """Get an AWS client for the given service"""
        return self.aws_session.client(service_name)
    
    async def fetch_resource_state(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Fetch the current state of the affected resource"""
        # Base implementation returns empty state
        # Override in specific rules if needed
        return {}


class RuleEngine:
    """Main rule engine that evaluates events against security rules"""
    
    def __init__(self):
        self.settings = get_settings()
        self.rules: List[Rule] = []
        self.redis = None
        self._load_rules()
    
    async def connect_redis(self):
        """Connect to Redis for real-time streaming"""
        self.redis = await aioredis.from_url(
            self.settings.redis_url,
            decode_responses=True
        )
    
    def _load_rules(self):
        """Load all available security rules"""
        # Dynamically import and instantiate rules
        try:
            from app.engine.rules.s3_rules import S3BucketPublicReadRule
            from app.engine.rules.ec2_rules import EC2SecurityGroupOpenSSHRule
            from app.engine.rules.ec2_rules import EC2SecurityGroupOpenRDPRule
            from app.engine.rules.iam_rules import IAMUserNoMFARule
            
            self.rules = [
                S3BucketPublicReadRule(),
                EC2SecurityGroupOpenSSHRule(),
                EC2SecurityGroupOpenRDPRule(),
                IAMUserNoMFARule()
            ]
            
            logger.info(f"Loaded {len(self.rules)} security rules")
            
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
    
    def _is_rule_applicable(self, rule: Rule, event: Dict[str, Any]) -> bool:
        """Check if a rule is applicable to the given event"""
        # Check resource type match (basic filter)
        resource_type = event.get('resource_type', '').lower()
        
        # Each rule can override this method for more specific filtering
        # For now, use simple type-based filtering
        rule_name = rule.__class__.__name__.lower()
        
        if 's3' in rule_name and resource_type == 's3':
            return True
        elif 'ec2' in rule_name and resource_type in ['ec2', 'security-group']:
            return True
        elif 'iam' in rule_name and resource_type == 'iam':
            return True
        
        return False
    
    async def _process_finding(self, finding: Finding):
        """Process and store a finding"""
        # Store in database
        await self._store_finding(finding)
        
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