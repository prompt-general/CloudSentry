import asyncio
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any
import boto3
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import json

from app.database import AsyncSessionLocal
from app.models import Finding, AuditLog, RuleMetadata
from app.engine.rule_engine import RuleEngine
from app.engine.rules.s3_rules import S3BucketPublicReadRule, S3BucketEncryptionRule
from app.engine.rules.ec2_rules import EC2SecurityGroupOpenSSHRule, EC2SecurityGroupOpenRDPRule
from app.config import get_settings

logger = logging.getLogger(__name__)

class AuditScheduler:
    """Scheduler for periodic security audits"""
    
    def __init__(self):
        self.settings = get_settings()
        self.rule_engine = RuleEngine()
        self.running = False
        self.audit_tasks = {}
        
        # Initialize AWS session
        self.aws_session = boto3.Session(
            region_name=self.settings.aws_region,
            aws_access_key_id=self.settings.aws_access_key_id,
            aws_secret_access_key=self.settings.aws_secret_access_key
        )
    
    async def start(self):
        """Start the scheduler"""
        self.running = True
        logger.info("Audit scheduler started")
        
        # Schedule periodic audits
        asyncio.create_task(self.schedule_periodic_audits())
    
    async def stop(self):
        """Stop the scheduler"""
        self.running = False
        logger.info("Audit scheduler stopped")
    
    async def schedule_periodic_audits(self):
        """Schedule periodic full audits"""
        while self.running:
            try:
                # Run full audit every X hours (configurable)
                await asyncio.sleep(self.settings.full_audit_interval_hours * 3600)
                
                if self.running:
                    logger.info("Starting scheduled full audit")
                    await self.run_full_audit()
                    
            except Exception as e:
                logger.error(f"Error in scheduled audit: {e}")
                await asyncio.sleep(300)  # Wait 5 minutes before retrying
    
    async def run_full_audit(self, account_id: str = None, resource_type: str = None):
        """Run a full security audit"""
        audit_id = None
        
        try:
            # Create audit log
            async with AsyncSessionLocal() as session:
                audit_log = AuditLog(
                    audit_type='full',
                    account_id=account_id,
                    start_time=datetime.utcnow(),
                    status='RUNNING'
                )
                session.add(audit_log)
                await session.commit()
                await session.refresh(audit_log)
                audit_id = str(audit_log.id)
            
            logger.info(f"Starting full audit {audit_id}")
            
            # Run audits based on resource type
            findings_count = 0
            
            if not resource_type or resource_type == 's3':
                findings_count += await self.audit_s3_buckets(account_id)
            
            if not resource_type or resource_type in ['ec2', 'security-group']:
                findings_count += await self.audit_ec2_security_groups(account_id)
            
            if not resource_type or resource_type == 'iam':
                findings_count += await self.audit_iam_users(account_id)
            
            # Update audit log
            async with AsyncSessionLocal() as session:
                query = select(AuditLog).where(AuditLog.id == audit_id)
                result = await session.execute(query)
                audit_log = result.scalar_one()
                
                audit_log.status = 'COMPLETED'
                audit_log.end_time = datetime.utcnow()
                audit_log.findings_count = findings_count
                
                await session.commit()
            
            logger.info(f"Full audit {audit_id} completed with {findings_count} findings")
            return audit_id
            
        except Exception as e:
            logger.error(f"Error in full audit: {e}")
            
            # Update audit log with error
            if audit_id:
                async with AsyncSessionLocal() as session:
                    query = select(AuditLog).where(AuditLog.id == audit_id)
                    result = await session.execute(query)
                    audit_log = result.scalar_one()
                    
                    audit_log.status = 'FAILED'
                    audit_log.end_time = datetime.utcnow()
                    audit_log.error_message = str(e)
                    
                    await session.commit()
            
            raise
    
    async def audit_s3_buckets(self, account_id: str = None) -> int:
        """Audit all S3 buckets in the account"""
        try:
            s3_client = self.aws_session.client('s3')
            findings_count = 0
            
            # List all buckets
            response = s3_client.list_buckets()
            buckets = response.get('Buckets', [])
            
            logger.info(f"Auditing {len(buckets)} S3 buckets")
            
            # Get bucket locations and audit each
            for bucket in buckets:
                bucket_name = bucket['Name']
                
                try:
                    # Get bucket location (region)
                    location_response = s3_client.get_bucket_location(Bucket=bucket_name)
                    bucket_region = location_response.get('LocationConstraint') or 'us-east-1'
                    
                    # Create event for rule evaluation
                    event = {
                        'resource_id': bucket_name,
                        'resource_type': 's3',
                        'account_id': account_id,
                        'region': bucket_region,
                        'event_time': datetime.utcnow()
                    }
                    
                    # Check public read access
                    public_read_rule = S3BucketPublicReadRule()
                    resource_state = await public_read_rule.fetch_resource_state(event)
                    finding = await public_read_rule.evaluate(event, resource_state)
                    
                    if finding:
                        await self.rule_engine._process_finding(finding)
                        findings_count += 1
                    
                    # Check encryption (if we implement it)
                    # encryption_rule = S3BucketEncryptionRule()
                    # finding = await encryption_rule.evaluate(event, {})
                    # if finding:
                    #     await self.rule_engine._process_finding(finding)
                    #     findings_count += 1
                    
                except Exception as e:
                    logger.error(f"Error auditing bucket {bucket_name}: {e}")
                    continue
            
            logger.info(f"S3 audit found {findings_count} issues")
            return findings_count
            
        except Exception as e:
            logger.error(f"Error in S3 audit: {e}")
            return 0
    
    async def audit_ec2_security_groups(self, account_id: str = None) -> int:
        """Audit all EC2 security groups in the account"""
        try:
            ec2_client = self.aws_session.client('ec2')
            findings_count = 0
            
            # Describe all security groups
            response = ec2_client.describe_security_groups()
            security_groups = response.get('SecurityGroups', [])
            
            logger.info(f"Auditing {len(security_groups)} security groups")
            
            for sg in security_groups:
                sg_id = sg['GroupId']
                sg_name = sg.get('GroupName', '')
                
                try:
                    # Check for open SSH
                    ssh_rule = EC2SecurityGroupOpenSSHRule()
                    
                    event = {
                        'resource_id': sg_id,
                        'resource_type': 'security-group',
                        'account_id': account_id,
                        'region': self.settings.aws_region,
                        'event_time': datetime.utcnow(),
                        'raw_event': {
                            'requestParameters': {
                                'ipPermissions': {
                                    'items': sg.get('IpPermissions', [])
                                }
                            }
                        }
                    }
                    
                    finding = await ssh_rule.evaluate(event, {})
                    if finding:
                        await self.rule_engine._process_finding(finding)
                        findings_count += 1
                    
                    # Check for open RDP
                    rdp_rule = EC2SecurityGroupOpenRDPRule()
                    finding = await rdp_rule.evaluate(event, {})
                    if finding:
                        await self.rule_engine._process_finding(finding)
                        findings_count += 1
                    
                except Exception as e:
                    logger.error(f"Error auditing security group {sg_id}: {e}")
                    continue
            
            logger.info(f"EC2 security group audit found {findings_count} issues")
            return findings_count
            
        except Exception as e:
            logger.error(f"Error in EC2 security group audit: {e}")
            return 0
    
    async def audit_iam_users(self, account_id: str = None) -> int:
        """Audit IAM users in the account"""
        try:
            iam_client = self.aws_session.client('iam')
            findings_count = 0
            
            # List all IAM users
            response = iam_client.list_users()
            users = response.get('Users', [])
            
            logger.info(f"Auditing {len(users)} IAM users")
            
            # Note: IAM rules would be implemented here
            # For now, just log that we're auditing
            
            return findings_count
            
        except Exception as e:
            logger.error(f"Error in IAM audit: {e}")
            return 0
    
    async def run_targeted_audit(self, resource_ids: List[str], resource_type: str):
        """Run audit on specific resources"""
        # Implementation for targeted audits
        pass


# Global scheduler instance
scheduler = AuditScheduler()

async def start_scheduler():
    """Start the audit scheduler"""
    await scheduler.start()

async def trigger_manual_audit(audit_type: str = 'full', account_id: str = None, resource_type: str = None):
    """Trigger a manual audit"""
    if audit_type == 'full':
        return await scheduler.run_full_audit(account_id, resource_type)
    else:
        raise ValueError(f"Unsupported audit type: {audit_type}")

def init_scheduler():
    """Initialize scheduler (called on app startup)"""
    # Start scheduler in background
    asyncio.create_task(start_scheduler())