import logging
from typing import Dict, Any, Optional
import boto3

from app.engine.rules.base_rule import BaseRule
from app.models import Finding

logger = logging.getLogger(__name__)

class EC2SecurityGroupOpenSSHRule(BaseRule):
    """Detects security groups allowing SSH from 0.0.0.0/0"""
    
    def __init__(self):
        super().__init__(
            rule_id="EC2-001",
            description="Security group allows SSH from 0.0.0.0/0",
            severity="HIGH",
            resource_types=["ec2", "security-group"]
        )
    
    def get_remediation_steps(self) -> str:
        return """1. Identify the security group in AWS Console
2. Remove the ingress rule allowing SSH (port 22) from 0.0.0.0/0
3. Restrict SSH access to specific IP ranges or use a bastion host
4. Consider using AWS Systems Manager Session Manager instead of SSH"""
    
    async def evaluate(self, event: Dict[str, Any], resource_state: Dict[str, Any]) -> Optional[Finding]:
        try:
            # This rule would typically run during full audits
            # For real-time events, check for AuthorizeSecurityGroupIngress events
            
            if event.get('event_name') == 'AuthorizeSecurityGroupIngress':
                request_params = event.get('raw_event', {}).get('requestParameters', {})
                
                # Check if this is adding SSH access
                ip_permissions = request_params.get('ipPermissions', {})
                items = ip_permissions.get('items', [])
                
                for item in items:
                    if (item.get('fromPort') == 22 and item.get('toPort') == 22 and 
                        item.get('ipProtocol') in ['tcp', '6', '-1']):
                        
                        ip_ranges = item.get('ipRanges', {}).get('items', [])
                        for ip_range in ip_ranges:
                            if ip_range.get('cidrIp') == '0.0.0.0/0':
                                return self.create_finding(event)
            
            return None
            
        except Exception as e:
            logger.error(f"Error in EC2SecurityGroupOpenSSHRule: {e}")
            return None


class EC2SecurityGroupOpenRDPRule(BaseRule):
    """Detects security groups allowing RDP from 0.0.0.0/0"""
    
    def __init__(self):
        super().__init__(
            rule_id="EC2-002",
            description="Security group allows RDP from 0.0.0.0/0",
            severity="HIGH",
            resource_types=["ec2", "security-group"]
        )
    
    def get_remediation_steps(self) -> str:
        return """1. Identify the security group in AWS Console
2. Remove the ingress rule allowing RDP (port 3389) from 0.0.0.0/0
3. Restrict RDP access to specific IP ranges
4. Consider using AWS Client VPN or AWS SSO for remote access"""
    
    async def evaluate(self, event: Dict[str, Any], resource_state: Dict[str, Any]) -> Optional[Finding]:
        try:
            if event.get('event_name') == 'AuthorizeSecurityGroupIngress':
                request_params = event.get('raw_event', {}).get('requestParameters', {})
                
                ip_permissions = request_params.get('ipPermissions', {})
                items = ip_permissions.get('items', [])
                
                for item in items:
                    if (item.get('fromPort') == 3389 and item.get('toPort') == 3389 and 
                        item.get('ipProtocol') in ['tcp', '6', '-1']):
                        
                        ip_ranges = item.get('ipRanges', {}).get('items', [])
                        for ip_range in ip_ranges:
                            if ip_range.get('cidrIp') == '0.0.0.0/0':
                                return self.create_finding(event)
            
            return None
            
        except Exception as e:
            logger.error(f"Error in EC2SecurityGroupOpenRDPRule: {e}")
            return None
