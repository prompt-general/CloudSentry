import json
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
import boto3

from app.models import Finding
from datetime import datetime

logger = logging.getLogger(__name__)

class BaseRule(ABC):
    """Enhanced base rule with common utilities"""
    
    def __init__(self, rule_id: str, description: str, severity: str, resource_types: list):
        self.rule_id = rule_id
        self.description = description
        self.severity = severity
        self.resource_types = resource_types
    
    def create_finding(self, event: Dict[str, Any], **kwargs) -> Finding:
        """Create a Finding object from event data"""
        return Finding(
            rule_id=self.rule_id,
            resource_id=event.get('resource_id', 'unknown'),
            resource_type=event.get('resource_type', 'unknown'),
            severity=self.severity,
            event_id=event.get('event_id', ''),
            timestamp=event.get('event_time', datetime.utcnow()),
            remediation_steps=self.get_remediation_steps(),
            account_id=event.get('account_id'),
            region=event.get('region')
        )
    
    @abstractmethod
    def get_remediation_steps(self) -> str:
        """Get remediation steps for this rule"""
        pass
