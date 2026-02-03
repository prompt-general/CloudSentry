import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
import boto3
from azure.identity import DefaultAzureCredential
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.keyvault import KeyVaultManagementClient

from app.models import Finding
from app.config import get_settings
from datetime import datetime

logger = logging.getLogger(__name__)

class BaseRule(ABC):
    """Enhanced base rule with multi-cloud support"""
    
    def __init__(self, rule_id: str, description: str, severity: str, resource_types: list, cloud_provider: str):
        self.rule_id = rule_id
        self.description = description
        self.severity = severity
        self.resource_types = resource_types
        self.cloud_provider = cloud_provider
        self.settings = get_settings()
        
        # Initialize cloud-specific clients
        self.aws_session = None
        self.azure_credential = None
    
    def get_aws_client(self, service_name: str, region: str = None):
        """Get an AWS client for the given service"""
        if not self.aws_session:
            self.aws_session = boto3.Session(
                region_name=region or self.settings.aws_region,
                aws_access_key_id=self.settings.aws_access_key_id,
                aws_secret_access_key=self.settings.aws_secret_access_key
            )
        
        return self.aws_session.client(service_name, region_name=region)
    
    def get_azure_client(self, service_type: str, subscription_id: str):
        """Get an Azure client for the given service"""
        if not self.azure_credential:
            self.azure_credential = DefaultAzureCredential()
        
        if service_type == 'storage':
            return StorageManagementClient(self.azure_credential, subscription_id)
        elif service_type == 'network':
            return NetworkManagementClient(self.azure_credential, subscription_id)
        elif service_type == 'compute':
            return ComputeManagementClient(self.azure_credential, subscription_id)
        elif service_type == 'keyvault':
            return KeyVaultManagementClient(self.azure_credential, subscription_id)
        else:
            raise ValueError(f"Unsupported Azure service type: {service_type}")
    
    def extract_azure_resource_info(self, resource_id: str) -> tuple:
        """Extract Azure resource group and name from resource ID"""
        parts = resource_id.split('/')
        if len(parts) >= 9:
            resource_group = parts[4]
            resource_name = parts[-1]
            return resource_group, resource_name
        return None, None
    
    def create_finding(self, event: Dict[str, Any], **kwargs) -> Finding:
        """Create a Finding object from event data"""
        from app.models import Finding
        
        return Finding(
            cloud_provider=self.cloud_provider,
            rule_id=self.rule_id,
            resource_id=event.get('resource_id', 'unknown'),
            resource_type=event.get('resource_type', 'unknown'),
            severity=self.severity,
            event_id=event.get('event_id', ''),
            timestamp=event.get('event_time', datetime.utcnow()),
            remediation_steps=self.get_remediation_steps(),
            account_id=event.get('account_id'),
            region=event.get('region'),
            **kwargs
        )
    
    @abstractmethod
    def get_remediation_steps(self) -> str:
        """Get remediation steps for this rule"""
        pass
    
    @abstractmethod
    async def evaluate(self, event: Dict[str, Any], resource_state: Dict[str, Any]) -> Optional[Finding]:
        """Evaluate the event and resource state for security issues"""
        pass
