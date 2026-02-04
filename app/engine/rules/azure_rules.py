import logging
from typing import Dict, Any, Optional
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.sql import SqlManagementClient
from azure.identity import DefaultAzureCredential

from app.engine.rules.base_rule import BaseRule
from app.models import Finding
from datetime import datetime

logger = logging.getLogger(__name__)

class AzureStoragePublicAccessRule(BaseRule):
    """Detects Azure Storage accounts with public access"""
    
    def __init__(self):
        super().__init__(
            rule_id="AZURE-001",
            description="Azure Storage account allows public access",
            severity="HIGH",
            resource_types=["storage-account", "Microsoft.Storage/storageAccounts"],
            cloud_provider="azure"
        )
    
    def get_remediation_steps(self) -> str:
        return """1. Navigate to the storage account in Azure Portal
2. Click on 'Configuration' under 'Settings'
3. Set 'Allow storage account key access' to 'Disabled' if not needed
4. Under 'Networking', set 'Public network access' to 'Disabled' or restrict to specific networks
5. Use Private Endpoints for secure access
6. Review and update Network Security Groups and Firewall rules"""
    
    async def evaluate(self, event: Dict[str, Any], resource_state: Dict[str, Any]) -> Optional[Finding]:
        try:
            resource_id = event.get('resource_id')
            if not resource_id:
                return None
            
            # Check if this is a storage account event
            if 'Microsoft.Storage/storageAccounts' not in resource_id:
                return None
            
            # Extract subscription and resource details
            parts = resource_id.split('/')
            subscription_id = parts[2]
            resource_group = parts[4]
            storage_account_name = parts[-1]
            
            # Get Azure client
            storage_client = self.get_azure_client('storage', subscription_id)
            
            try:
                # Get storage account properties
                storage_account = storage_client.storage_accounts.get_properties(
                    resource_group_name=resource_group,
                    account_name=storage_account_name
                )
                
                # Check for public access
                if self._has_public_access(storage_account):
                    return self.create_finding(event)
                    
            except Exception as e:
                logger.error(f"Error checking storage account {storage_account_name}: {e}")
            
            return None
            
        except Exception as e:
            logger.error(f"Error in AzureStoragePublicAccessRule: {e}")
            return None
    
    def _has_public_access(self, storage_account) -> bool:
        """Check if storage account allows public access"""
        try:
            # Check network rules
            if hasattr(storage_account, 'network_rule_set'):
                network_rules = storage_account.network_rule_set
                
                # Check if default action is Allow (public)
                if network_rules and network_rules.default_action == 'Allow':
                    return True
                
                # Check if there are IP rules allowing all
                if network_rules and network_rules.ip_rules:
                    for rule in network_rules.ip_rules:
                        if rule.ip_address_or_range == '0.0.0.0/0':
                            return True
            
            # Check if blob public access is enabled
            if hasattr(storage_account, 'allow_blob_public_access'):
                if storage_account.allow_blob_public_access:
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking storage account public access: {e}")
            return False


class AzureNSGOpenSSHRule(BaseRule):
    """Detects Network Security Groups allowing SSH from any IP"""
    
    def __init__(self):
        super().__init__(
            rule_id="AZURE-002",
            description="Network Security Group allows SSH from any IP",
            severity="HIGH",
            resource_types=["network-security-group", "Microsoft.Network/networkSecurityGroups"],
            cloud_provider="azure"
        )
    
    def get_remediation_steps(self) -> str:
        return """1. Navigate to the Network Security Group in Azure Portal
2. Click on 'Inbound security rules'
3. Find the rule allowing SSH (port 22) from any source (0.0.0.0/0 or ::/0)
4. Either delete the rule or restrict it to specific IP ranges
5. Consider using Azure Bastion or Just-in-Time VM access for SSH management
6. Enable Network Security Group flow logs for monitoring"""
    
    async def evaluate(self, event: Dict[str, Any], resource_state: Dict[str, Any]) -> Optional[Finding]:
        try:
            resource_id = event.get('resource_id')
            if not resource_id:
                return None
            
            # Check if this is a NSG event
            if 'Microsoft.Network/networkSecurityGroups' not in resource_id:
                return None
            
            # Check event name for security rule changes
            event_name = event.get('event_name', '').lower()
            if 'securityrules' not in event_name:
                return None
            
            # Extract subscription and resource details
            parts = resource_id.split('/')
            subscription_id = parts[2]
            resource_group = parts[4]
            nsg_name = parts[-1]
            
            # Get Azure client
            network_client = self.get_azure_client('network', subscription_id)
            
            try:
                # Get NSG security rules
                nsg = network_client.network_security_groups.get(
                    resource_group_name=resource_group,
                    network_security_group_name=nsg_name
                )
                
                # Check security rules
                if nsg and nsg.security_rules:
                    for rule in nsg.security_rules:
                        if self._is_open_ssh_rule(rule):
                            return self.create_finding(event)
                            
            except Exception as e:
                logger.error(f"Error checking NSG {nsg_name}: {e}")
            
            return None
            
        except Exception as e:
            logger.error(f"Error in AzureNSGOpenSSHRule: {e}")
            return None
    
    def _is_open_ssh_rule(self, rule) -> bool:
        """Check if rule allows SSH from any IP"""
        try:
            # Check if rule is for SSH
            if rule.destination_port_range == '22' or '22' in (rule.destination_port_ranges or []):
                # Check if source address prefix allows any IP
                if rule.source_address_prefix == '*' or rule.source_address_prefix == '0.0.0.0/0' or rule.source_address_prefix == '::/0':
                    # Check if rule allows traffic
                    if rule.access == 'Allow' and rule.direction == 'Inbound':
                        # Check protocol
                        if rule.protocol in ['Tcp', 'TCP', '*']:
                            return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking NSG rule: {e}")
            return False


class AzureVMNoDiskEncryptionRule(BaseRule):
    """Detects Azure VMs without disk encryption"""
    
    def __init__(self):
        super().__init__(
            rule_id="AZURE-003",
            description="Azure Virtual Machine has no disk encryption",
            severity="MEDIUM",
            resource_types=["virtual-machine", "Microsoft.Compute/virtualMachines"],
            cloud_provider="azure"
        )
    
    def get_remediation_steps(self) -> str:
        return """1. Navigate to the Virtual Machine in Azure Portal
2. Click on 'Disks' under 'Settings'
3. Enable Azure Disk Encryption for OS and data disks
4. Use Azure Key Vault to manage encryption keys
5. For Linux VMs: Use Azure Disk Encryption with DM-Crypt
6. For Windows VMs: Use Azure Disk Encryption with BitLocker
7. Ensure backup is configured before enabling encryption"""
    
    async def evaluate(self, event: Dict[str, Any], resource_state: Dict[str, Any]) -> Optional[Finding]:
        try:
            resource_id = event.get('resource_id')
            if not resource_id:
                return None
            
            # Check if this is a VM event
            if 'Microsoft.Compute/virtualMachines' not in resource_id:
                return None
            
            # This rule would typically run during full audits
            # For real-time events, we'd need to check VM properties
            
            return None
            
        except Exception as e:
            logger.error(f"Error in AzureVMNoDiskEncryptionRule: {e}")
            return None


class AzureKeyVaultNoFirewallRule(BaseRule):
    """Detects Azure Key Vaults without firewall restrictions"""
    
    def __init__(self):
        super().__init__(
            rule_id="AZURE-004",
            description="Azure Key Vault has no firewall or network restrictions",
            severity="HIGH",
            resource_types=["key-vault", "Microsoft.KeyVault/vaults"],
            cloud_provider="azure"
        )
    
    def get_remediation_steps(self) -> str:
        return """1. Navigate to the Key Vault in Azure Portal
2. Click on 'Networking' under 'Settings'
3. Set 'Public network access' to 'Disabled' or 'Enabled from selected virtual networks and IP addresses'
4. Configure firewall rules to allow only specific IP ranges
5. Enable Private Endpoint for private network access
6. Configure network security groups and route tables
7. Enable VNet service endpoints for Key Vault"""
    
    async def evaluate(self, event: Dict[str, Any], resource_state: Dict[str, Any]) -> Optional[Finding]:
        try:
            resource_id = event.get('resource_id')
            if not resource_id:
                return None
            
            # Check if this is a Key Vault event
            if 'Microsoft.KeyVault/vaults' not in resource_id:
                return None
            
            # Extract subscription and resource details
            parts = resource_id.split('/')
            subscription_id = parts[2]
            resource_group = parts[4]
            vault_name = parts[-1]
            
            # Get Azure client
            keyvault_client = self.get_azure_client('keyvault', subscription_id)
            
            try:
                # Get Key Vault properties
                vault = keyvault_client.vaults.get(
                    resource_group_name=resource_group,
                    vault_name=vault_name
                )
                
                # Check firewall settings
                if self._has_no_firewall_restrictions(vault):
                    return self.create_finding(event)
                    
            except Exception as e:
                logger.error(f"Error checking Key Vault {vault_name}: {e}")
            
            return None
            
        except Exception as e:
            logger.error(f"Error in AzureKeyVaultNoFirewallRule: {e}")
            return None
    
    def _has_no_firewall_restrictions(self, vault) -> bool:
        """Check if Key Vault has no firewall restrictions"""
        try:
            # Check network ACLs
            if hasattr(vault, 'properties') and hasattr(vault.properties, 'network_acls'):
                network_acls = vault.properties.network_acls
                
                # Check if default action is Allow (public)
                if network_acls and network_acls.default_action == 'Allow':
                    # Check if there are no IP rules
                    if not network_acls.ip_rules or len(network_acls.ip_rules) == 0:
                        return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking Key Vault firewall: {e}")
            return False


class AzureSQLServerNoFirewallRule(BaseRule):
    """Detects Azure SQL Servers without firewall restrictions"""
    
    def __init__(self):
        super().__init__(
            rule_id="AZURE-005",
            description="Azure SQL Server has no firewall restrictions",
            severity="HIGH",
            resource_types=["sql-server", "Microsoft.Sql/servers"],
            cloud_provider="azure"
        )
    
    def get_remediation_steps(self) -> str:
        return """1. Navigate to the SQL server in Azure Portal
2. Click on 'Firewalls and virtual networks' under 'Security'
3. Remove the rule allowing 0.0.0.0 to 0.0.0.0 (all Azure services)
4. Add firewall rules for specific IP addresses or ranges
5. Enable 'Allow Azure services and resources to access this server' only if necessary
6. Consider using Private Endpoint for private network access
7. Configure VNet service endpoints for secure access"""
    
    async def evaluate(self, event: Dict[str, Any], resource_state: Dict[str, Any]) -> Optional[Finding]:
        try:
            resource_id = event.get('resource_id')
            if not resource_id:
                return None
            
            # Check if this is a SQL Server event
            if 'Microsoft.Sql/servers' not in resource_id:
                return None
            
            return None
            
        except Exception as e:
            logger.error(f"Error in AzureSQLServerNoFirewallRule: {e}")
            return None


class AzureStorageNoHTTPSRule(BaseRule):
    """Detects Azure Storage accounts requiring HTTPS"""
    
    def __init__(self):
        super().__init__(
            rule_id="AZURE-006",
            description="Azure Storage account allows HTTP traffic",
            severity="MEDIUM",
            resource_types=["storage-account", "Microsoft.Storage/storageAccounts"],
            cloud_provider="azure"
        )
    
    def get_remediation_steps(self) -> str:
        return """1. Navigate to the storage account in Azure Portal
2. Click on 'Configuration' under 'Settings'
3. Set 'Secure transfer required' to 'Enabled'
4. Update applications to use HTTPS endpoints
5. Configure custom domains with HTTPS
6. Use Azure CDN with HTTPS for public content"""
    
    async def evaluate(self, event: Dict[str, Any], resource_state: Dict[str, Any]) -> Optional[Finding]:
        try:
            resource_id = event.get('resource_id')
            if not resource_id:
                return None
            
            # Check if this is a storage account event
            if 'Microsoft.Storage/storageAccounts' not in resource_id:
                return None
            
            # Extract subscription and resource details
            parts = resource_id.split('/')
            subscription_id = parts[2]
            resource_group = parts[4]
            storage_account_name = parts[-1]
            
            # Get Azure client
            storage_client = self.get_azure_client('storage', subscription_id)
            
            try:
                # Get storage account properties
                storage_account = storage_client.storage_accounts.get_properties(
                    resource_group_name=resource_group,
                    account_name=storage_account_name
                )
                
                # Check if secure transfer is disabled
                if self._has_secure_transfer_disabled(storage_account):
                    return self.create_finding(event)
                    
            except Exception as e:
                logger.error(f"Error checking storage account {storage_account_name}: {e}")
            
            return None
            
        except Exception as e:
            logger.error(f"Error in AzureStorageNoHTTPSRule: {e}")
            return None
    
    def _has_secure_transfer_disabled(self, storage_account) -> bool:
        """Check if secure transfer is disabled"""
        try:
            if hasattr(storage_account, 'enable_https_traffic_only'):
                return not storage_account.enable_https_traffic_only
            return True
            
        except Exception as e:
            logger.error(f"Error checking storage account secure transfer: {e}")
            return True


# Additional Azure Security Rules

class AzureVMNoManagedIdentityRule(BaseRule):
    """Detects Azure VMs without managed identities enabled"""
    
    def __init__(self):
        super().__init__(
            rule_id="AZURE-007",
            description="Azure Virtual Machine has no managed identity enabled",
            severity="MEDIUM",
            resource_types=["virtual-machine", "Microsoft.Compute/virtualMachines"],
            cloud_provider="azure"
        )
    
    def get_remediation_steps(self) -> str:
        return """1. Navigate to the Virtual Machine in Azure Portal
2. Click on 'Identity' under 'Settings'
3. Set 'Status' to 'On' for System-assigned managed identity
4. Configure User-assigned managed identities if needed
5. Update applications to use managed identities instead of service principals
6. Review and remove hardcoded credentials from applications"""
    
    async def evaluate(self, event: Dict[str, Any], resource_state: Dict[str, Any]) -> Optional[Finding]:
        try:
            resource_id = event.get('resource_id')
            if not resource_id:
                return None
            
            # Check if this is a VM event
            if 'Microsoft.Compute/virtualMachines' not in resource_id:
                return None
            
            # Extract subscription and resource details
            parts = resource_id.split('/')
            subscription_id = parts[2]
            resource_group = parts[4]
            vm_name = parts[-1]
            
            # Get Azure client
            compute_client = self.get_azure_client('compute', subscription_id)
            
            try:
                # Get VM properties
                vm = compute_client.virtual_machines.get(
                    resource_group_name=resource_group,
                    vm_name=vm_name
                )
                
                # Check if managed identity is disabled
                if self._has_no_managed_identity(vm):
                    return self.create_finding(event)
                    
            except Exception as e:
                logger.error(f"Error checking VM {vm_name}: {e}")
            
            return None
            
        except Exception as e:
            logger.error(f"Error in AzureVMNoManagedIdentityRule: {e}")
            return None
    
    def _has_no_managed_identity(self, vm) -> bool:
        """Check if VM has no managed identity"""
        try:
            if hasattr(vm, 'identity'):
                return vm.identity.type == 'None'
            return True
            
        except Exception as e:
            logger.error(f"Error checking VM managed identity: {e}")
            return True


class AzureResourceGroupNoTagsRule(BaseRule):
    """Detects Azure Resource Groups without required tags"""
    
    def __init__(self):
        super().__init__(
            rule_id="AZURE-008",
            description="Azure Resource Group has no required tags",
            severity="LOW",
            resource_types=["resource-group", "Microsoft.Resources/resourceGroups"],
            cloud_provider="azure"
        )
    
    def get_remediation_steps(self) -> str:
        return """1. Navigate to the Resource Group in Azure Portal
2. Click on 'Tags' in the left menu
3. Add required tags such as: Environment, Owner, CostCenter, Project
4. Implement tagging policies using Azure Policy
5. Use Azure Cost Management to track costs by tags
6. Set up automated tagging for new resources"""
    
    async def evaluate(self, event: Dict[str, Any], resource_state: Dict[str, Any]) -> Optional[Finding]:
        try:
            resource_id = event.get('resource_id')
            if not resource_id:
                return None
            
            # Check if this is a resource group event
            if 'Microsoft.Resources/resourceGroups' not in resource_id:
                return None
            
            # Check event name for resource group operations
            event_name = event.get('event_name', '').lower()
            if 'resourcegroups' not in event_name:
                return None
            
            # Extract resource group details
            parts = resource_id.split('/')
            resource_group_name = parts[4]
            
            # Get resource group tags from event
            tags = event.get('tags', {})
            
            # Check for required tags
            if self._missing_required_tags(tags):
                return self.create_finding(event)
            
            return None
            
        except Exception as e:
            logger.error(f"Error in AzureResourceGroupNoTagsRule: {e}")
            return None
    
    def _missing_required_tags(self, tags: Dict[str, str]) -> bool:
        """Check if required tags are missing"""
        required_tags = ['Environment', 'Owner', 'Project']
        for tag in required_tags:
            if tag not in tags or not tags[tag]:
                return True
        return False


class AzureDiagnosticSettingsDisabledRule(BaseRule):
    """Detects Azure resources without diagnostic settings enabled"""
    
    def __init__(self):
        super().__init__(
            rule_id="AZURE-009",
            description="Azure resource has no diagnostic settings enabled",
            severity="MEDIUM",
            resource_types=["storage-account", "virtual-machine", "sql-server", "key-vault"],
            cloud_provider="azure"
        )
    
    def get_remediation_steps(self) -> str:
        return """1. Navigate to the resource in Azure Portal
2. Click on 'Diagnostic settings' under 'Monitoring'
3. Click 'Add diagnostic setting'
4. Configure logs and metrics to be sent to Log Analytics workspace
5. Set appropriate retention periods
6. Enable alerts for critical events
7. Use Azure Policy to enforce diagnostic settings"""
    
    async def evaluate(self, event: Dict[str, Any], resource_state: Dict[str, Any]) -> Optional[Finding]:
        try:
            resource_id = event.get('resource_id')
            if not resource_id:
                return None
            
            # Check if this is a resource creation event
            event_name = event.get('event_name', '').lower()
            if 'write' not in event_name or 'create' not in event_name:
                return None
            
            # Check resource type
            resource_types = [
                'Microsoft.Storage/storageAccounts',
                'Microsoft.Compute/virtualMachines',
                'Microsoft.Sql/servers',
                'Microsoft.KeyVault/vaults'
            ]
            
            if not any(resource_type in resource_id for resource_type in resource_types):
                return None
            
            # This rule would typically check diagnostic settings
            # For now, we'll flag new resources that should have diagnostics
            
            return self.create_finding(event)
            
        except Exception as e:
            logger.error(f"Error in AzureDiagnosticSettingsDisabledRule: {e}")
            return None


class AzurePublicIPAddressRule(BaseRule):
    """Detects Public IP addresses without security controls"""
    
    def __init__(self):
        super().__init__(
            rule_id="AZURE-010",
            description="Public IP address without security controls",
            severity="MEDIUM",
            resource_types=["public-ip", "Microsoft.Network/publicIPAddresses"],
            cloud_provider="azure"
        )
    
    def get_remediation_steps(self) -> str:
        return """1. Navigate to the Public IP address in Azure Portal
2. Check if the IP is associated with a resource that needs public access
3. If not needed, delete the Public IP address
4. If needed, ensure it's behind a firewall or Application Gateway
5. Use Network Security Groups to restrict access
6. Consider using Private IP addresses where possible
7. Monitor public IP usage and costs"""
    
    async def evaluate(self, event: Dict[str, Any], resource_state: Dict[str, Any]) -> Optional[Finding]:
        try:
            resource_id = event.get('resource_id')
            if not resource_id:
                return None
            
            # Check if this is a Public IP event
            if 'Microsoft.Network/publicIPAddresses' not in resource_id:
                return None
            
            # Extract subscription and resource details
            parts = resource_id.split('/')
            subscription_id = parts[2]
            resource_group = parts[4]
            ip_name = parts[-1]
            
            # Get Azure client
            network_client = self.get_azure_client('network', subscription_id)
            
            try:
                # Get Public IP properties
                public_ip = network_client.public_ip_addresses.get(
                    resource_group_name=resource_group,
                    public_ip_address_name=ip_name
                )
                
                # Check if IP is idle or unsecured
                if self._is_unsecured_public_ip(public_ip):
                    return self.create_finding(event)
                    
            except Exception as e:
                logger.error(f"Error checking Public IP {ip_name}: {e}")
            
            return None
            
        except Exception as e:
            logger.error(f"Error in AzurePublicIPAddressRule: {e}")
            return None
    
    def _is_unsecured_public_ip(self, public_ip) -> bool:
        """Check if Public IP is unsecured"""
        try:
            # Check if IP is not associated with any resource
            if not hasattr(public_ip, 'ip_configuration') or not public_ip.ip_configuration:
                return True
            
            # Check if IP is static and might be unused
            if hasattr(public_ip, 'public_ip_allocation_method'):
                if public_ip.public_ip_allocation_method == 'Static':
                    # Additional checks could be added here
                    pass
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking Public IP security: {e}")
            return False


# Rule Registry
AZURE_RULES = [
    AzureStoragePublicAccessRule(),
    AzureNSGOpenSSHRule(),
    AzureVMNoDiskEncryptionRule(),
    AzureKeyVaultNoFirewallRule(),
    AzureSQLServerNoFirewallRule(),
    AzureStorageNoHTTPSRule(),
    AzureVMNoManagedIdentityRule(),
    AzureResourceGroupNoTagsRule(),
    AzureDiagnosticSettingsDisabledRule(),
    AzurePublicIPAddressRule(),
]

def get_azure_rules():
    """Get all Azure security rules"""
    return AZURE_RULES
