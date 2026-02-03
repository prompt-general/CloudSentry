import pytest
import json
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime
from app.engine.azure_event_ingestor import AzureActivityLogNormalizer, AzureEventIngestor
from app.engine.rules.azure_rules import AzureStoragePublicAccessRule, AzureNSGOpenSSHRule, AzureKeyVaultNoFirewallRule

@pytest.fixture
def sample_azure_event():
    """Sample Azure Activity Log event for testing"""
    return {
        'id': 'test-azure-id',
        'operationName': {'value': 'Microsoft.Storage/storageAccounts/write'},
        'category': {'value': 'Write'},
        'eventTimestamp': '2024-01-15T12:00:00Z',
        'subscriptionId': 'test-sub-123',
        'tenantId': 'test-tenant-123',
        'resourceGroup': 'test-rg',
        'resourceId': '/subscriptions/test-sub-123/resourceGroups/test-rg/providers/Microsoft.Storage/storageAccounts/teststorage',
        'resourceLocation': 'eastus',
        'caller': 'testuser@example.com',
        'properties': {
            'statusCode': 'Created',
            'serviceRequestId': 'test-request-id'
        }
    }

@pytest.fixture
def sample_azure_nsg_event():
    """Sample Azure NSG event for testing"""
    return {
        'id': 'test-nsg-id',
        'operationName': {'value': 'Microsoft.Network/networkSecurityGroups/securityRules/write'},
        'category': {'value': 'Write'},
        'eventTimestamp': '2024-01-15T12:00:00Z',
        'subscriptionId': 'test-sub-123',
        'tenantId': 'test-tenant-123',
        'resourceGroup': 'test-rg',
        'resourceId': '/subscriptions/test-sub-123/resourceGroups/test-rg/providers/Microsoft.Network/networkSecurityGroups/test-nsg',
        'resourceLocation': 'eastus',
        'caller': 'testuser@example.com'
    }

@pytest.fixture
def sample_azure_keyvault_event():
    """Sample Azure Key Vault event for testing"""
    return {
        'id': 'test-kv-id',
        'operationName': {'value': 'Microsoft.KeyVault/vaults/write'},
        'category': {'value': 'Write'},
        'eventTimestamp': '2024-01-15T12:00:00Z',
        'subscriptionId': 'test-sub-123',
        'tenantId': 'test-tenant-123',
        'resourceGroup': 'test-rg',
        'resourceId': '/subscriptions/test-sub-123/resourceGroups/test-rg/providers/Microsoft.KeyVault/vaults/test-kv',
        'resourceLocation': 'eastus',
        'caller': 'testuser@example.com'
    }

class TestAzureActivityLogNormalizer:
    """Test Azure Activity Log event normalization"""
    
    def test_normalize_event_basic(self, sample_azure_event):
        """Test basic Azure event normalization"""
        normalized = AzureActivityLogNormalizer.normalize_event(sample_azure_event)
        
        assert normalized['cloud_provider'] == 'azure'
        assert normalized['event_id'] == 'test-azure-id'
        assert normalized['event_name'] == 'Microsoft.Storage/storageAccounts/write'
        assert normalized['event_source'] == 'Write'
        assert normalized['resource_id'] == '/subscriptions/test-sub-123/resourceGroups/test-rg/providers/Microsoft.Storage/storageAccounts/teststorage'
        assert normalized['resource_type'] == 'storageAccounts'
        assert normalized['resource_name'] == 'teststorage'
        assert normalized['account_id'] == 'test-sub-123'
        assert normalized['region'] == 'eastus'
        assert normalized['resource_group'] == 'test-rg'
        assert normalized['caller'] == 'testuser@example.com'
        assert normalized['tenant_id'] == 'test-tenant-123'
        assert 'raw_event' in normalized
        assert isinstance(normalized['event_time'], datetime)
    
    def test_normalize_event_missing_fields(self):
        """Test normalization with missing fields"""
        incomplete_event = {
            'id': 'test-id',
            'operationName': {'value': 'test-operation'},
            'category': {'value': 'test-category'}
        }
        
        normalized = AzureActivityLogNormalizer.normalize_event(incomplete_event)
        
        assert normalized['cloud_provider'] == 'azure'
        assert normalized['event_id'] == 'test-id'
        assert normalized['event_name'] == 'test-operation'
        assert normalized['event_source'] == 'test-category'
        assert normalized['resource_type'] == 'unknown'
        assert normalized['resource_name'] == 'unknown'
        assert normalized['account_id'] == ''
        assert normalized['region'] == ''
        assert normalized['resource_group'] == ''
    
    def test_extract_resource_info_storage(self):
        """Test Azure storage account resource extraction"""
        resource_id = '/subscriptions/sub-123/resourceGroups/rg-name/providers/Microsoft.Storage/storageAccounts/storage-name'
        
        resource_type, resource_name = AzureActivityLogNormalizer._extract_resource_info(resource_id)
        
        assert resource_type == 'storageAccounts'
        assert resource_name == 'storage-name'
    
    def test_extract_resource_info_vm(self):
        """Test Azure VM resource extraction"""
        resource_id = '/subscriptions/sub-123/resourceGroups/rg-name/providers/Microsoft.Compute/virtualMachines/vm-name'
        
        resource_type, resource_name = AzureActivityLogNormalizer._extract_resource_info(resource_id)
        
        assert resource_type == 'virtualMachines'
        assert resource_name == 'vm-name'
    
    def test_extract_resource_info_invalid(self):
        """Test resource extraction with invalid ID"""
        resource_id = 'invalid-resource-id'
        
        resource_type, resource_name = AzureActivityLogNormalizer._extract_resource_info(resource_id)
        
        assert resource_type == 'unknown'
        assert resource_name == 'invalid-resource-id'
    
    def test_extract_resource_info_short(self):
        """Test resource extraction with short ID"""
        resource_id = '/providers/test/type/name'
        
        resource_type, resource_name = AzureActivityLogNormalizer._extract_resource_info(resource_id)
        
        assert resource_type == 'type'
        assert resource_name == 'name'
    
    def test_map_azure_resource_type(self):
        """Test Azure resource type mapping"""
        # Test storage accounts
        storage_type = AzureActivityLogNormalizer.map_azure_resource_type('Microsoft.Storage/storageAccounts')
        assert storage_type == 'storage-account'
        
        # Test VMs
        vm_type = AzureActivityLogNormalizer.map_azure_resource_type('Microsoft.Compute/virtualMachines')
        assert vm_type == 'virtual-machine'
        
        # Test NSGs
        nsg_type = AzureActivityLogNormalizer.map_azure_resource_type('Microsoft.Network/networkSecurityGroups')
        assert nsg_type == 'network-security-group'
        
        # Test Key Vault
        kv_type = AzureActivityLogNormalizer.map_azure_resource_type('Microsoft.KeyVault/vaults')
        assert kv_type == 'key-vault'
        
        # Test unknown type
        unknown_type = AzureActivityLogNormalizer.map_azure_resource_type('Microsoft.Unknown/service')
        assert unknown_type == 'Microsoft.Unknown/service'

class TestAzureEventIngestor:
    """Test Azure event ingestor functionality"""
    
    @pytest.mark.asyncio
    async def test_ingestor_initialization(self):
        """Test Azure ingestor initialization"""
        ingestor = AzureEventIngestor()
        
        assert ingestor.running == False
        assert ingestor.rule_engine is not None
        assert ingestor.azure_credential is None
        assert ingestor.subscription_id is None
    
    @pytest.mark.asyncio
    async def test_generate_azure_test_events(self):
        """Test Azure test event generation"""
        ingestor = AzureEventIngestor()
        ingestor.running = True
        
        # Mock database session
        with patch('app.engine.azure_event_ingestor.AsyncSessionLocal') as mock_session:
            mock_session_instance = AsyncMock()
            mock_session.return_value.__aenter__.return_value = mock_session_instance
            mock_session_instance.add = Mock()
            mock_session_instance.commit = AsyncMock()
            
            # Mock rule engine
            with patch.object(ingestor.rule_engine, 'evaluate_event') as mock_evaluate:
                mock_evaluate.return_value = None
                
                await ingestor._generate_azure_test_events()
                
                # Verify test events were generated
                assert mock_session_instance.add.call_count == 3
                assert mock_evaluate.call_count == 3
    
    @pytest.mark.asyncio
    async def test_start_with_test_source(self):
        """Test starting ingestor with test source"""
        ingestor = AzureEventIngestor()
        
        with patch.object(ingestor, '_generate_azure_test_events') as mock_generate:
            mock_generate.return_value = None
            
            await ingestor.start('test')
            
            assert ingestor.running == True
            mock_generate.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_stop(self):
        """Test stopping the ingestor"""
        ingestor = AzureEventIngestor()
        ingestor.running = True
        
        ingestor.stop()
        
        assert ingestor.running == False

class TestAzureStoragePublicAccessRule:
    """Test Azure storage public access rule"""
    
    def test_rule_initialization(self):
        """Test rule initialization"""
        rule = AzureStoragePublicAccessRule()
        
        assert rule.rule_id == 'AZURE-001'
        assert rule.cloud_provider == 'azure'
        assert rule.severity == 'HIGH'
        assert 'storage-account' in rule.resource_types
        assert 'Microsoft.Storage/storageAccounts' in rule.resource_types
    
    @pytest.mark.asyncio
    async def test_evaluate_public_storage(self):
        """Test evaluation of storage account with public access"""
        rule = AzureStoragePublicAccessRule()
        
        event = {
            'cloud_provider': 'azure',
            'resource_id': '/subscriptions/sub-123/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/teststorage',
            'resource_type': 'storageAccounts',
            'event_id': 'test-001',
            'account_id': 'sub-123',
            'region': 'eastus',
            'event_time': datetime.utcnow()
        }
        
        # Mock Azure client with public access
        with patch.object(rule, 'get_azure_client') as mock_client:
            storage_mock = Mock()
            storage_account_mock = Mock()
            
            # Configure storage account with public access
            storage_account_mock.network_rule_set = Mock()
            storage_account_mock.network_rule_set.default_action = 'Allow'
            storage_account_mock.allow_blob_public_access = True
            
            storage_mock.storage_accounts.get_properties.return_value = storage_account_mock
            mock_client.return_value = storage_mock
            
            finding = await rule.evaluate(event, {})
            
            assert finding is not None
            assert finding.rule_id == 'AZURE-001'
            assert finding.severity == 'HIGH'
            assert finding.cloud_provider == 'azure'
            assert finding.resource_id == event['resource_id']
    
    @pytest.mark.asyncio
    async def test_evaluate_secure_storage(self):
        """Test evaluation of secure storage account"""
        rule = AzureStoragePublicAccessRule()
        
        event = {
            'cloud_provider': 'azure',
            'resource_id': '/subscriptions/sub-123/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/teststorage',
            'resource_type': 'storageAccounts',
            'event_id': 'test-001',
            'account_id': 'sub-123',
            'region': 'eastus',
            'event_time': datetime.utcnow()
        }
        
        # Mock Azure client with secure configuration
        with patch.object(rule, 'get_azure_client') as mock_client:
            storage_mock = Mock()
            storage_account_mock = Mock()
            
            # Configure storage account with secure settings
            storage_account_mock.network_rule_set = Mock()
            storage_account_mock.network_rule_set.default_action = 'Deny'
            storage_account_mock.allow_blob_public_access = False
            
            storage_mock.storage_accounts.get_properties.return_value = storage_account_mock
            mock_client.return_value = storage_mock
            
            finding = await rule.evaluate(event, {})
            
            assert finding is None
    
    @pytest.mark.asyncio
    async def test_evaluate_non_storage_event(self):
        """Test evaluation of non-storage event"""
        rule = AzureStoragePublicAccessRule()
        
        event = {
            'cloud_provider': 'azure',
            'resource_id': '/subscriptions/sub-123/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/testvm',
            'resource_type': 'virtualMachines',
            'event_id': 'test-001',
            'account_id': 'sub-123',
            'region': 'eastus',
            'event_time': datetime.utcnow()
        }
        
        finding = await rule.evaluate(event, {})
        
        assert finding is None
    
    def test_has_public_access_true(self):
        """Test public access detection - positive case"""
        storage_account_mock = Mock()
        storage_account_mock.network_rule_set = Mock()
        storage_account_mock.network_rule_set.default_action = 'Allow'
        storage_account_mock.allow_blob_public_access = True
        
        result = rule._has_public_access(storage_account_mock)
        assert result == True
    
    def test_has_public_access_false(self):
        """Test public access detection - negative case"""
        storage_account_mock = Mock()
        storage_account_mock.network_rule_set = Mock()
        storage_account_mock.network_rule_set.default_action = 'Deny'
        storage_account_mock.allow_blob_public_access = False
        
        result = rule._has_public_access(storage_account_mock)
        assert result == False

class TestAzureNSGOpenSSHRule:
    """Test Azure NSG SSH rule"""
    
    def test_rule_initialization(self):
        """Test NSG rule initialization"""
        rule = AzureNSGOpenSSHRule()
        
        assert rule.rule_id == 'AZURE-002'
        assert rule.cloud_provider == 'azure'
        assert rule.severity == 'HIGH'
        assert 'network-security-group' in rule.resource_types
    
    @pytest.mark.asyncio
    async def test_evaluate_open_ssh_rule(self, sample_azure_nsg_event):
        """Test evaluation of NSG with open SSH"""
        rule = AzureNSGOpenSSHRule()
        
        event = {
            'cloud_provider': 'azure',
            'resource_id': '/subscriptions/sub-123/resourceGroups/test-rg/providers/Microsoft.Network/networkSecurityGroups/test-nsg',
            'resource_type': 'networkSecurityGroups',
            'event_name': 'Microsoft.Network/networkSecurityGroups/securityRules/write',
            'event_id': 'test-002',
            'account_id': 'sub-123',
            'region': 'eastus',
            'event_time': datetime.utcnow()
        }
        
        # Mock Azure client with open SSH rule
        with patch.object(rule, 'get_azure_client') as mock_client:
            network_mock = Mock()
            nsg_mock = Mock()
            
            # Configure NSG with open SSH rule
            security_rule_mock = Mock()
            security_rule_mock.destination_port_range = '22'
            security_rule_mock.source_address_prefix = '0.0.0.0/0'
            security_rule_mock.access = 'Allow'
            security_rule_mock.direction = 'Inbound'
            security_rule_mock.protocol = 'Tcp'
            
            nsg_mock.security_rules = [security_rule_mock]
            network_mock.network_security_groups.get.return_value = nsg_mock
            mock_client.return_value = network_mock
            
            finding = await rule.evaluate(event, {})
            
            assert finding is not None
            assert finding.rule_id == 'AZURE-002'
            assert finding.severity == 'HIGH'
    
    @pytest.mark.asyncio
    async def test_evaluate_secure_nsg(self, sample_azure_nsg_event):
        """Test evaluation of secure NSG"""
        rule = AzureNSGOpenSSHRule()
        
        event = {
            'cloud_provider': 'azure',
            'resource_id': '/subscriptions/sub-123/resourceGroups/test-rg/providers/Microsoft.Network/networkSecurityGroups/test-nsg',
            'resource_type': 'networkSecurityGroups',
            'event_name': 'Microsoft.Network/networkSecurityGroups/securityRules/write',
            'event_id': 'test-002',
            'account_id': 'sub-123',
            'region': 'eastus',
            'event_time': datetime.utcnow()
        }
        
        # Mock Azure client with secure NSG
        with patch.object(rule, 'get_azure_client') as mock_client:
            network_mock = Mock()
            nsg_mock = Mock()
            
            # Configure NSG with secure rules
            security_rule_mock = Mock()
            security_rule_mock.destination_port_range = '22'
            security_rule_mock.source_address_prefix = '10.0.0.0/24'
            security_rule_mock.access = 'Allow'
            security_rule_mock.direction = 'Inbound'
            security_rule_mock.protocol = 'Tcp'
            
            nsg_mock.security_rules = [security_rule_mock]
            network_mock.network_security_groups.get.return_value = nsg_mock
            mock_client.return_value = network_mock
            
            finding = await rule.evaluate(event, {})
            
            assert finding is None
    
    def test_is_open_ssh_rule_true(self):
        """Test SSH rule detection - positive case"""
        rule = AzureNSGOpenSSHRule()
        
        rule_mock = Mock()
        rule_mock.destination_port_range = '22'
        rule_mock.source_address_prefix = '0.0.0.0/0'
        rule_mock.access = 'Allow'
        rule_mock.direction = 'Inbound'
        rule_mock.protocol = 'Tcp'
        
        result = rule._is_open_ssh_rule(rule_mock)
        assert result == True
    
    def test_is_open_ssh_rule_false(self):
        """Test SSH rule detection - negative case"""
        rule = AzureNSGOpenSSHRule()
        
        rule_mock = Mock()
        rule_mock.destination_port_range = '22'
        rule_mock.source_address_prefix = '10.0.0.0/24'  # Restricted IP range
        rule_mock.access = 'Allow'
        rule_mock.direction = 'Inbound'
        rule_mock.protocol = 'Tcp'
        
        result = rule._is_open_ssh_rule(rule_mock)
        assert result == False

class TestAzureKeyVaultNoFirewallRule:
    """Test Azure Key Vault firewall rule"""
    
    def test_rule_initialization(self):
        """Test Key Vault rule initialization"""
        rule = AzureKeyVaultNoFirewallRule()
        
        assert rule.rule_id == 'AZURE-004'
        assert rule.cloud_provider == 'azure'
        assert rule.severity == 'HIGH'
        assert 'key-vault' in rule.resource_types
    
    @pytest.mark.asyncio
    async def test_evaluate_no_firewall_vault(self, sample_azure_keyvault_event):
        """Test evaluation of Key Vault without firewall"""
        rule = AzureKeyVaultNoFirewallRule()
        
        event = {
            'cloud_provider': 'azure',
            'resource_id': '/subscriptions/sub-123/resourceGroups/test-rg/providers/Microsoft.KeyVault/vaults/test-kv',
            'resource_type': 'vaults',
            'event_id': 'test-004',
            'account_id': 'sub-123',
            'region': 'eastus',
            'event_time': datetime.utcnow()
        }
        
        # Mock Azure client with no firewall
        with patch.object(rule, 'get_azure_client') as mock_client:
            keyvault_mock = Mock()
            vault_mock = Mock()
            
            # Configure Key Vault with no firewall restrictions
            network_acls_mock = Mock()
            network_acls_mock.default_action = 'Allow'
            network_acls_mock.ip_rules = []
            
            vault_mock.properties = Mock()
            vault_mock.properties.network_acls = network_acls_mock
            keyvault_mock.vaults.get.return_value = vault_mock
            mock_client.return_value = keyvault_mock
            
            finding = await rule.evaluate(event, {})
            
            assert finding is not None
            assert finding.rule_id == 'AZURE-004'
            assert finding.severity == 'HIGH'
    
    @pytest.mark.asyncio
    async def test_evaluate_secure_vault(self, sample_azure_keyvault_event):
        """Test evaluation of secure Key Vault"""
        rule = AzureKeyVaultNoFirewallRule()
        
        event = {
            'cloud_provider': 'azure',
            'resource_id': '/subscriptions/sub-123/resourceGroups/test-rg/providers/Microsoft.KeyVault/vaults/test-kv',
            'resource_type': 'vaults',
            'event_id': 'test-004',
            'account_id': 'sub-123',
            'region': 'eastus',
            'event_time': datetime.utcnow()
        }
        
        # Mock Azure client with firewall
        with patch.object(rule, 'get_azure_client') as mock_client:
            keyvault_mock = Mock()
            vault_mock = Mock()
            
            # Configure Key Vault with firewall restrictions
            network_acls_mock = Mock()
            network_acls_mock.default_action = 'Deny'
            network_acls_mock.ip_rules = [Mock()]  # Has IP rules
            
            vault_mock.properties = Mock()
            vault_mock.properties.network_acls = network_acls_mock
            keyvault_mock.vaults.get.return_value = vault_mock
            mock_client.return_value = keyvault_mock
            
            finding = await rule.evaluate(event, {})
            
            assert finding is None
    
    def test_has_no_firewall_restrictions_true(self):
        """Test firewall restriction detection - positive case"""
        rule = AzureKeyVaultNoFirewallRule()
        
        vault_mock = Mock()
        network_acls_mock = Mock()
        network_acls_mock.default_action = 'Allow'
        network_acls_mock.ip_rules = []
        
        vault_mock.properties = Mock()
        vault_mock.properties.network_acls = network_acls_mock
        
        result = rule._has_no_firewall_restrictions(vault_mock)
        assert result == True
    
    def test_has_no_firewall_restrictions_false(self):
        """Test firewall restriction detection - negative case"""
        rule = AzureKeyVaultNoFirewallRule()
        
        vault_mock = Mock()
        network_acls_mock = Mock()
        network_acls_mock.default_action = 'Deny'
        network_acls_mock.ip_rules = [Mock()]
        
        vault_mock.properties = Mock()
        vault_mock.properties.network_acls = network_acls_mock
        
        result = rule._has_no_firewall_restrictions(vault_mock)
        assert result == False

class TestAzureIntegration:
    """Integration tests for Azure components"""
    
    @pytest.mark.asyncio
    async def test_end_to_end_azure_processing(self):
        """Test end-to-end Azure event processing"""
        # Create sample Azure event
        azure_event = {
            'id': 'integration-test-id',
            'operationName': {'value': 'Microsoft.Storage/storageAccounts/write'},
            'category': {'value': 'Write'},
            'eventTimestamp': '2024-01-15T12:00:00Z',
            'subscriptionId': 'test-sub-123',
            'tenantId': 'test-tenant-123',
            'resourceGroup': 'test-rg',
            'resourceId': '/subscriptions/test-sub-123/resourceGroups/test-rg/providers/Microsoft.Storage/storageAccounts/teststorage',
            'resourceLocation': 'eastus',
            'caller': 'testuser@example.com'
        }
        
        # Normalize event
        normalized = AzureActivityLogNormalizer.normalize_event(azure_event)
        
        # Verify normalization
        assert normalized['cloud_provider'] == 'azure'
        assert normalized['event_name'] == 'Microsoft.Storage/storageAccounts/write'
        assert normalized['resource_type'] == 'storageAccounts'
        
        # Test storage rule
        storage_rule = AzureStoragePublicAccessRule()
        
        # Mock Azure client
        with patch.object(storage_rule, 'get_azure_client') as mock_client:
            storage_mock = Mock()
            storage_account_mock = Mock()
            
            # Configure with public access
            storage_account_mock.network_rule_set = Mock()
            storage_account_mock.network_rule_set.default_action = 'Allow'
            storage_account_mock.allow_blob_public_access = True
            
            storage_mock.storage_accounts.get_properties.return_value = storage_account_mock
            mock_client.return_value = storage_mock
            
            # Evaluate rule
            finding = await storage_rule.evaluate(normalized, {})
            
            # Verify finding
            assert finding is not None
            assert finding.rule_id == 'AZURE-001'
            assert finding.severity == 'HIGH'
            assert finding.cloud_provider == 'azure'
            assert finding.resource_id == normalized['resource_id']
    
    @pytest.mark.asyncio
    async def test_multiple_azure_rules(self):
        """Test multiple Azure rules on same event"""
        azure_event = {
            'cloud_provider': 'azure',
            'resource_id': '/subscriptions/sub-123/resourceGroups/test-rg/providers/Microsoft.Storage/storageAccounts/teststorage',
            'resource_type': 'storageAccounts',
            'event_id': 'test-multi',
            'account_id': 'sub-123',
            'region': 'eastus',
            'event_time': datetime.utcnow()
        }
        
        rules = [
            AzureStoragePublicAccessRule(),
            AzureNSGOpenSSHRule(),
            AzureKeyVaultNoFirewallRule()
        ]
        
        findings = []
        
        for rule in rules:
            # Mock Azure client for storage rule
            with patch.object(rule, 'get_azure_client') as mock_client:
                if rule.rule_id == 'AZURE-001':
                    storage_mock = Mock()
                    storage_account_mock = Mock()
                    storage_account_mock.network_rule_set = Mock()
                    storage_account_mock.network_rule_set.default_action = 'Allow'
                    storage_account_mock.allow_blob_public_access = True
                    storage_mock.storage_accounts.get_properties.return_value = storage_account_mock
                    mock_client.return_value = storage_mock
                    
                    finding = await rule.evaluate(azure_event, {})
                    if finding:
                        findings.append(finding)
                else:
                    # Non-storage rules should not trigger on storage event
                    finding = await rule.evaluate(azure_event, {})
                    assert finding is None
        
        # Only storage rule should trigger
        assert len(findings) == 1
        assert findings[0].rule_id == 'AZURE-001'

if __name__ == '__main__':
    pytest.main([__file__])
