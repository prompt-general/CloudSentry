# Azure Activity Logs Configuration for CloudSentry

This guide shows how to configure Azure Activity Logs for CloudSentry integration with multiple deployment options.

## Option A: Event Hub (Recommended for Production)

### Prerequisites
- Azure CLI installed and logged in
- Appropriate Azure permissions

### Step 1: Create Resource Group
```bash
# Create Resource Group
az group create --name cloudsentry-rg --location eastus
```

### Step 2: Create Event Hub Namespace
```bash
# Create Event Hub Namespace
az eventhubs namespace create \
  --name cloudsentry-eh \
  --resource-group cloudsentry-rg \
  --location eastus \
  --sku Standard \
  --capacity 1
```

### Step 3: Create Event Hub
```bash
# Create Event Hub
az eventhubs eventhub create \
  --name insights-activity-logs \
  --resource-group cloudsentry-rg \
  --namespace-name cloudsentry-eh \
  --partition-count 2 \
  --message-retention 7
```

### Step 4: Create Storage Account for Checkpoints
```bash
# Create Storage Account for checkpoints
az storage account create \
  --name cloudsentrystorage \
  --resource-group cloudsentry-rg \
  --location eastus \
  --sku Standard_LRS \
  --kind StorageV2
```

### Step 5: Create Container for Checkpoints
```bash
# Create container for checkpoints
az storage container create \
  --name cloudsentry-checkpoints \
  --account-name cloudsentrystorage \
  --public-access off
```

### Step 6: Get Connection Strings
```bash
# Get Event Hub connection string
EVENT_HUB_CS=$(az eventhubs namespace authorization-rule keys list \
  --resource-group cloudsentry-rg \
  --namespace-name cloudsentry-eh \
  --name RootManageSharedAccessKey \
  --query primaryConnectionString \
  --output tsv)

# Get Storage connection string
STORAGE_CS=$(az storage account show-connection-string \
  --resource-group cloudsentry-rg \
  --name cloudsentrystorage \
  --query connectionString \
  --output tsv)

echo "Event Hub Connection String: $EVENT_HUB_CS"
echo "Storage Connection String: $STORAGE_CS"
```

### Step 7: Configure Activity Log Export
```bash
# Get subscription ID
SUBSCRIPTION_ID=$(az account show --query id --output tsv)

# Create diagnostic settings for Activity Log export
az monitor diagnostic-settings create \
  --name "CloudSentry-ActivityLogs" \
  --resource /subscriptions/$SUBSCRIPTION_ID \
  --event-hub-authorization-rule-id /subscriptions/$SUBSCRIPTION_ID/resourceGroups/cloudsentry-rg/providers/Microsoft.EventHub/namespaces/cloudsentry-eh/authorizationrules/RootManageSharedAccessKey \
  --event-hub insights-activity-logs \
  --logs '[{"category": "Administrative","enabled": true},{"category": "Security","enabled": true},{"category": "ResourceHealth","enabled": true},{"category": "Policy","enabled": true},{"category": "Autoscale","enabled": true},{"category": "Recommendation","enabled": true}]'
```

### Step 8: Verify Configuration
```bash
# Check diagnostic settings
az monitor diagnostic-settings list \
  --resource /subscriptions/$SUBSCRIPTION_ID

# Check Event Hub
az eventhubs eventhub show \
  --name insights-activity-logs \
  --namespace-name cloudsentry-eh \
  --resource-group cloudsentry-rg
```

## Option B: Diagnostic Settings with Log Analytics (Simpler Setup)

### Prerequisites
- Azure CLI installed and logged in
- Basic Azure permissions

### Step 1: Create Resource Group
```bash
# Create Resource Group
az group create --name cloudsentry-rg --location eastus
```

### Step 2: Create Log Analytics Workspace
```bash
# Create Log Analytics Workspace
az monitor log-analytics workspace create \
  --resource-group cloudsentry-rg \
  --workspace-name cloudsentry-law \
  --location eastus
```

### Step 3: Configure Activity Log Diagnostic Settings
```bash
# Get subscription ID
SUBSCRIPTION_ID=$(az account show --query id --output tsv)

# Configure Activity Log diagnostic settings
az monitor diagnostic-settings create \
  --name CloudSentryActivityLogs \
  --resource /subscriptions/$SUBSCRIPTION_ID \
  --workspace /subscriptions/$SUBSCRIPTION_ID/resourceGroups/cloudsentry-rg/providers/Microsoft.OperationalInsights/workspaces/cloudsentry-law \
  --logs '[{"category": "Administrative", "enabled": true}, {"category": "Security", "enabled": true}, {"category": "Policy", "enabled": true}, {"category": "ResourceHealth", "enabled": true}, {"category": "Autoscale", "enabled": true}, {"category": "Recommendation", "enabled": true}]'
```

### Step 4: Get Workspace Information
```bash
# Get workspace ID and key
WORKSPACE_ID=$(az monitor log-analytics workspace show \
  --resource-group cloudsentry-rg \
  --name cloudsentry-law \
  --query customerId \
  --output tsv)

WORKSPACE_KEY=$(az monitor log-analytics workspace get-shared-keys \
  --resource-group cloudsentry-rg \
  --name cloudsentry-law \
  --query primarySharedKey \
  --output tsv)

echo "Workspace ID: $WORKSPACE_ID"
echo "Workspace Key: $WORKSPACE_KEY"
```

### Step 5: Verify Configuration
```bash
# Check diagnostic settings
az monitor diagnostic-settings list \
  --resource /subscriptions/$SUBSCRIPTION_ID

# Check Log Analytics workspace
az monitor log-analytics workspace show \
  --name cloudsentry-law \
  --resource-group cloudsentry-rg
```

### Step 6: Query Activity Logs (Optional)
```bash
# Query Activity Logs from Log Analytics
az monitor log-analytics query \
  --workspace cloudsentry-law \
  --analytics-query "AzureActivity | where TimeGenerated > ago(1h) | take 10"
```

### Environment Variables for Log Analytics
```bash
# Create .env file for Log Analytics
cat > .env.loganalytics << EOF
# Azure Configuration
ENABLE_AZURE=true
AZURE_SUBSCRIPTION_ID=$SUBSCRIPTION_ID
AZURE_TENANT_ID=$(az account show --query tenantId --output tsv)
AZURE_CLIENT_ID={client-id}
AZURE_CLIENT_SECRET={client-secret}
AZURE_LOG_ANALYTICS_WORKSPACE_ID=$WORKSPACE_ID
AZURE_LOG_ANALYTICS_WORKSPACE_KEY=$WORKSPACE_KEY
AZURE_LOG_ANALYTICS_WORKSPACE_NAME=cloudsentry-law

# Cloud Provider Settings
DEFAULT_CLOUD_PROVIDER=azure
ENABLE_AWS=false
ENABLE_GCP=false
EOF
```

### Benefits of Log Analytics Approach
- **Simpler Setup**: No Event Hub or Storage Account needed
- **Built-in Queries**: Powerful KQL query language
- **Long Retention**: Extended data retention options
- **Cost Effective**: Lower infrastructure costs
- **Integrated Monitoring**: Azure Monitor integration

### Limitations
- **Not Real-time**: Slight delay in data availability
- **Query-based**: Requires polling instead of streaming
- **API Limits**: Rate limits on Log Analytics API
- **Storage Costs**: Log Analytics storage costs

## Option C: Azure Monitor REST API (Alternative)

### Prerequisites
- Service Principal with Reader role
- Azure Monitor REST API access

### Step 1: Create Service Principal
```bash
# Create service principal for API access
az ad sp create-for-rbac \
  --name "CloudSentry-Monitor" \
  --role "Reader" \
  --scopes /subscriptions/{subscription-id}
```

### Step 2: Configure API Access
```bash
# Set environment variables for API access
export AZURE_CLIENT_ID={client-id}
export AZURE_CLIENT_SECRET={client-secret}
export AZURE_TENANT_ID={tenant-id}
export AZURE_SUBSCRIPTION_ID={subscription-id}
```

### Step 3: Test API Access
```bash
# Test API access
curl -X GET "https://management.azure.com/subscriptions/{subscription-id}/providers/microsoft.insights/eventtypes?api-version=2015-04-01" \
  -H "Authorization: Bearer {access-token}"
```

## Option C: Azure Log Analytics Workspace (Advanced)

### Step 1: Create Log Analytics Workspace
```bash
# Create Log Analytics workspace
az monitor log-analytics workspace create \
  --name cloudsentry-law \
  --resource-group cloudsentry-rg \
  --location eastus
```

### Step 2: Configure Activity Log Export to Log Analytics
```bash
# Export Activity Logs to Log Analytics
az monitor diagnostic-settings create \
  --name "CloudSentry-LogAnalytics" \
  --resource /subscriptions/$SUBSCRIPTION_ID \
  --workspace /subscriptions/$SUBSCRIPTION_ID/resourceGroups/cloudsentry-rg/providers/Microsoft.OperationalInsights/workspaces/cloudsentry-law \
  --logs '[{"category": "Administrative","enabled": true},{"category": "Security","enabled": true}]'
```

### Step 3: Query Activity Logs
```bash
# Query Activity Logs from Log Analytics
az monitor log-analytics query \
  --workspace cloudsentry-law \
  --analytics-query "AzureActivity | where Category in ('Administrative', 'Security') | take 10"
```

## Configuration Files

### Environment Variables (.env)
```bash
# Azure Event Hub Configuration
ENABLE_AZURE=true
AZURE_SUBSCRIPTION_ID={subscription-id}
AZURE_TENANT_ID={tenant-id}
AZURE_CLIENT_ID={client-id}
AZURE_CLIENT_SECRET={client-secret}
AZURE_EVENTHUB_CONNECTION_STRING=$EVENT_HUB_CS
AZURE_EVENTHUB_NAME=insights-activity-logs
AZURE_STORAGE_CONNECTION_STRING=$STORAGE_CS
AZURE_STORAGE_CONTAINER=cloudsentry-checkpoints

# Cloud Provider Settings
DEFAULT_CLOUD_PROVIDER=azure
ENABLE_AWS=false
ENABLE_GCP=false
```

### Docker Compose Override (docker-compose.azure.yml)
```yaml
version: '3.8'
services:
  app:
    environment:
      - ENABLE_AZURE=true
      - AZURE_SUBSCRIPTION_ID=${AZURE_SUBSCRIPTION_ID}
      - AZURE_TENANT_ID=${AZURE_TENANT_ID}
      - AZURE_CLIENT_ID=${AZURE_CLIENT_ID}
      - AZURE_CLIENT_SECRET=${AZURE_CLIENT_SECRET}
      - AZURE_EVENTHUB_CONNECTION_STRING=${AZURE_EVENTHUB_CONNECTION_STRING}
      - AZURE_EVENTHUB_NAME=${AZURE_EVENTHUB_NAME}
      - AZURE_STORAGE_CONNECTION_STRING=${AZURE_STORAGE_CONNECTION_STRING}
      - AZURE_STORAGE_CONTAINER=${AZURE_STORAGE_CONTAINER}
      - DEFAULT_CLOUD_PROVIDER=azure
      - ENABLE_AWS=false
```

## Deployment Scripts

### Automated Setup Script (setup-azure.sh)
```bash
#!/bin/bash

# Azure Activity Logs Setup Script
set -e

# Variables
RESOURCE_GROUP="cloudsentry-rg"
LOCATION="eastus"
EVENT_HUB_NAMESPACE="cloudsentry-eh"
EVENT_HUB_NAME="insights-activity-logs"
STORAGE_ACCOUNT="cloudsentrystorage$(date +%s | tail -c 6)"
STORAGE_CONTAINER="cloudsentry-checkpoints"

echo "Setting up Azure Activity Logs for CloudSentry..."

# Create Resource Group
echo "Creating resource group..."
az group create --name $RESOURCE_GROUP --location $LOCATION

# Create Event Hub Namespace
echo "Creating Event Hub namespace..."
az eventhubs namespace create \
  --name $EVENT_HUB_NAMESPACE \
  --resource-group $RESOURCE_GROUP \
  --location $LOCATION \
  --sku Standard \
  --capacity 1

# Create Event Hub
echo "Creating Event Hub..."
az eventhubs eventhub create \
  --name $EVENT_HUB_NAME \
  --resource-group $RESOURCE_GROUP \
  --namespace-name $EVENT_HUB_NAMESPACE \
  --partition-count 2 \
  --message-retention 7

# Create Storage Account
echo "Creating storage account..."
az storage account create \
  --name $STORAGE_ACCOUNT \
  --resource-group $RESOURCE_GROUP \
  --location $LOCATION \
  --sku Standard_LRS \
  --kind StorageV2

# Create Container
echo "Creating storage container..."
az storage container create \
  --name $STORAGE_CONTAINER \
  --account-name $STORAGE_ACCOUNT \
  --public-access off

# Get Connection Strings
echo "Getting connection strings..."
EVENT_HUB_CS=$(az eventhubs namespace authorization-rule keys list \
  --resource-group $RESOURCE_GROUP \
  --namespace-name $EVENT_HUB_NAMESPACE \
  --name RootManageSharedAccessKey \
  --query primaryConnectionString \
  --output tsv)

STORAGE_CS=$(az storage account show-connection-string \
  --resource-group $RESOURCE_GROUP \
  --name $STORAGE_ACCOUNT \
  --query connectionString \
  --output tsv)

# Configure Activity Log Export
echo "Configuring Activity Log export..."
SUBSCRIPTION_ID=$(az account show --query id --output tsv)

az monitor diagnostic-settings create \
  --name "CloudSentry-ActivityLogs" \
  --resource /subscriptions/$SUBSCRIPTION_ID \
  --event-hub-authorization-rule-id /subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.EventHub/namespaces/$EVENT_HUB_NAMESPACE/authorizationrules/RootManageSharedAccessKey \
  --event-hub $EVENT_HUB_NAME \
  --logs '[{"category": "Administrative","enabled": true},{"category": "Security","enabled": true},{"category": "ResourceHealth","enabled": true},{"category": "Policy","enabled": true}]'

# Create .env file
echo "Creating .env file..."
cat > .env.azure << EOF
# Azure Configuration
ENABLE_AZURE=true
AZURE_SUBSCRIPTION_ID=$SUBSCRIPTION_ID
AZURE_TENANT_ID=$(az account show --query tenantId --output tsv)
AZURE_CLIENT_ID={client-id}
AZURE_CLIENT_SECRET={client-secret}
AZURE_EVENTHUB_CONNECTION_STRING=$EVENT_HUB_CS
AZURE_EVENTHUB_NAME=$EVENT_HUB_NAME
AZURE_STORAGE_CONNECTION_STRING=$STORAGE_CS
AZURE_STORAGE_CONTAINER=$STORAGE_CONTAINER

# Cloud Provider Settings
DEFAULT_CLOUD_PROVIDER=azure
ENABLE_AWS=false
ENABLE_GCP=false
EOF

echo "Setup complete!"
echo "Event Hub Connection String: $EVENT_HUB_CS"
echo "Storage Connection String: $STORAGE_CS"
echo "Subscription ID: $SUBSCRIPTION_ID"
echo ""
echo "Next steps:"
echo "1. Update .env.azure with your service principal credentials"
echo "2. Copy .env.azure to .env"
echo "3. Run: docker-compose up -d"
```

### Cleanup Script (cleanup-azure.sh)
```bash
#!/bin/bash

# Azure Cleanup Script
set -e

RESOURCE_GROUP="cloudsentry-rg"

echo "Cleaning up Azure resources..."

# Delete resource group and all resources
az group delete --name $RESOURCE_GROUP --yes --no-wait

echo "Cleanup initiated. Resources will be deleted shortly."
```

## Verification Steps

### 1. Test Event Hub Connection
```bash
# Test Event Hub connection
python -c "
from azure.eventhub import EventHubConsumerClient
from azure.identity import DefaultAzureCredential

# Test connection
credential = DefaultAzureCredential()
client = EventHubConsumerClient(
    fully_qualified_namespace='cloudsentry-eh.servicebus.windows.net',
    eventhub_name='insights-activity-logs',
    consumer_group='$Default',
    credential=credential
)
print('Event Hub connection successful!')
"
```

### 2. Verify Activity Log Export
```bash
# Check diagnostic settings
az monitor diagnostic-settings list \
  --resource /subscriptions/{subscription-id}

# Check Event Hub messages
az eventhubs eventhub show \
  --name insights-activity-logs \
  --namespace-name cloudsentry-eh \
  --resource-group cloudsentry-rg
```

### 3. Test CloudSentry Integration
```bash
# Start CloudSentry with Azure support
docker-compose -f docker-compose.yml -f docker-compose.azure.yml up -d

# Check logs
docker-compose logs -f app | grep "Azure"

# Test API endpoint
curl -X GET "http://localhost:8000/api/v1/azure/subscriptions"
```

## Troubleshooting

### Common Issues

#### 1. Event Hub Connection Failed
```bash
# Check Event Hub namespace
az eventhubs namespace show \
  --name cloudsentry-eh \
  --resource-group cloudsentry-rg

# Check authorization rules
az eventhubs namespace authorization-rule list \
  --namespace-name cloudsentry-eh \
  --resource-group cloudsentry-rg
```

#### 2. Storage Access Issues
```bash
# Check storage account
az storage account show \
  --name cloudsentrystorage \
  --resource-group cloudsentry-rg

# Check container
az storage container exists \
  --name cloudsentry-checkpoints \
  --account-name cloudsentrystorage
```

#### 3. Activity Log Export Issues
```bash
# Check diagnostic settings
az monitor diagnostic-settings show \
  --name CloudSentry-ActivityLogs \
  --resource /subscriptions/{subscription-id}

# Check Activity Log categories
az monitor activity-log list-categories
```

### Debug Mode
```bash
# Enable debug logging
export AZURE_LOG_LEVEL=DEBUG
export DEBUG=true

# Run with verbose output
docker-compose --verbose up app
```

## Performance Optimization

### Event Hub Optimization
```bash
# Increase partition count for high throughput
az eventhubs eventhub update \
  --name insights-activity-logs \
  --resource-group cloudsentry-rg \
  --namespace-name cloudsentry-eh \
  --partition-count 4

# Increase throughput units
az eventhubs namespace update \
  --name cloudsentry-eh \
  --resource-group cloudsentry-rg \
  --capacity 2
```

### Storage Optimization
```bash
# Enable hot storage tier
az storage account update \
  --name cloudsentrystorage \
  --resource-group cloudsentry-rg \
  --enable-large-file-share true
```

## Security Considerations

### Network Security
```bash
# Configure virtual network service endpoints
az network vnet subnet create \
  --resource-group cloudsentry-rg \
  --vnet-name cloudsentry-vnet \
  --name cloudsentry-subnet \
  --address-prefix 10.0.0.0/24 \
  --service-endpoints Microsoft.EventHub Microsoft.Storage

# Create private endpoints
az network private-endpoint create \
  --resource-group cloudsentry-rg \
  --name cloudsentry-eh-pe \
  --vnet-name cloudsentry-vnet \
  --subnet cloudsentry-subnet \
  --private-connection-resource-id /subscriptions/{subscription-id}/resourceGroups/cloudsentry-rg/providers/Microsoft.EventHub/namespaces/cloudsentry-eh \
  --group-ids namespace
```

### Access Control
```bash
# Create role assignments
az role assignment create \
  --assignee {principal-id} \
  --role "Event Hub Data Receiver" \
  --scope /subscriptions/{subscription-id}/resourceGroups/cloudsentry-rg/providers/Microsoft.EventHub/namespaces/cloudsentry-eh

az role assignment create \
  --assignee {principal-id} \
  --role "Storage Blob Data Contributor" \
  --scope /subscriptions/{subscription-id}/resourceGroups/cloudsentry-rg/providers/Microsoft.Storage/storageAccounts/cloudsentrystorage
```

## Cost Management

### Monitor Costs
```bash
# Check resource costs
az consumption usage list \
  --resource-group cloudsentry-rg \
  --start-date 2024-01-01 \
  --end-date 2024-01-31
```

### Cost Optimization
```bash
# Right-size Event Hub
az eventhubs namespace update \
  --name cloudsentry-eh \
  --resource-group cloudsentry-rg \
  --capacity 1

# Use appropriate storage tier
az storage account update \
  --name cloudsentrystorage \
  --resource-group cloudsentry-rg \
  --sku Standard_LRS
```

## Next Steps

1. **Choose Option**: Select Event Hub (recommended) or alternative
2. **Run Setup**: Execute the automated setup script
3. **Configure Credentials**: Set up service principal
4. **Deploy CloudSentry**: Start the application
5. **Verify Integration**: Test the connection and data flow
6. **Monitor Performance**: Set up monitoring and alerting

## Support

For Azure Activity Logs issues:
- Check Azure documentation
- Review Azure service health
- Contact Azure support
- Check CloudSentry logs
