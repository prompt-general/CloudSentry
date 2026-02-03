# Azure Setup Guide for CloudSentry

## Prerequisites

1. **Azure Subscription**: Active Azure subscription
2. **Azure CLI**: Installed and logged in
3. **Python 3.8+**: For running setup scripts
4. **Docker**: For containerized deployment

## Step 1: Create Azure Service Principal

```bash
# Login to Azure
az login

# Create service principal for CloudSentry
az ad sp create-for-rbac \
  --name "CloudSentry" \
  --role "Contributor" \
  --scopes /subscriptions/{subscription-id} \
  --years 1

# Save the output - you'll need these values:
# {
#   "appId": "...",        # AZURE_CLIENT_ID
#   "password": "...",     # AZURE_CLIENT_SECRET
#   "tenant": "...",       # AZURE_TENANT_ID
#   "subscription": "..."  # AZURE_SUBSCRIPTION_ID
# }
```

## Step 2: Create Azure Event Hub

```bash
# Set variables
RESOURCE_GROUP="CloudSentry-RG"
LOCATION="eastus"
EVENT_HUB_NAMESPACE="cloudsentry-events"
EVENT_HUB_NAME="insights-activity-logs"

# Create resource group
az group create \
  --name $RESOURCE_GROUP \
  --location $LOCATION

# Create Event Hub namespace
az eventhubs namespace create \
  --name $EVENT_HUB_NAMESPACE \
  --resource-group $RESOURCE_GROUP \
  --location $LOCATION \
  --sku Standard \
  --capacity 1

# Create Event Hub
az eventhubs eventhub create \
  --name $EVENT_HUB_NAME \
  --resource-group $RESOURCE_GROUP \
  --namespace-name $EVENT_HUB_NAMESPACE \
  --message-retention 7 \
  --partition-count 4

# Get Event Hub connection string
EVENT_HUB_CONNECTION_STRING=$(az eventhubs namespace authorization-rule keys list \
  --resource-group $RESOURCE_GROUP \
  --namespace-name $EVENT_HUB_NAMESPACE \
  --name RootManageSharedAccessKey \
  --query primaryConnectionString \
  --output tsv)

echo "Event Hub Connection String: $EVENT_HUB_CONNECTION_STRING"
```

## Step 3: Create Azure Storage Account

```bash
# Create storage account for checkpoints
STORAGE_ACCOUNT_NAME="cloudsentry$(date +%s | tail -c 6)"
STORAGE_CONTAINER_NAME="cloudsentry-checkpoints"

# Create storage account
az storage account create \
  --name $STORAGE_ACCOUNT_NAME \
  --resource-group $RESOURCE_GROUP \
  --location $LOCATION \
  --sku Standard_LRS \
  --kind StorageV2

# Create container for checkpoints
az storage container create \
  --name $STORAGE_CONTAINER_NAME \
  --account-name $STORAGE_ACCOUNT_NAME \
  --public-access off

# Get storage connection string
STORAGE_CONNECTION_STRING=$(az storage account show-connection-string \
  --name $STORAGE_ACCOUNT_NAME \
  --resource-group $RESOURCE_GROUP \
  --query connectionString \
  --output tsv)

echo "Storage Connection String: $STORAGE_CONNECTION_STRING"
```

## Step 4: Configure Activity Log Export

```bash
# Create diagnostic settings for Activity Log export
az monitor diagnostic-settings create \
  --name "CloudSentry-ActivityLogs" \
  --resource /subscriptions/{subscription-id} \
  --event-hub-authorization-rule-id /subscriptions/{subscription-id}/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.EventHub/namespaces/$EVENT_HUB_NAMESPACE/authorizationrules/RootManageSharedAccessKey \
  --event-hub $EVENT_HUB_NAME \
  --logs '[{"category": "Administrative","enabled": true},{"category": "Security","enabled": true},{"category": "ResourceHealth","enabled": true},{"category": "Policy","enabled": true}]'
```

## Step 5: Set Environment Variables

```bash
# Create .env file for Azure configuration
cat > .env.azure << EOF
# Azure Configuration
ENABLE_AZURE=true
AZURE_SUBSCRIPTION_ID={subscription-id}
AZURE_TENANT_ID={tenant-id}
AZURE_CLIENT_ID={client-id}
AZURE_CLIENT_SECRET={client-secret}
AZURE_EVENTHUB_CONNECTION_STRING=$EVENT_HUB_CONNECTION_STRING
AZURE_EVENTHUB_NAME=$EVENT_HUB_NAME
AZURE_STORAGE_CONNECTION_STRING=$STORAGE_CONNECTION_STRING
AZURE_STORAGE_CONTAINER=$STORAGE_CONTAINER_NAME

# Cloud Provider Settings
DEFAULT_CLOUD_PROVIDER=azure
ENABLE_AWS=false
ENABLE_GCP=false

# Database (use Azure PostgreSQL or external)
DATABASE_URL=postgresql+asyncpg://cloudsentry:password@localhost:5432/cloudsentry

# Redis (use Azure Cache for Redis or external)
REDIS_URL=redis://localhost:6379/0
EOF
```

## Step 6: Deploy CloudSentry with Azure Support

### Option 1: Docker Compose (Recommended)

```bash
# Copy Azure environment variables
cp .env.azure .env

# Update .env with your actual values
# Edit .env file and replace {subscription-id}, {tenant-id}, etc.

# Deploy with Azure support
docker-compose up -d

# Check logs
docker-compose logs -f app
```

### Option 2: Local Development

```bash
# Install Azure dependencies
pip install -r requirements.txt

# Set environment variables
export ENABLE_AZURE=true
export AZURE_SUBSCRIPTION_ID={subscription-id}
export AZURE_TENANT_ID={tenant-id}
export AZURE_CLIENT_ID={client-id}
export AZURE_CLIENT_SECRET={client-secret}
export AZURE_EVENTHUB_CONNECTION_STRING=$EVENT_HUB_CONNECTION_STRING
export AZURE_STORAGE_CONNECTION_STRING=$STORAGE_CONNECTION_STRING

# Run the application
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

## Step 7: Verify Azure Integration

### Check Azure Event Hub Connection

```bash
# Test Azure Event Hub connection
curl -X GET "http://localhost:8000/api/v1/azure/subscriptions" \
  -H "Authorization: Bearer {your-token}"
```

### Verify Multi-Cloud Dashboard

1. Open dashboard: http://localhost:3000
2. Check cloud provider filter dropdown
3. Select "Azure" to see Azure-specific findings
4. Verify Azure findings appear in the table

### Check Database Integration

```bash
# Connect to database and check cloud provider data
psql -h localhost -U cloudsentry -d cloudsentry

# Check Azure findings
SELECT cloud_provider, COUNT(*) FROM findings WHERE cloud_provider = 'azure' GROUP BY cloud_provider;

# Check Azure-specific fields
SELECT resource_group, subscription_id, tenant_id FROM findings WHERE cloud_provider = 'azure' LIMIT 5;
```

## Step 8: Configure Azure Security Rules

### Enable Azure Rules

The following Azure security rules are automatically enabled when Azure is configured:

1. **AZURE-001**: Storage Public Access Detection
2. **AZURE-002**: NSG Open SSH Detection
3. **AZURE-003**: VM No Disk Encryption Detection
4. **AZURE-004**: Key Vault No Firewall Detection
5. **AZURE-005**: SQL Server No Firewall Detection
6. **AZURE-006**: Storage No HTTPS Enforcement

### Test Azure Rules

```bash
# Trigger a manual audit for Azure resources
curl -X POST "http://localhost:8000/api/v1/audits/trigger" \
  -H "Content-Type: application/json" \
  -d '{"audit_type": "full"}'
```

## Step 9: Monitor Azure Integration

### Check Event Hub Metrics

```bash
# Monitor Event Hub metrics
az monitor metrics list \
  --resource /subscriptions/{subscription-id}/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.EventHub/namespaces/$EVENT_HUB_NAMESPACE \
  --metric "IncomingMessages" \
  --interval PT1H
```

### Monitor Storage Usage

```bash
# Check storage account usage
az storage account show-usage \
  --name $STORAGE_ACCOUNT_NAME \
  --resource-group $RESOURCE_GROUP
```

### Application Logs

```bash
# Check application logs for Azure events
docker-compose logs app | grep "Azure"
```

## Step 10: Production Deployment

### Azure Container Instances (ACI)

```bash
# Deploy to Azure Container Instances
az container create \
  --resource-group $RESOURCE_GROUP \
  --name cloudsentry-azure \
  --image cloudsentry:latest \
  --cpu 2 \
  --memory 4 \
  --environment-variables \
    ENABLE_AZURE=true \
    AZURE_SUBSCRIPTION_ID={subscription-id} \
    AZURE_TENANT_ID={tenant-id} \
    AZURE_CLIENT_ID={client-id} \
    AZURE_CLIENT_SECRET={client-secret} \
    AZURE_EVENTHUB_CONNECTION_STRING=$EVENT_HUB_CONNECTION_STRING \
    AZURE_STORAGE_CONNECTION_STRING=$STORAGE_CONNECTION_STRING \
  --dns-name-label cloudsentry-azure-$(date +%s)
```

### Azure Kubernetes Service (AKS)

```bash
# Create AKS cluster
az aks create \
  --resource-group $RESOURCE_GROUP \
  --name cloudsentry-aks \
  --node-count 3 \
  --enable-addons monitoring \
  --attach-acr cloudsentry-acr

# Deploy with Helm (recommended)
helm install cloudsentry ./helm/charts/cloudsentry \
  --set azure.enabled=true \
  --set azure.subscriptionId={subscription-id} \
  --set azure.tenantId={tenant-id} \
  --set azure.clientId={client-id} \
  --set azure.clientSecret={client-secret}
```

## Troubleshooting

### Common Issues

#### 1. Service Principal Permissions
```bash
# Check service principal permissions
az role assignment list \
  --assignee {client-id} \
  --subscription {subscription-id}
```

#### 2. Event Hub Connection Issues
```bash
# Test Event Hub connection
az eventhubs eventhub show \
  --name $EVENT_HUB_NAME \
  --namespace-name $EVENT_HUB_NAMESPACE \
  --resource-group $RESOURCE_GROUP
```

#### 3. Storage Access Issues
```bash
# Test storage access
az storage container list \
  --account-name $STORAGE_ACCOUNT_NAME \
  --query '[].name'
```

#### 4. Activity Log Export Issues
```bash
# Check diagnostic settings
az monitor diagnostic-settings list \
  --resource /subscriptions/{subscription-id}
```

### Debug Mode

```bash
# Enable debug logging
export DEBUG=true
export AZURE_LOG_LEVEL=DEBUG

# Run with verbose logging
docker-compose --verbose up app
```

### Health Checks

```bash
# Check application health
curl -f "http://localhost:8000/health"

# Check Azure-specific health
curl -f "http://localhost:8000/api/v1/health/detailed"
```

## Security Best Practices

### 1. Use Managed Identity (Recommended)
```bash
# Enable managed identity for VM/container
az identity create \
  --resource-group $RESOURCE_GROUP \
  --name cloudsentry-identity

# Assign identity to VM/container
az vm identity assign \
  --resource-group $RESOURCE_GROUP \
  --name cloudsentry-vm \
  --identities cloudsentry-identity
```

### 2. Network Security
```bash
# Configure network security groups
az network nsg create \
  --resource-group $RESOURCE_GROUP \
  --name cloudsentry-nsg

# Allow only necessary ports
az network nsg rule create \
  --resource-group $RESOURCE_GROUP \
  --nsg-name cloudsentry-nsg \
  --name allow-http \
  --protocol tcp \
  --direction inbound \
  --priority 1000 \
  --source-address-prefix '*' \
  --source-port-range '*' \
  --destination-address-prefix '*' \
  --destination-port-range 80 \
  --access allow
```

### 3. Key Vault Integration
```bash
# Store secrets in Key Vault
az keyvault create \
  --name cloudsentry-kv \
  --resource-group $RESOURCE_GROUP \
  --location $LOCATION

# Store secrets
az keyvault secret set \
  --vault-name cloudsentry-kv \
  --name azure-client-secret \
  --value {client-secret}
```

## Performance Optimization

### 1. Event Hub Scaling
```bash
# Scale Event Hub for high throughput
az eventhubs eventhub update \
  --name $EVENT_HUB_NAME \
  --resource-group $RESOURCE_GROUP \
  --namespace-name $EVENT_HUB_NAMESPACE \
  --partition-count 8
```

### 2. Storage Optimization
```bash
# Enable hot storage tier
az storage account update \
  --name $STORAGE_ACCOUNT_NAME \
  --resource-group $RESOURCE_GROUP \
  --enable-large-file-share true
```

### 3. Database Optimization
```bash
# Use Azure Database for PostgreSQL
az postgres server create \
  --resource-group $RESOURCE_GROUP \
  --name cloudsentry-db \
  --location $LOCATION \
  --admin-user cloudsentry \
  --admin-password {strong-password} \
  --sku-name GP_Gen5_2
```

## Monitoring and Alerting

### 1. Azure Monitor Integration
```bash
# Create alert rules
az monitor metrics alert create \
  --name "CloudSentry-High-Error-Rate" \
  --resource-group $RESOURCE_GROUP \
  --scopes /subscriptions/{subscription-id}/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.EventHub/namespaces/$EVENT_HUB_NAMESPACE \
  --condition "avg IncomingMessages > 1000" \
  --description "Alert on high error rate"
```

### 2. Log Analytics
```bash
# Create Log Analytics workspace
az monitor log-analytics workspace create \
  --resource-group $RESOURCE_GROUP \
  --name cloudsentry-logs \
  --location $LOCATION
```

## Backup and Recovery

### 1. Data Backup
```bash
# Configure storage backup
az backup protection enable-for-vm \
  --resource-group $RESOURCE_GROUP \
  --vm-name cloudsentry-vm \
  --policy-name cloudsentry-backup-policy
```

### 2. Disaster Recovery
```bash
# Create geo-redundant storage
az storage account create \
  --name cloudsentry-backup \
  --resource-group $RESOURCE_GROUP \
  --location $LOCATION \
  --sku Standard_GRS
```

## Cost Optimization

### 1. Resource Sizing
```bash
# Right-size resources based on usage
az monitor metrics list \
  --resource /subscriptions/{subscription-id}/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.Compute/virtualMachines/cloudsentry-vm \
  --metric "Percentage CPU" \
  --interval PT1H
```

### 2. Reserved Instances
```bash
# Purchase reserved instances for cost savings
az reservation purchase \
  --resource-group $RESOURCE_GROUP \
  --reservation-name cloudsentry-reservation \
  --reserved-resource-type VirtualMachines \
  --sku Standard_B2s \
  --location $LOCATION \
  --quantity 1 \
  --term P1Y \
  --billing-plan Upfront
```

## Next Steps

1. **Test Integration**: Verify all Azure components work together
2. **Monitor Performance**: Set up monitoring and alerting
3. **Scale Resources**: Adjust resources based on usage patterns
4. **Implement Security**: Apply security best practices
5. **Optimize Costs**: Monitor and optimize Azure spending

## Support

For Azure-specific issues:
1. Check Azure documentation
2. Review Azure service health
3. Contact Azure support
4. Check CloudSentry GitHub issues

## References

- [Azure Identity Documentation](https://docs.microsoft.com/en-us/python/api/azure-identity/)
- [Azure Event Hub Python SDK](https://docs.microsoft.com/en-us/python/api/azure-eventhub/)
- [Azure Management SDK](https://docs.microsoft.com/en-us/python/api/azure-mgmt/)
- [CloudSentry GitHub](https://github.com/your-org/cloudsentry)
