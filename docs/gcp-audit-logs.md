# GCP Audit Log Configuration for CloudSentry

This guide covers two approaches for configuring GCP audit logs for CloudSentry integration.

## Prerequisites

- Active GCP project with appropriate permissions
- gcloud CLI installed and authenticated
- CloudSentry service account created (see gcp-setup.md)

## Option A: Pub/Sub (Recommended for Production)

Real-time event processing with immediate security findings.

### Step 1: Create Pub/Sub Infrastructure

```bash
# Set your project ID
export PROJECT_ID="your-project-id"
gcloud config set project $PROJECT_ID

# Create Pub/Sub topic for audit logs
gcloud pubsub topics create cloudsentry-audit-logs \
  --description="CloudSentry audit log events"

# Create Pub/Sub subscription for CloudSentry
gcloud pubsub subscriptions create cloudsentry-subscription \
  --topic=cloudsentry-audit-logs \
  --ack-deadline=60 \
  --message-retention-duration=7d \
  --description="CloudSentry event ingestion subscription"
```

### Step 2: Create Audit Log Sink

```bash
# Create log sink to Pub/Sub topic
gcloud logging sinks create cloudsentry-sink \
  pubsub.googleapis.com/projects/${PROJECT_ID}/topics/cloudsentry-audit-logs \
  --log-filter='logName:"cloudaudit.googleapis.com"' \
  --description="CloudSentry audit log sink to Pub/Sub"

# Get the sink's service account
SINK_SA=$(gcloud logging sinks describe cloudsentry-sink --format="value(writerIdentity)")
echo "Sink service account: ${SINK_SA}")
```

### Step 3: Grant Permissions

```bash
# Grant Pub/Sub publisher role to sink service account
gcloud pubsub topics add-iam-policy-binding cloudsentry-audit-logs \
  --member="serviceAccount:${SINK_SA}" \
  --role="roles/pubsub.publisher"

# Verify the binding
gcloud pubsub topics get-iam-policy cloudsentry-audit-logs
```

### Step 4: Configure CloudSentry

Update your `.env` file:
```bash
ENABLE_GCP=true
GCP_PROJECT_ID=${PROJECT_ID}
GCP_PUBSUB_SUBSCRIPTION_ID=cloudsentry-subscription
GCP_AUDIT_LOG_SINK=cloudsentry-sink
```

### Step 5: Test the Configuration

```bash
# Generate a test audit event
gcloud compute instances create test-instance \
  --zone=us-central1-a \
  --machine-type=e2-micro \
  --image-family=debian-11 \
  --image-project=debian-cloud

# Check Pub/Sub subscription
gcloud pubsub subscriptions describe cloudsentry-subscription

# View recent audit logs
gcloud logging read 'logName="cloudaudit.googleapis.com"' --limit=5 --format="table(timestamp,protoPayload.methodName,protoPayload.resourceName)"
```

## Option B: Logging Export (Simpler Setup)

Batch processing with periodic security scans.

### Step 1: Enable Required APIs

```bash
# Enable necessary GCP APIs
gcloud services enable \
  cloudresourcemanager.googleapis.com \
  logging.googleapis.com \
  compute.googleapis.com \
  storage.googleapis.com \
  iam.googleapis.com \
  sqladmin.googleapis.com \
  storage-component.googleapis.com
```

### Step 2: Create Storage Bucket

```bash
# Create bucket for audit log exports
gsutil mb gs://cloudsentry-logs-${PROJECT_ID}

# Set appropriate permissions
gsutil iam ch serviceAccount:${PROJECT_ID}@cloudservices.gserviceaccount.com:objectViewer gs://cloudsentry-logs-${PROJECT_ID}
```

### Step 3: Configure Audit Log Export

```bash
# Create log sink to Cloud Storage
gcloud logging sinks create cloudsentry-log-sink \
  storage.googleapis.com/cloudsentry-logs-${PROJECT_ID} \
  --log-filter='logName:"cloudaudit.googleapis.com"' \
  --description="CloudSentry audit logs export to Cloud Storage"

# Get sink service account
SINK_SA=$(gcloud logging sinks describe cloudsentry-log-sink --format="value(writerIdentity)")
echo "Sink service account: ${SINK_SA}")
```

### Step 4: Grant Storage Permissions

```bash
# Grant storage object creator role to sink service account
gcloud projects add-iam-policy-binding ${PROJECT_ID} \
  --member="serviceAccount:${SINK_SA}" \
  --role="roles/storage.objectCreator"

# Verify permissions
gsutil iam get gs://cloudsentry-logs-${PROJECT_ID}
```

### Step 5: Configure CloudSentry

Update your `.env` file:
```bash
ENABLE_GCP=true
GCP_PROJECT_ID=${PROJECT_ID}
GCP_AUDIT_LOG_SINK=cloudsentry-log-sink
# Note: For storage export, you'll need to configure periodic scanning
```

## Advanced Configuration

### Custom Log Filters

Focus on specific services or event types:

```bash
# Storage and Compute only
gcloud logging sinks create cloudsentry-focused-sink \
  pubsub.googleapis.com/projects/${PROJECT_ID}/topics/cloudsentry-audit-logs \
  --log-filter='logName:"cloudaudit.googleapis.com" AND (protoPayload.serviceName="storage.googleapis.com" OR protoPayload.serviceName="compute.googleapis.com")'

# High-risk operations only
gcloud logging sinks create cloudsentry-highrisk-sink \
  pubsub.googleapis.com/projects/${PROJECT_ID}/topics/cloudsentry-audit-logs \
  --log-filter='logName:"cloudaudit.googleapis.com" AND (protoPayload.methodName="storage.buckets.setIamPolicy" OR protoPayload.methodName="compute.firewalls.insert" OR protoPayload.methodName="iam.serviceAccounts.create")'
```

### Multi-Project Setup

For organizations with multiple GCP projects:

```bash
# In central project (monitoring project)
export CENTRAL_PROJECT="cloudsentry-monitoring"
gcloud config set project ${CENTRAL_PROJECT}

# Create central Pub/Sub topic
gcloud pubsub topics create cloudsentry-audit-logs-central

# In each source project
for PROJECT in project-1 project-2 project-3; do
  gcloud config set project ${PROJECT}
  
  # Create sink pointing to central topic
  gcloud logging sinks create cloudsentry-to-central \
    pubsub.googleapis.com/projects/${CENTRAL_PROJECT}/topics/cloudsentry-audit-logs-central \
    --log-filter='logName:"cloudaudit.googleapis.com"'
  
  # Get and grant permissions
  SINK_SA=$(gcloud logging sinks describe cloudsentry-to-central --format="value(writerIdentity)")
  gcloud pubsub topics add-iam-policy-binding \
    projects/${CENTRAL_PROJECT}/topics/cloudsentry-audit-logs-central \
    --member="serviceAccount:${SINK_SA}" \
    --role="roles/pubsub.publisher"
done
```

## Troubleshooting

### Common Issues

1. **No Events in Pub/Sub**
   ```bash
   # Check sink status
   gcloud logging sinks describe cloudsentry-sink
   
   # Check Pub/Sub topic permissions
   gcloud pubsub topics get-iam-policy cloudsentry-audit-logs
   
   # Check recent logs
   gcloud logging read 'logName="cloudaudit.googleapis.com"' --limit=10
   ```

2. **Permission Denied Errors**
   ```bash
   # Verify service account permissions
   gcloud projects get-iam-policy ${PROJECT_ID} --flatten="bindings[].members" --format="table(bindings.role,bindings.members)"
   
   # Check sink service account
   gcloud logging sinks describe cloudsentry-sink --format="value(writerIdentity)"
   ```

3. **High Latency**
   ```bash
   # Check Pub/Sub subscription configuration
   gcloud pubsub subscriptions describe cloudsentry-subscription
   
   # Monitor message delivery
   gcloud pubsub subscriptions pull cloudsentry-subscription --limit=5
   ```

### Monitoring and Alerts

```bash
# Create alert for sink failures
gcloud monitoring alerts create \
  --display-name="CloudSentry Audit Log Sink Alert" \
  --condition-filter='metric.type="logging.googleapis.com/sink/destination_errors" AND resource.type="project"' \
  --notification-channels=your-notification-channel

# Monitor Pub/Sub message flow
gcloud monitoring metrics list --filter="pubsub.googleapis.com"
```

## Security Best Practices

1. **Principle of Least Privilege**
   - Use specific IAM roles instead of broad permissions
   - Regularly review and audit service account permissions

2. **Data Protection**
   - Enable Cloud KMS for sensitive audit log data
   - Configure appropriate retention policies

3. **Monitoring**
   - Set up alerts for sink failures
   - Monitor Pub/Sub subscription backlog
   - Track audit log processing latency

## Migration Between Options

### From Storage Export to Pub/Sub

```bash
# 1. Create Pub/Sub infrastructure (see Option A)
# 2. Update sink destination
gcloud logging sinks update cloudsentry-log-sink \
  --destination=pubsub.googleapis.com/projects/${PROJECT_ID}/topics/cloudsentry-audit-logs

# 3. Update CloudSentry configuration
# 4. Test and verify
# 5. Clean up old storage bucket (optional)
```

### From Pub/Sub to Storage Export

```bash
# 1. Create storage bucket (see Option B)
# 2. Update sink destination
gcloud logging sinks update cloudsentry-sink \
  --destination=storage.googleapis.com/cloudsentry-logs-${PROJECT_ID}

# 3. Update CloudSentry configuration for batch processing
# 4. Clean up Pub/Sub resources (optional)
```

## Performance Considerations

### Pub/Sub Performance
- Message throughput: Up to 1MB/s per subscription
- Latency: Typically < 100ms
- Scaling: Automatic with multiple subscribers

### Storage Export Performance
- Export frequency: Every few minutes
- Latency: Higher than Pub/Sub
- Cost: More predictable for large volumes

Choose Pub/Sub for real-time security monitoring and Storage Export for cost-effective batch processing.
