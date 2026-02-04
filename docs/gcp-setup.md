# Google Cloud Platform Setup Guide for CloudSentry

## Prerequisites

1. **GCP Project**: Active Google Cloud Platform project
2. **gcloud CLI**: Installed and authenticated
3. **Python 3.8+**: For running setup scripts
4. **Docker**: For containerized deployment

## Step 1: Create GCP Service Account

```bash
# Set your project ID
export PROJECT_ID="your-project-id"
gcloud config set project $PROJECT_ID

# Create service account
gcloud iam service-accounts create cloudsentry \
  --display-name="CloudSentry Service Account"

# Grant necessary permissions
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:cloudsentry@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/viewer"

gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:cloudsentry@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/logging.viewer"

gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:cloudsentry@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/pubsub.subscriber"

# Create and download service account key
gcloud iam service-accounts keys create cloudsentry-key.json \
  --iam-account=cloudsentry@${PROJECT_ID}.iam.gserviceaccount.com"

# Get key as base64 (for Docker environment variable)
cat cloudsentry-key.json | base64
```

## Step 2: Enable Required APIs

```bash
# Enable necessary GCP APIs
gcloud services enable logging.googleapis.com
gcloud services enable pubsub.googleapis.com
gcloud services enable cloudresourcemanager.googleapis.com
gcloud services enable storage.googleapis.com
gcloud services enable compute.googleapis.com
gcloud services enable iam.googleapis.com
gcloud services enable secretmanager.googleapis.com
gcloud services enable asset.googleapis.com
gcloud services enable securitycenter.googleapis.com
```

## Step 3: Configure Audit Logs

```bash
# Create audit log sink for CloudSentry
gcloud logging sinks create cloudsentry-audit-sink \
  pubsub.googleapis.com/projects/${PROJECT_ID}/topics/cloudsentry-audit-logs \
  --log-filter='protoPayload.methodName!~"storage.objects.get" AND protoPayload.methodName!~"storage.objects.list" AND protoPayload.methodName!~"storage.objects.download"'

# Grant Pub/Sub publisher role to the logging service account
LOGGING_SA=$(gcloud logging sinks describe cloudsentry-audit-sink --format='value(writerIdentity)')
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:${LOGGING_SA}" \
  --role="roles/pubsub.publisher"
```

## Step 4: Create Pub/Sub Subscription

```bash
# Create Pub/Sub topic (if not created by sink)
gcloud pubsub topics create cloudsentry-audit-logs

# Create subscription for CloudSentry
gcloud pubsub subscriptions create cloudsentry-events \
  --topic=cloudsentry-audit-logs \
  --ack-deadline=60 \
  --message-retention-duration=7d
```

## Step 5: Configure Environment Variables

Create a `.env` file with your GCP configuration:

```bash
# GCP Configuration
ENABLE_GCP=true
GCP_PROJECT_ID=your-project-id
GCP_SERVICE_ACCOUNT_KEY='{"type":"service_account","project_id":"your-project-id",...}'
GCP_PUBSUB_SUBSCRIPTION_ID=cloudsentry-events
GCP_AUDIT_LOG_SINK=cloudsentry-audit-sink

# Multi-cloud settings
DEFAULT_CLOUD_PROVIDER=gcp
```

**Note**: For `GCP_SERVICE_ACCOUNT_KEY`, either:
1. Use the base64-encoded key from Step 1, or
2. Provide the JSON key content directly

## Step 6: Deploy CloudSentry

### Option A: Docker Compose

```bash
# Update docker-compose.yml with GCP environment variables
docker-compose up -d
```

### Option B: Manual Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Run database migrations
python -m alembic upgrade head

# Start the application
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## Step 7: Verify Setup

1. **Check API Health**:
   ```bash
   curl http://localhost:8000/health
   ```

2. **Test GCP Projects Endpoint**:
   ```bash
   curl http://localhost:8000/api/v1/gcp/projects
   ```

3. **Check Dashboard**:
   - Navigate to `http://localhost:3000`
   - Verify GCP findings appear in the dashboard

## Step 8: Test Security Rules

Generate test events to verify security rules are working:

```bash
# Create a public storage bucket (should trigger security rule)
gsutil mb gs://test-public-bucket-${RANDOM}
gsutil iam ch allUsers:objectViewer gs://test-public-bucket-${RANDOM}

# Create a VM with open SSH port (should trigger security rule)
gcloud compute instances create test-vm-${RANDOM} \
  --zone=us-central1-a \
  --image-family=debian-11 \
  --image-project=debian-cloud \
  --tags=http-server,https-server

# Create firewall rule allowing SSH from anywhere (should trigger security rule)
gcloud compute firewall-rules create allow-ssh-${RANDOM} \
  --allow tcp:22 \
  --source-ranges 0.0.0.0/0 \
  --description "Allow SSH from anywhere"
```

## Security Rules Enabled

The following GCP security rules are automatically enabled:

1. **GCP-001**: Storage Bucket Public Access
2. **GCP-002**: Firewall Open SSH Rule
3. **GCP-003**: Instance No Service Account Rule
4. **GCP-004**: Bucket No Versioning Rule
5. **GCP-005**: KMS Key No Rotation Rule
6. **GCP-006**: Bucket No Logging Rule
7. **GCP-007**: Public Cloud SQL Rule
8. **GCP-008**: Default Network Rule

## Monitoring and Troubleshooting

### Check Logs

```bash
# Application logs
docker-compose logs app

# GCP Pub/Sub subscription status
gcloud pubsub subscriptions describe cloudsentry-events

# Audit log sink status
gcloud logging sinks describe cloudsentry-audit-sink
```

### Common Issues

1. **Permission Denied**: Ensure service account has required IAM roles
2. **Pub/Sub Not Receiving**: Check audit log sink configuration
3. **No Findings**: Verify audit logs are being generated and sent to Pub/Sub

### Clean Up Test Resources

```bash
# Remove test bucket
gsutil rb gs://test-public-bucket-${RANDOM}

# Remove test VM and firewall rule
gcloud compute instances delete test-vm-${RANDOM} --zone=us-central1-a
gcloud compute firewall-rules delete allow-ssh-${RANDOM}
```

## Production Considerations

1. **Service Account Security**: Use least-privilege IAM roles
2. **Audit Log Filtering**: Configure appropriate log filters to reduce noise
3. **Resource Limits**: Monitor GCP API quotas and limits
4. **Data Retention**: Configure appropriate Pub/Sub message retention
5. **Monitoring**: Set up Cloud Monitoring for CloudSentry metrics

## Additional Configuration

### Custom Audit Log Filters

Modify the audit log sink filter to focus on specific services:

```bash
# Example: Focus only on Storage and Compute
gcloud logging sinks update cloudsentry-audit-sink \
  --log-filter='protoPayload.serviceName="storage.googleapis.com" OR protoPayload.serviceName="compute.googleapis.com"'
```

### Multi-Project Setup

For monitoring multiple GCP projects:

1. Create service account in central project
2. Grant cross-project IAM roles
3. Create audit log sinks in each project pointing to central Pub/Sub topic
4. Configure CloudSentry with the central project ID

## Support

For issues with GCP integration:
1. Check GCP service status
2. Verify IAM permissions
3. Review audit log configuration
4. Consult CloudSentry logs
5. Check GCP documentation for specific service requirements
