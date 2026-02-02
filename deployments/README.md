# CloudSentry Deployment Guide

This guide covers deploying CloudSentry in both development and production environments.

## Quick Start

### Development Environment
```bash
# Clone and navigate to the project
git clone <repository-url>
cd CloudSentry

# Run development deployment
chmod +x deployments/deploy-dev.sh
./deployments/deploy-dev.sh
```

### Production Environment
```bash
# Set required environment variables
export AWS_REGION=us-east-1
export AWS_ACCESS_KEY_ID=your-access-key
export AWS_SECRET_ACCESS_KEY=your-secret-key

# Run production deployment
chmod +x deployments/deploy.sh
./deployments/deploy.sh
```

## Environment Variables

### Required Variables
- `AWS_REGION`: AWS region for resources (e.g., `us-east-1`)
- `AWS_ACCESS_KEY_ID`: AWS access key ID
- `AWS_SECRET_ACCESS_KEY`: AWS secret access key

### Optional Variables
- `APP_ENV`: Environment (`development`, `staging`, `production`) - Default: `production`
- `DB_PASSWORD`: PostgreSQL database password - Auto-generated if not set
- `JWT_SECRET_KEY`: JWT signing secret - Auto-generated if not set
- `GRAFANA_PASSWORD`: Grafana admin password - Auto-generated if not set

### AWS Configuration
- `AWS_SESSION_TOKEN`: AWS session token (for temporary credentials)
- `ENABLE_MULTI_ACCOUNT`: Enable multi-account AWS scanning - Default: `false`
- `MEMBER_ACCOUNT_ROLE_NAME`: IAM role name for member accounts - Default: `CloudSentryAuditRole`
- `AUTO_DISCOVER_ACCOUNTS`: Auto-discover AWS organization accounts - Default: `true`

### Event Collection
- `EVENT_BRIDGE_BUS`: EventBridge bus name - Default: `default`
- `SQS_QUEUE_URL`: SQS queue URL for event collection

### Notifications
- `SLACK_WEBHOOK_URL`: Slack webhook URL for notifications
- `SMTP_HOST`: SMTP server host - Default: `smtp.gmail.com`
- `SMTP_PORT`: SMTP server port - Default: `587`
- `SMTP_USER`: SMTP username
- `SMTP_PASSWORD`: SMTP password
- `NOTIFICATION_EMAIL`: Email address for notifications

### Security
- `CORS_ORIGINS`: Comma-separated list of allowed CORS origins

## Services

### Core Services
- **app**: Main FastAPI application (port 8000)
- **dashboard**: React dashboard (port 3000)
- **postgres**: PostgreSQL database (port 5432)
- **redis**: Redis cache (port 6379)

### Background Services
- **celery-worker**: Background task processor
- **celery-beat**: Scheduled task manager

### Monitoring Services
- **nginx**: Reverse proxy with SSL termination (ports 80, 443)
- **prometheus**: Metrics collection (port 9090)
- **grafana**: Visualization dashboard (port 3001)

## SSL Certificates

The deployment script automatically generates self-signed SSL certificates for development and testing. For production:

1. Replace `./deployments/ssl/cloudsentry.crt` with your certificate
2. Replace `./deployments/ssl/cloudsentry.key` with your private key
3. Update nginx configuration if needed

## Database Management

### Backup
```bash
# Create database backup
docker-compose exec postgres pg_dump -U cloudsentry cloudsentry > backup.sql

# Restore database backup
docker-compose exec -T postgres psql -U cloudsentry cloudsentry < backup.sql
```

### Access
```bash
# Connect to database
docker-compose exec postgres psql -U cloudsentry cloudsentry

# Access Redis
docker-compose exec redis redis-cli
```

## Monitoring and Logging

### View Logs
```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f app

# Multiple services
docker-compose logs -f app postgres redis
```

### Health Checks
```bash
# Check service status
docker-compose ps

# Check application health
curl -k https://localhost/health

# Check metrics
curl http://localhost:9090/targets
```

## Scaling and Performance

### Resource Limits
Adjust resource limits in `docker-compose.yml`:

```yaml
services:
  app:
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 1G
        reservations:
          cpus: '0.5'
          memory: 512M
```

### Horizontal Scaling
```bash
# Scale application services
docker-compose up -d --scale app=2 --scale celery-worker=3
```

## Security Configuration

### Production Security Checklist

1. **Environment Variables**
   - [ ] Change all default passwords
   - [ ] Use strong, unique secrets
   - [ ] Set `APP_ENV=production`

2. **SSL/TLS**
   - [ ] Replace self-signed certificates
   - [ ] Configure proper domain names
   - [ ] Enable HSTS headers

3. **Network Security**
   - [ ] Configure firewall rules
   - [ ] Use private networks where possible
   - [ ] Limit exposed ports

4. **AWS Security**
   - [ ] Use IAM roles instead of access keys when possible
   - [ ] Apply principle of least privilege
   - [ ] Enable CloudTrail logging

5. **Application Security**
   - [ ] Review CORS settings
   - [ ] Configure rate limiting
   - [ ] Enable security headers

## Troubleshooting

### Common Issues

#### Service Won't Start
```bash
# Check logs
docker-compose logs service-name

# Check resource usage
docker stats

# Restart service
docker-compose restart service-name
```

#### Database Connection Issues
```bash
# Check database health
docker-compose exec postgres pg_isready -U cloudsentry

# Reset database
docker-compose down
docker volume rm cloudsentry_postgres_data
docker-compose up -d postgres
```

#### SSL Certificate Issues
```bash
# Regenerate certificates
rm -f ./deployments/ssl/*
./deployments/deploy.sh

# Check certificate validity
openssl x509 -in ./deployments/ssl/cloudsentry.crt -text -noout
```

#### Permission Issues
```bash
# Fix file permissions
sudo chown -R $USER:$USER ./deployments
chmod +x deployments/*.sh
```

### Performance Issues

#### High Memory Usage
```bash
# Monitor resource usage
docker stats

# Clean up unused resources
docker system prune -f
```

#### Slow Database Queries
```bash
# Connect to database and analyze queries
docker-compose exec postgres psql -U cloudsentry cloudsentry
# Then run: SELECT * FROM pg_stat_activity;
```

## Maintenance

### Regular Tasks

1. **Daily**
   - Check service health
   - Review error logs
   - Monitor resource usage

2. **Weekly**
   - Update Docker images
   - Backup database
   - Review security logs

3. **Monthly**
   - Rotate secrets
   - Update dependencies
   - Performance tuning

### Updates

```bash
# Update application
git pull origin main
./deployments/deploy.sh

# Update Docker images
docker-compose pull
docker-compose up -d
```

## Support

For issues and support:

1. Check the troubleshooting section above
2. Review application logs: `docker-compose logs -f app`
3. Check service health: `docker-compose ps`
4. Consult the documentation in the repository

## Backup and Recovery

### Automated Backups
Create a backup script:

```bash
#!/bin/bash
# ./deployments/backup.sh

BACKUP_DIR="./backups/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

# Backup database
docker-compose exec -T postgres pg_dump -U cloudsentry cloudsentry > "$BACKUP_DIR/database.sql"

# Backup configuration
cp -r ./deployments "$BACKUP_DIR/"
cp .env "$BACKUP_DIR/" 2>/dev/null || true

echo "Backup created: $BACKUP_DIR"
```

### Recovery
```bash
# Stop services
docker-compose down

# Restore database
docker-compose up -d postgres
docker-compose exec -T postgres psql -U cloudsentry cloudsentry < backup/database.sql

# Start all services
docker-compose up -d
```
