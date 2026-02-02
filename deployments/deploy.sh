#!/bin/bash

# CloudSentry Production Deployment Script
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Check if running on supported platform
check_platform() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        log_info "Detected Linux platform"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        log_info "Detected macOS platform"
    elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
        log_warning "Detected Windows platform - make sure you're running this in Git Bash or WSL"
    else
        log_warning "Unknown platform $OSTYPE - proceeding anyway"
    fi
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed or not in PATH"
        exit 1
    fi
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        log_error "Docker Compose is not installed or not in PATH"
        exit 1
    fi
    
    # Check OpenSSL
    if ! command -v openssl &> /dev/null; then
        log_error "OpenSSL is not installed or not in PATH"
        exit 1
    fi
    
    # Check if Docker is running
    if ! docker info &> /dev/null; then
        log_error "Docker is not running. Please start Docker first."
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

# Validate environment variables
validate_environment() {
    log_info "Validating environment variables..."
    
    # Required variables
    local required_vars=("AWS_REGION" "AWS_ACCESS_KEY_ID" "AWS_SECRET_ACCESS_KEY")
    local missing_vars=()
    
    for var in "${required_vars[@]}"; do
        if [ -z "${!var}" ]; then
            missing_vars+=("$var")
        fi
    done
    
    if [ ${#missing_vars[@]} -ne 0 ]; then
        log_error "Missing required environment variables:"
        for var in "${missing_vars[@]}"; do
            echo "  - $var"
        done
        log_error "Please set these variables and try again."
        exit 1
    fi
    
    # Validate AWS region format
    if [[ ! "$AWS_REGION" =~ ^[a-z]{2}-[a-z]+-[0-9]+$ ]]; then
        log_error "Invalid AWS_REGION format. Expected format: us-east-1, eu-west-1, etc."
        exit 1
    fi
    
    # Optional variables with defaults
    export APP_ENV=${APP_ENV:-production}
    export COMPOSE_PROJECT_NAME=${COMPOSE_PROJECT_NAME:-cloudsentry}
    export DB_PASSWORD=${DB_PASSWORD:-$(openssl rand -base64 32)}
    export JWT_SECRET_KEY=${JWT_SECRET_KEY:-$(openssl rand -base64 64)}
    export GRAFANA_PASSWORD=${GRAFANA_PASSWORD:-$(openssl rand -base64 16)}
    
    log_success "Environment validation passed"
}

# Create necessary directories
create_directories() {
    log_info "Creating necessary directories..."
    
    local dirs=(
        "./logs"
        "./deployments/ssl"
        "./deployments/nginx-log"
        "./deployments/grafana/dashboards"
        "./deployments/grafana/datasources"
    )
    
    for dir in "${dirs[@]}"; do
        mkdir -p "$dir"
    done
    
    log_success "Directories created"
}

# Generate SSL certificates
generate_ssl_certificates() {
    log_info "Checking SSL certificates..."
    
    local cert_file="./deployments/ssl/cloudsentry.crt"
    local key_file="./deployments/ssl/cloudsentry.key"
    
    if [ ! -f "$cert_file" ] || [ ! -f "$key_file" ]; then
        log_info "Generating self-signed SSL certificates..."
        
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout "$key_file" \
            -out "$cert_file" \
            -subj "/C=US/ST=State/L=City/O=CloudSentry/CN=cloudsentry.local" \
            2>/dev/null
        
        if [ $? -eq 0 ]; then
            log_success "SSL certificates generated"
        else
            log_error "Failed to generate SSL certificates"
            exit 1
        fi
    else
        log_info "SSL certificates already exist"
    fi
}

# Create environment file
create_env_file() {
    local env_file=".env"
    
    if [ ! -f "$env_file" ]; then
        log_info "Creating .env file..."
        
        cat > "$env_file" << EOF
# CloudSentry Environment Configuration
# Generated on $(date)

# Application
APP_ENV=$APP_ENV
COMPOSE_PROJECT_NAME=$COMPOSE_PROJECT_NAME

# Database
DB_PASSWORD=$DB_PASSWORD

# Security
JWT_SECRET_KEY=$JWT_SECRET_KEY

# AWS Configuration
AWS_REGION=$AWS_REGION
AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY
AWS_SESSION_TOKEN=$AWS_SESSION_TOKEN

# Multi-account (optional)
ENABLE_MULTI_ACCOUNT=${ENABLE_MULTI_ACCOUNT:-false}
MEMBER_ACCOUNT_ROLE_NAME=${MEMBER_ACCOUNT_ROLE_NAME:-CloudSentryAuditRole}
AUTO_DISCOVER_ACCOUNTS=${AUTO_DISCOVER_ACCOUNTS:-true}

# Event Collection (optional)
EVENT_BRIDGE_BUS=${EVENT_BRIDGE_BUS:-default}
SQS_QUEUE_URL=$SQS_QUEUE_URL

# Notifications (optional)
SLACK_WEBHOOK_URL=$SLACK_WEBHOOK_URL
SMTP_HOST=${SMTP_HOST:-smtp.gmail.com}
SMTP_PORT=${SMTP_PORT:-587}
SMTP_USER=$SMTP_USER
SMTP_PASSWORD=$SMTP_PASSWORD
NOTIFICATION_EMAIL=$NOTIFICATION_EMAIL

# Monitoring
GRAFANA_PASSWORD=$GRAFANA_PASSWORD

# CORS (comma-separated, no spaces)
CORS_ORIGINS=${CORS_ORIGINS:-https://localhost,https://localhost:3000,https://localhost:3001}
EOF
        
        log_success ".env file created"
        log_warning "Please review .env file and update optional variables as needed"
    else
        log_info ".env file already exists"
    fi
}

# Backup existing deployment
backup_deployment() {
    if docker-compose ps -q | grep -q .; then
        log_info "Backing up existing deployment..."
        
        local backup_dir="./backups/$(date +%Y%m%d_%H%M%S)"
        mkdir -p "$backup_dir"
        
        # Export database
        if docker-compose ps postgres | grep -q "Up"; then
            log_info "Backing up database..."
            docker-compose exec -T postgres pg_dump -U cloudsentry cloudsentry > "$backup_dir/database.sql"
        fi
        
        # Copy configuration files
        cp -r ./deployments "$backup_dir/" 2>/dev/null || true
        cp .env "$backup_dir/" 2>/dev/null || true
        
        log_success "Backup created in $backup_dir"
    fi
}

# Deploy application
deploy_application() {
    log_info "Deploying CloudSentry..."
    
    # Pull latest images
    log_info "Pulling latest Docker images..."
    docker-compose pull
    
    # Stop existing services
    log_info "Stopping existing services..."
    docker-compose down
    
    # Build and start services
    log_info "Building and starting services..."
    docker-compose up -d --build
    
    # Wait for services to be ready
    log_info "Waiting for services to be ready..."
    sleep 30
    
    # Check service health
    check_service_health
}

# Check service health
check_service_health() {
    log_info "Checking service health..."
    
    local services=("postgres" "redis" "app")
    local unhealthy_services=()
    
    for service in "${services[@]}"; do
        local health=$(docker-compose ps -q "$service" | xargs docker inspect --format='{{.State.Health.Status}}' 2>/dev/null || echo "no-healthcheck")
        
        if [ "$health" = "healthy" ] || [ "$health" = "no-healthcheck" ]; then
            log_success "$service is healthy"
        else
            log_warning "$service health status: $health"
            unhealthy_services+=("$service")
        fi
    done
    
    if [ ${#unhealthy_services[@]} -eq 0 ]; then
        log_success "All core services are healthy"
    else
        log_warning "Some services may still be starting up. Check logs for details."
    fi
}

# Display deployment information
display_info() {
    echo ""
    log_success "CloudSentry deployed successfully!"
    echo ""
    echo "🌐 Services:"
    echo "  - Dashboard: https://localhost"
    echo "  - API Server: https://localhost/api"
    echo "  - API Docs: https://localhost/api/docs"
    echo "  - Grafana: https://localhost:3001 (admin/$GRAFANA_PASSWORD)"
    echo "  - Prometheus: http://localhost:9090"
    echo ""
    echo "🔧 Management Commands:"
    echo "  - View logs: docker-compose logs -f"
    echo "  - Stop services: docker-compose down"
    echo "  - Restart services: docker-compose restart"
    echo "  - Update deployment: ./deployments/deploy.sh"
    echo ""
    echo "📊 Monitoring:"
    echo "  - System metrics: http://localhost:9090"
    echo "  - Dashboards: https://localhost:3001"
    echo ""
    echo "🔐 Security Notes:"
    echo "  - SSL certificates are self-signed (browsers will show warnings)"
    echo "  - Change default passwords in production"
    echo "  - Review .env file for sensitive data"
    echo ""
    echo "⏱️  Initial setup may take a few minutes. Check logs for progress."
}

# Main execution
main() {
    echo "🚀 CloudSentry Production Deployment"
    echo "=================================="
    echo ""
    
    check_platform
    check_prerequisites
    validate_environment
    create_directories
    generate_ssl_certificates
    create_env_file
    backup_deployment
    deploy_application
    display_info
    
    echo ""
    log_success "Deployment completed successfully!"
}

# Handle script interruption
trap 'log_error "Deployment interrupted"; exit 1' INT TERM

# Run main function
main "$@"
