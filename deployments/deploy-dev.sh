#!/bin/bash

# CloudSentry Development Deployment Script
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
    
    # Check if Docker is running
    if ! docker info &> /dev/null; then
        log_error "Docker is not running. Please start Docker first."
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

# Setup development environment
setup_dev_environment() {
    log_info "Setting up development environment..."
    
    # Create necessary directories
    mkdir -p ./logs ./deployments/ssl ./deployments/nginx-log
    
    # Generate development SSL certificates
    if [ ! -f "./deployments/ssl/cloudsentry.crt" ]; then
        log_info "Generating development SSL certificates..."
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout ./deployments/ssl/cloudsentry.key \
            -out ./deployments/ssl/cloudsentry.crt \
            -subj "/C=US/ST=State/L=City/O=CloudSentry/CN=cloudsentry.local" \
            2>/dev/null
    fi
    
    # Create development .env file if it doesn't exist
    if [ ! -f ".env" ]; then
        log_info "Creating development .env file..."
        cat > .env << EOF
# CloudSentry Development Environment
APP_ENV=development
COMPOSE_PROJECT_NAME=cloudsentry-dev

# Database
DB_PASSWORD=devpassword

# Security
JWT_SECRET_KEY=dev-secret-key-change-in-production

# AWS Configuration (optional for development)
AWS_REGION=${AWS_REGION:-us-east-1}
AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}
AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}

# Multi-account
ENABLE_MULTI_ACCOUNT=false
MEMBER_ACCOUNT_ROLE_NAME=CloudSentryAuditRole
AUTO_DISCOVER_ACCOUNTS=true

# Notifications
SMTP_HOST=localhost
SMTP_PORT=1025
SMTP_USER=
SMTP_PASSWORD=
NOTIFICATION_EMAIL=admin@example.com

# Monitoring
GRAFANA_PASSWORD=admin

# CORS
CORS_ORIGINS=http://localhost:3000,http://localhost:8000,http://localhost:3001
EOF
        log_success "Development .env file created"
    fi
    
    export APP_ENV=development
    export COMPOSE_PROJECT_NAME=cloudsentry-dev
}

# Deploy development services
deploy_dev() {
    log_info "Deploying CloudSentry for development..."
    
    # Use development docker-compose file if it exists
    local compose_file="docker-compose.yml"
    if [ -f "docker-compose.dev.yml" ]; then
        compose_file="docker-compose.dev.yml"
        log_info "Using development docker-compose file"
    fi
    
    # Build and start services
    docker-compose -f "$compose_file" down
    docker-compose -f "$compose_file" up -d --build
    
    # Wait a moment for services to start
    sleep 15
    
    log_success "Development deployment completed"
}

# Display development information
display_dev_info() {
    echo ""
    log_success "CloudSentry development environment ready!"
    echo ""
    echo "🌐 Development Services:"
    echo "  - Dashboard: http://localhost:3000"
    echo "  - API Server: http://localhost:8000"
    echo "  - API Docs: http://localhost:8000/docs"
    echo "  - Grafana: http://localhost:3001 (admin/admin)"
    echo "  - Prometheus: http://localhost:9090"
    echo ""
    echo "🔧 Development Commands:"
    echo "  - View logs: docker-compose logs -f"
    echo "  - Stop services: docker-compose down"
    echo "  - Restart services: docker-compose restart"
    echo "  - Access app container: docker-compose exec app bash"
    echo ""
    echo "🛠️  Development Tips:"
    echo "  - Code changes are auto-reloaded in the app container"
    echo "  - Database data persists between restarts"
    echo "  - Use 'docker-compose logs -f app' to watch application logs"
    echo ""
}

# Main execution
main() {
    echo "🔧 CloudSentry Development Deployment"
    echo "=================================="
    echo ""
    
    check_prerequisites
    setup_dev_environment
    deploy_dev
    display_dev_info
    
    echo ""
    log_success "Development environment ready!"
}

# Handle script interruption
trap 'log_error "Development setup interrupted"; exit 1' INT TERM

# Run main function
main "$@"
