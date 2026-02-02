#!/bin/bash

# CloudSentry Production Deployment Script
# This script deploys CloudSentry to production using Docker Compose

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
COMPOSE_FILE="$PROJECT_ROOT/docker-compose.production.yml"
ENV_FILE="$PROJECT_ROOT/.env.production"

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
    
    # Check if Docker is installed
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    # Check if Docker Compose is installed
    if ! command -v docker-compose &> /dev/null; then
        log_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
    
    # Check if .env.production file exists
    if [ ! -f "$ENV_FILE" ]; then
        log_warning ".env.production file not found. Creating from template..."
        cp "$PROJECT_ROOT/.env.production.example" "$ENV_FILE"
        log_warning "Please edit $ENV_FILE with your production configuration before continuing."
        exit 1
    fi
    
    # Check if docker-compose.production.yml exists
    if [ ! -f "$COMPOSE_FILE" ]; then
        log_error "docker-compose.production.yml not found at $COMPOSE_FILE"
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

# Validate environment configuration
validate_config() {
    log_info "Validating environment configuration..."
    
    # Source the environment file
    source "$ENV_FILE"
    
    # Check required variables
    required_vars=(
        "POSTGRES_PASSWORD"
        "REDIS_PASSWORD"
        "JWT_SECRET_KEY"
        "AWS_ACCESS_KEY_ID"
        "AWS_SECRET_ACCESS_KEY"
        "GRAFANA_PASSWORD"
    )
    
    missing_vars=()
    for var in "${required_vars[@]}"; do
        if [ -z "${!var:-}" ] || [[ "${!var}" == *"your_"* ]] || [[ "${!var}" == *"here"* ]]; then
            missing_vars+=("$var")
        fi
    done
    
    if [ ${#missing_vars[@]} -gt 0 ]; then
        log_error "Missing or unset required environment variables:"
        for var in "${missing_vars[@]}"; do
            echo "  - $var"
        done
        log_error "Please update $ENV_FILE with the correct values."
        exit 1
    fi
    
    log_success "Environment configuration validation passed"
}

# Create necessary directories
create_directories() {
    log_info "Creating necessary directories..."
    
    directories=(
        "$PROJECT_ROOT/deployments/ssl"
        "$PROJECT_ROOT/logs"
        "$PROJECT_ROOT/backups"
        "$PROJECT_ROOT/data"
    )
    
    for dir in "${directories[@]}"; do
        if [ ! -d "$dir" ]; then
            mkdir -p "$dir"
            log_info "Created directory: $dir"
        fi
    done
    
    log_success "Directories created/verified"
}

# Generate SSL certificates (self-signed for development, replace with proper certs in production)
generate_ssl() {
    log_info "Checking SSL certificates..."
    
    SSL_DIR="$PROJECT_ROOT/deployments/ssl"
    CERT_FILE="$SSL_DIR/cloudsentry.crt"
    KEY_FILE="$SSL_DIR/cloudsentry.key"
    
    if [ ! -f "$CERT_FILE" ] || [ ! -f "$KEY_FILE" ]; then
        log_warning "SSL certificates not found. Generating self-signed certificates..."
        log_warning "⚠️  REPLACE THESE WITH PROPER SSL CERTIFICATES IN PRODUCTION!"
        
        openssl req -x509 -newkey rsa:4096 -keyout "$KEY_FILE" -out "$CERT_FILE" -days 365 -nodes \
            -subj "/C=US/ST=State/L=City/O=CloudSentry/CN=cloudsentry.local"
        
        log_success "Self-signed SSL certificates generated"
    else
        log_success "SSL certificates found"
    fi
}

# Build and deploy services
deploy_services() {
    log_info "Building and deploying CloudSentry services..."
    
    cd "$PROJECT_ROOT"
    
    # Pull latest images
    log_info "Pulling latest images..."
    docker-compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" pull
    
    # Build custom images
    log_info "Building application images..."
    docker-compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" build --parallel
    
    # Stop existing services
    log_info "Stopping existing services..."
    docker-compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" down
    
    # Start services
    log_info "Starting services..."
    docker-compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" up -d
    
    log_success "Services deployed successfully"
}

# Wait for services to be healthy
wait_for_services() {
    log_info "Waiting for services to be healthy..."
    
    services=("postgres" "redis" "app")
    max_wait=300
    wait_time=0
    
    for service in "${services[@]}"; do
        log_info "Waiting for $service to be healthy..."
        
        while [ $wait_time -lt $max_wait ]; do
            if docker-compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" ps "$service" | grep -q "healthy\|Up"; then
                log_success "$service is healthy"
                break
            fi
            
            sleep 10
            wait_time=$((wait_time + 10))
            
            if [ $wait_time -ge $max_wait ]; then
                log_error "$service did not become healthy within $max_wait seconds"
                return 1
            fi
        done
        
        wait_time=0
    done
    
    log_success "All services are healthy"
}

# Run health checks
run_health_checks() {
    log_info "Running comprehensive health checks..."
    
    # Load environment variables
    source "$ENV_FILE"
    
    # Check main application health
    if curl -f -s "http://localhost:${APP_PORT:-8000}/health" > /dev/null; then
        log_success "Main application health check passed"
    else
        log_error "Main application health check failed"
        return 1
    fi
    
    # Check database connectivity
    if curl -f -s "http://localhost:${APP_PORT:-8000}/api/v1/health/detailed" | grep -q '"database": "healthy"'; then
        log_success "Database connectivity check passed"
    else
        log_error "Database connectivity check failed"
        return 1
    fi
    
    # Check Redis connectivity
    if curl -f -s "http://localhost:${APP_PORT:-8000}/api/v1/health/detailed" | grep -q '"redis": "healthy"'; then
        log_success "Redis connectivity check passed"
    else
        log_error "Redis connectivity check failed"
        return 1
    fi
    
    log_success "All health checks passed"
}

# Display deployment information
display_info() {
    log_success "🎉 CloudSentry deployment completed successfully!"
    echo ""
    echo "📊 Services Information:"
    echo "  - Main Application: http://localhost:${HTTP_PORT:-80}"
    echo "  - HTTPS Application: https://localhost:${HTTPS_PORT:-443}"
    echo "  - API Documentation: http://localhost:${HTTP_PORT:-80}/docs"
    echo "  - Health Check: http://localhost:${HTTP_PORT:-80}/health"
    echo "  - Grafana Dashboard: http://localhost:${GRAFANA_PORT:-3001}"
    echo "  - Prometheus: http://localhost:${PROMETHEUS_PORT:-9090}"
    echo "  - Flower (Celery): http://localhost:${FLOWER_PORT:-5555}"
    echo ""
    echo "🔧 Management Commands:"
    echo "  - View logs: docker-compose -f $COMPOSE_FILE --env-file $ENV_FILE logs -f"
    echo "  - View status: docker-compose -f $COMPOSE_FILE --env-file $ENV_FILE ps"
    echo "  - Stop services: docker-compose -f $COMPOSE_FILE --env-file $ENV_FILE down"
    echo "  - Restart services: docker-compose -f $COMPOSE_FILE --env-file $ENV_FILE restart"
    echo ""
    echo "📁 Important Files:"
    echo "  - Environment: $ENV_FILE"
    echo "  - Compose File: $COMPOSE_FILE"
    echo "  - SSL Certificates: $PROJECT_ROOT/deployments/ssl/"
    echo "  - Logs: $PROJECT_ROOT/logs/"
    echo "  - Backups: $PROJECT_ROOT/backups/"
    echo ""
    echo "🔒 Security Notes:"
    echo "  - Replace self-signed SSL certificates with proper certificates"
    echo "  - Ensure firewall rules are properly configured"
    echo "  - Regularly update passwords and secrets"
    echo "  - Monitor logs for suspicious activity"
}

# Cleanup function
cleanup() {
    if [ $? -ne 0 ]; then
        log_error "Deployment failed. Cleaning up..."
        docker-compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" down || true
    fi
}

# Main execution
main() {
    echo "🚀 CloudSentry Production Deployment"
    echo "====================================="
    echo ""
    
    # Set up cleanup trap
    trap cleanup EXIT
    
    # Execute deployment steps
    check_prerequisites
    validate_config
    create_directories
    generate_ssl
    deploy_services
    wait_for_services
    run_health_checks
    display_info
    
    log_success "Deployment completed successfully!"
}

# Handle script arguments
case "${1:-deploy}" in
    "deploy")
        main
        ;;
    "stop")
        log_info "Stopping CloudSentry services..."
        cd "$PROJECT_ROOT"
        docker-compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" down
        log_success "Services stopped"
        ;;
    "restart")
        log_info "Restarting CloudSentry services..."
        cd "$PROJECT_ROOT"
        docker-compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" restart
        log_success "Services restarted"
        ;;
    "logs")
        cd "$PROJECT_ROOT"
        docker-compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" logs -f "${2:-}"
        ;;
    "status")
        cd "$PROJECT_ROOT"
        docker-compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" ps
        ;;
    "health")
        run_health_checks
        ;;
    "backup")
        log_info "Creating backup..."
        cd "$PROJECT_ROOT"
        ./scripts/backup.sh
        ;;
    "update")
        log_info "Updating CloudSentry..."
        main
        ;;
    "help"|"-h"|"--help")
        echo "CloudSentry Production Deployment Script"
        echo ""
        echo "Usage: $0 [COMMAND]"
        echo ""
        echo "Commands:"
        echo "  deploy    Deploy CloudSentry (default)"
        echo "  stop      Stop all services"
        echo "  restart   Restart all services"
        echo "  logs      Show logs (optional service name)"
        echo "  status    Show service status"
        echo "  health    Run health checks"
        echo "  backup    Create backup"
        echo "  update    Update deployment"
        echo "  help      Show this help message"
        echo ""
        echo "Examples:"
        echo "  $0 deploy           # Deploy the application"
        echo "  $0 logs app         # Show logs for app service"
        echo "  $0 restart          # Restart all services"
        ;;
    *)
        log_error "Unknown command: $1"
        echo "Run '$0 help' for usage information"
        exit 1
        ;;
esac
