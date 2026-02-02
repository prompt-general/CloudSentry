#!/bin/bash

# CloudSentry Health Check Script
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

# Check if Docker is running
check_docker() {
    if ! docker info &> /dev/null; then
        log_error "Docker is not running"
        exit 1
    fi
}

# Check service health
check_service_health() {
    local service=$1
    local url=$2
    local expected_status=${3:-200}
    
    log_info "Checking $service health..."
    
    if curl -k -s -o /dev/null -w "%{http_code}" "$url" | grep -q "$expected_status"; then
        log_success "$service is healthy"
        return 0
    else
        log_error "$service is unhealthy"
        return 1
    fi
}

# Check Docker container status
check_container_status() {
    local service=$1
    local status=$(docker-compose ps -q "$service" | xargs docker inspect --format='{{.State.Status}}' 2>/dev/null || echo "not_found")
    
    if [ "$status" = "running" ]; then
        log_success "$service container is running"
        return 0
    else
        log_error "$service container status: $status"
        return 1
    fi
}

# Main health check
main() {
    echo "🏥 CloudSentry Health Check"
    echo "=========================="
    echo ""
    
    check_docker
    
    local unhealthy_count=0
    
    # Check container status
    echo "📦 Container Status:"
    local services=("postgres" "redis" "app" "dashboard" "nginx" "prometheus" "grafana")
    
    for service in "${services[@]}"; do
        if ! check_container_status "$service"; then
            ((unhealthy_count++))
        fi
    done
    
    echo ""
    echo "🌐 Service Health:"
    
    # Check service endpoints
    local base_url="https://localhost"
    
    # Check main application
    if check_service_health "API Server" "$base_url/health"; then
        log_success "API Server responding"
    else
        ((unhealthy_count++))
    fi
    
    # Check dashboard
    if check_service_health "Dashboard" "http://localhost:3000"; then
        log_success "Dashboard responding"
    else
        log_warning "Dashboard not accessible (may be starting)"
    fi
    
    # Check Prometheus
    if check_service_health "Prometheus" "http://localhost:9090/-/healthy"; then
        log_success "Prometheus healthy"
    else
        log_warning "Prometheus not accessible"
    fi
    
    # Check Grafana
    if check_service_health "Grafana" "http://localhost:3001/api/health"; then
        log_success "Grafana healthy"
    else
        log_warning "Grafana not accessible"
    fi
    
    echo ""
    echo "📊 Resource Usage:"
    docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}" || echo "Unable to get stats"
    
    echo ""
    if [ $unhealthy_count -eq 0 ]; then
        log_success "All services are healthy!"
        exit 0
    else
        log_error "$unhealthy_count services have issues"
        echo ""
        echo "🔧 Troubleshooting:"
        echo "  - View logs: docker-compose logs -f"
        echo "  - Restart services: docker-compose restart"
        echo "  - Check configuration: docker-compose config"
        exit 1
    fi
}

# Run main function
main "$@"
