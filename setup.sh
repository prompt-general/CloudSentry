#!/bin/bash

# CloudSentry Setup Script
echo "Setting up CloudSentry..."

# Check for Docker
if ! command -v docker &> /dev/null; then
    echo "Error: Docker is not installed"
    exit 1
fi

# Check for Docker Compose
if ! command -v docker-compose &> /dev/null; then
    echo "Error: Docker Compose is not installed"
    exit 1
fi

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    echo "Creating .env file from template..."
    cp .env.example .env
    echo "Please edit .env file with your AWS credentials and settings"
    exit 1
fi

# Build and start services
echo "Building and starting CloudSentry services..."
docker-compose build
docker-compose up -d

echo ""
echo "✅ CloudSentry is starting up!"
echo ""
echo "Services:"
echo "  - Dashboard: http://localhost:3000"
echo "  - API Server: http://localhost:8000"
echo "  - API Docs: http://localhost:8000/docs"
echo "  - WebSocket Test: http://localhost:8000/ws-test"
echo ""
echo "To view logs: docker-compose logs -f"
echo "To stop: docker-compose down"
echo ""
echo "Wait 30 seconds for services to initialize, then open the dashboard."
