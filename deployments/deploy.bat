@echo off
REM CloudSentry Production Deployment Script for Windows
setlocal enabledelayedexpansion

echo 🚀 Deploying CloudSentry...

REM Check environment
if "%AWS_REGION%"=="" (
    echo Error: AWS_REGION environment variable is required
    exit /b 1
)

if "%AWS_ACCESS_KEY_ID%"=="" (
    echo Error: AWS_ACCESS_KEY_ID environment variable is required
    exit /b 1
)

if "%AWS_SECRET_ACCESS_KEY%"=="" (
    echo Error: AWS_SECRET_ACCESS_KEY environment variable is required
    exit /b 1
)

REM Create necessary directories
if not exist ".\logs" mkdir ".\logs"
if not exist ".\deployments\ssl" mkdir ".\deployments\ssl"
if not exist ".\deployments\nginx-log" mkdir ".\deployments\nginx-log"

REM Generate self-signed SSL certificates for development
if not exist ".\deployments\ssl\cloudsentry.crt" (
    echo Generating SSL certificates...
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 ^
        -keyout ".\deployments\ssl\cloudsentry.key" ^
        -out ".\deployments\ssl\cloudsentry.crt" ^
        -subj "/C=US/ST=State/L=City/O=CloudSentry/CN=cloudsentry.local"
)

REM Set environment
if "%APP_ENV%"=="" set APP_ENV=production
if "%COMPOSE_PROJECT_NAME%"=="" set COMPOSE_PROJECT_NAME=cloudsentry

REM Pull latest images
echo Pulling latest Docker images...
docker-compose pull

REM Build and deploy
echo Stopping existing services...
docker-compose down

echo Building and starting services...
docker-compose up -d --build

echo.
echo ✅ CloudSentry deployed successfully!
echo.
echo Services:
echo   - Dashboard: https://localhost
echo   - API Server: https://localhost/api
echo   - API Docs: https://localhost/api/docs
echo   - Grafana: https://localhost:3001
echo   - Prometheus: http://localhost:9090
echo.
echo To view logs: docker-compose logs -f
echo To stop: docker-compose down
echo.
echo Initial setup may take a few minutes. Check logs for progress.

pause
