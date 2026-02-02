from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from contextlib import asynccontextmanager
import logging
import os
import redis
from datetime import datetime
from typing import Optional

from app.config import get_settings
from app.database import get_db, AsyncSessionLocal
from app.api import rest, websocket
from app.engine.event_ingestor import start_event_ingestor
from app.scheduler.audit_scheduler import init_scheduler
from app.security.middleware import (
    SecurityHeadersMiddleware,
    RateLimitMiddleware,
    LoggingMiddleware
)

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("cloudsentry.log")
    ]
)

logger = logging.getLogger(__name__)

def validate_environment() -> None:
    """Validate critical environment variables"""
    app_env = os.getenv("APP_ENV", "development")
    valid_envs = ["development", "staging", "production", "test"]
    
    if app_env not in valid_envs:
        raise ValueError(f"Invalid APP_ENV '{app_env}'. Must be one of: {valid_envs}")
    
    # Validate Redis URL in production
    if app_env == "production":
        redis_url = os.getenv("REDIS_URL")
        if not redis_url:
            raise ValueError("REDIS_URL is required in production environment")
    
    logger.info(f"Environment validated: {app_env}")

validate_environment()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application startup and shutdown events"""
    logger.info("Starting CloudSentry...")
    
    # Initialize scheduler
    init_scheduler()
    
    # Start event ingestor in background
    await start_event_ingestor()
    
    # Start WebSocket manager
    from app.api.websocket import start_websocket_manager
    await start_websocket_manager()
    
    # Initialize multi-account setup if enabled
    settings = get_settings()
    if settings.enable_multi_account:
        from app.aws.organizations import AWSOrganizationsManager
        org_manager = AWSOrganizationsManager()
        accounts = await org_manager.get_all_accounts()
        logger.info(f"Multi-account enabled. Found {len(accounts)} accounts")
    
    yield
    
    logger.info("Shutting down CloudSentry...")

# Create FastAPI app
app = FastAPI(
    title="CloudSentry",
    description="Real-time Multi-cloud Security Auditing",
    version="1.0.0",
    docs_url="/api/docs" if os.getenv("APP_ENV") != "production" else None,
    redoc_url="/api/redoc" if os.getenv("APP_ENV") != "production" else None,
    openapi_url="/api/openapi.json" if os.getenv("APP_ENV") != "production" else None,
    lifespan=lifespan
)

# Add security middleware
settings = get_settings()
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(LoggingMiddleware)

# Add rate limiting in production
if os.getenv("APP_ENV") == "production":
    app.add_middleware(RateLimitMiddleware, max_requests=100, time_window=60)
    logger.info("Rate limiting enabled for production")

# Include routers
app.include_router(rest.router, prefix="/api/v1", tags=["api"])
app.include_router(websocket.router, tags=["websocket"])

# Add metrics endpoint for Prometheus
@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint"""
    # In production, use prometheus-fastapi-instrumentator
    return {"message": "Metrics endpoint"}

@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "service": "CloudSentry",
        "version": "1.0.0",
        "status": "running",
        "environment": os.getenv("APP_ENV", "development"),
        "multi_account": os.getenv("ENABLE_MULTI_ACCOUNT", "false"),
        "docs": "/api/docs",
        "ws_docs": "/api/redoc"
    }

@app.get("/health")
async def health_check(db: AsyncSessionLocal = Depends(get_db)):
    """Comprehensive health check"""
    db_status = "unhealthy"
    redis_status = "unhealthy"
    
    try:
        # Check database
        await db.execute("SELECT 1")
        db_status = "healthy"
        
        # Check Redis with proper connection cleanup
        redis_client = redis.Redis.from_url(
            os.getenv("REDIS_URL", "redis://localhost:6379"),
            socket_connect_timeout=5,
            socket_timeout=5
        )
        try:
            redis_client.ping()
            redis_status = "healthy"
        finally:
            redis_client.close()
        
    except Exception as e:
        logger.error(f"Health check error: {e}")
        if db_status == "healthy":
            db_status = f"unhealthy: {str(e)}"
    
    return {
        "status": "healthy" if db_status == "healthy" and redis_status == "healthy" else "unhealthy",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "components": {
            "database": db_status,
            "redis": redis_status
        }
    }