from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import logging

from app.config import get_settings
from app.database import get_db, AsyncSessionLocal
from app.api import rest, websocket
from app.engine.event_ingestor import start_event_ingestor
from app.scheduler.audit_scheduler import init_scheduler

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("cloudsentry.log")
    ]
)

logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application startup and shutdown events"""
    logger.info("Starting CloudSentry...")
    
    # Initialize scheduler
    init_scheduler()
    
    # Start event ingestor in background
    await start_event_ingestor()
    
    yield
    
    logger.info("Shutting down CloudSentry...")

# Create FastAPI app
app = FastAPI(
    title="CloudSentry",
    description="Real-time Multi-cloud Security Auditing",
    version="1.0.0",
    lifespan=lifespan
)

# Add CORS middleware
settings = get_settings()
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(rest.router, prefix="/api/v1", tags=["api"])
app.include_router(websocket.router, tags=["websocket"])

@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "service": "CloudSentry",
        "version": "1.0.0",
        "status": "running",
        "docs": "/docs",
        "ws_docs": "/redoc"
    }

@app.get("/health")
async def health_check(db: AsyncSessionLocal = Depends(get_db)):
    """Comprehensive health check"""
    try:
        # Check database
        await db.execute("SELECT 1")
        db_status = "healthy"
    except Exception as e:
        db_status = f"unhealthy: {str(e)}"
    
    return {
        "status": "healthy",
        "database": db_status,
        "timestamp": "2024-01-15T00:00:00Z"  # TODO: Use actual timestamp
    }