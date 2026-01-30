from pydantic_settings import BaseSettings
from typing import List, Optional
from functools import lru_cache

class Settings(BaseSettings):
    # App
    app_name: str = "CloudSentry"
    app_version: str = "1.0.0"
    debug: bool = False
    
    # Database
    database_url: str = "postgresql+asyncpg://cloudsentry:changeme@localhost:5432/cloudsentry"
    
    # Redis
    redis_url: str = "redis://localhost:6379/0"
    
    # AWS
    aws_region: str = "us-east-1"
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    aws_role_arn: Optional[str] = None
    
    # Event Sources
    event_bridge_bus: str = "default"
    sqs_queue_url: Optional[str] = None
    
    # Security
    allowed_origins: List[str] = ["http://localhost:3000", "http://localhost:8000"]
    
    # Notifications
    slack_webhook_url: Optional[str] = None
    smtp_host: str = "localhost"
    smtp_port: int = 1025
    smtp_user: str = ""
    smtp_password: str = ""
    notification_email: str = "admin@example.com"
    
    # Scheduler
    full_audit_interval_hours: int = 24
    
    class Config:
        env_file = ".env"
        case_sensitive = False

@lru_cache()
def get_settings() -> Settings:
    return Settings()