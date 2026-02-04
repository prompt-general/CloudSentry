from pydantic_settings import BaseSettings
from typing import List, Optional, Dict
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
    
    # Azure Configuration
    azure_subscription_id: Optional[str] = None
    azure_tenant_id: Optional[str] = None
    azure_client_id: Optional[str] = None
    azure_client_secret: Optional[str] = None
    azure_eventhub_connection_string: Optional[str] = None
    azure_eventhub_name: str = "insights-activity-logs"
    azure_storage_connection_string: Optional[str] = None
    azure_storage_container: str = "cloudsentry-checkpoints"
    
    # GCP Configuration
    gcp_project_id: Optional[str] = None
    gcp_service_account_key: Optional[str] = None  # JSON string
    gcp_pubsub_subscription_id: Optional[str] = None
    gcp_audit_log_sink: Optional[str] = None
    
    # Cloud Provider Enable/Disable
    enable_aws: bool = True
    enable_azure: bool = False
    enable_gcp: bool = False
    
    # Multi-cloud settings
    default_cloud_provider: str = "aws"
    
    # Event Sources
    event_bridge_bus: str = "default"
    sqs_queue_url: Optional[str] = None
    
    # Security
    allowed_origins: List[str] = ["http://localhost:3000", "http://localhost:8000"]
    allowed_hosts: List[str] = ["localhost", "127.0.0.1"]
    
    # Notifications
    slack_webhook_url: Optional[str] = None
    smtp_host: str = "localhost"
    smtp_port: int = 1025
    smtp_user: str = ""
    smtp_password: str = ""
    notification_email: str = "admin@example.com"
    
    # Scheduler
    full_audit_interval_hours: int = 24
    
    # Multi-account
    enable_multi_account: bool = False
    member_account_role_name: str = "CloudSentryAuditRole"
    auto_discover_accounts: bool = True
    excluded_accounts: List[str] = []
    
    # Cross-account event collection
    central_event_bus_name: str = "default"
    cross_account_sqs_queue_name: str = "cloudsentry-security-events"
    
    # Audit scheduling
    multi_account_audit_interval_hours: int = 24
    max_concurrent_audits: int = 3
    
    # Account-specific settings
    account_configs: Dict[str, Dict] = {}
    
    class Config:
        env_file = ".env"
        env_nested_delimiter = "__"
        case_sensitive = False

@lru_cache()
def get_settings() -> Settings:
    return Settings()