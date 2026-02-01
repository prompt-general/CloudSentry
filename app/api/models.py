from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FindingStatus(str, Enum):
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED = "RESOLVED"
    SUPPRESSED = "SUPPRESSED"


class FindingBase(BaseModel):
    rule_id: str
    resource_id: str
    resource_type: str
    severity: Severity
    event_id: Optional[str] = None
    timestamp: datetime
    remediation_steps: Optional[str] = None
    account_id: Optional[str] = None
    region: Optional[str] = None
    status: FindingStatus = FindingStatus.OPEN


class FindingResponse(FindingBase):
    id: str
    created_at: datetime
    
    class Config:
        from_attributes = True


class FindingUpdate(BaseModel):
    status: Optional[FindingStatus] = None
    remediation_steps: Optional[str] = None


class RuleResponse(BaseModel):
    id: str
    description: str
    severity: Severity
    resource_types: List[str]
    enabled: bool
    created_at: datetime
    updated_at: Optional[datetime] = None


class RuleUpdate(BaseModel):
    enabled: Optional[bool] = None


class EventResponse(BaseModel):
    id: str
    event_id: str
    event_name: str
    event_source: str
    event_time: datetime
    resource_id: Optional[str] = None
    resource_type: Optional[str] = None
    account_id: str
    region: str
    processed_at: datetime


class FindingsSummary(BaseModel):
    total: int
    by_severity: Dict[str, int]
    by_status: Dict[str, int]
    by_resource_type: Dict[str, int]
    time_range: str
    start_time: Optional[str] = None


class AuditLogResponse(BaseModel):
    id: str
    audit_type: str
    account_id: Optional[str] = None
    start_time: datetime
    end_time: Optional[datetime] = None
    status: str
    findings_count: int = 0
    error_message: Optional[str] = None
    created_at: datetime


class WebSocketMessage(BaseModel):
    type: str
    data: Optional[Dict[str, Any]] = None
    message: Optional[str] = None
    timestamp: Optional[str] = None
