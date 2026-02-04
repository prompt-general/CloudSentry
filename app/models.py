from sqlalchemy import Column, String, DateTime, Text, Boolean, JSON, Integer
from sqlalchemy.dialects.postgresql import UUID, ARRAY
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime
import uuid

Base = declarative_base()

class Finding(Base):
    __tablename__ = 'findings'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cloud_provider = Column(String(20), default='aws', nullable=False)  # 'aws', 'azure', 'gcp'
    rule_id = Column(String(50), nullable=False)
    resource_id = Column(String(255), nullable=False)
    resource_type = Column(String(50), nullable=False)
    severity = Column(String(20), nullable=False)
    event_id = Column(String(100))
    timestamp = Column(DateTime(timezone=True), nullable=False)
    remediation_steps = Column(Text)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    account_id = Column(String(50))
    region = Column(String(50))
    status = Column(String(20), default='OPEN')
    
    # Azure-specific fields
    resource_group = Column(String(100))
    subscription_id = Column(String(100))
    tenant_id = Column(String(100))
    
    # GCP-specific fields
    project_id = Column(String(100))
    
    def to_dict(self):
        result = {
            'id': str(self.id),
            'cloud_provider': self.cloud_provider,
            'rule_id': self.rule_id,
            'resource_id': self.resource_id,
            'resource_type': self.resource_type,
            'severity': self.severity,
            'event_id': self.event_id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'remediation_steps': self.remediation_steps,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'account_id': self.account_id,
            'region': self.region,
            'status': self.status
        }
        
        # Add Azure-specific fields if present
        if self.resource_group:
            result['resource_group'] = self.resource_group
        if self.subscription_id:
            result['subscription_id'] = self.subscription_id
        if self.tenant_id:
            result['tenant_id'] = self.tenant_id
        
        # Add GCP-specific fields if present
        if self.project_id:
            result['project_id'] = self.project_id
            
        return result

class Event(Base):
    __tablename__ = 'events'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cloud_provider = Column(String(20), default='aws', nullable=False)  # 'aws', 'azure', 'gcp'
    event_id = Column(String(100), unique=True, nullable=False)
    event_name = Column(String(200), nullable=False)
    event_source = Column(String(100), nullable=False)
    event_time = Column(DateTime(timezone=True), nullable=False)
    resource_id = Column(String(255))
    resource_type = Column(String(50))
    account_id = Column(String(50), nullable=False)
    region = Column(String(50), nullable=False)
    raw_event = Column(JSON)
    processed_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    
    # Azure-specific fields
    resource_group = Column(String(100))
    subscription_id = Column(String(100))
    tenant_id = Column(String(100))
    
    # GCP-specific fields
    project_id = Column(String(100))

class RuleMetadata(Base):
    __tablename__ = 'rules'
    
    id = Column(String(50), primary_key=True)
    description = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False)
    resource_types = Column(ARRAY(String), nullable=False)
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at = Column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)

class AuditLog(Base):
    __tablename__ = 'audit_logs'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    audit_type = Column(String(50), nullable=False)
    account_id = Column(String(50))
    start_time = Column(DateTime(timezone=True), nullable=False)
    end_time = Column(DateTime(timezone=True))
    status = Column(String(20), nullable=False)
    findings_count = Column(Integer, default=0)
    error_message = Column(Text)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)