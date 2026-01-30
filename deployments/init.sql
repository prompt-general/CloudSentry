-- Create tables for CloudSentry

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Findings table
CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    rule_id VARCHAR(50) NOT NULL,
    resource_id VARCHAR(255) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    event_id VARCHAR(100),
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    remediation_steps TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    account_id VARCHAR(50),
    region VARCHAR(50),
    status VARCHAR(20) DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'IN_PROGRESS', 'RESOLVED', 'SUPPRESSED')),
    
    -- Indexes for common queries
    INDEX idx_findings_resource (resource_type, resource_id),
    INDEX idx_findings_severity (severity),
    INDEX idx_findings_timestamp (timestamp),
    INDEX idx_findings_account (account_id)
);

-- Events table (normalized events)
CREATE TABLE events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_id VARCHAR(100) NOT NULL UNIQUE,
    event_name VARCHAR(200) NOT NULL,
    event_source VARCHAR(100) NOT NULL,
    event_time TIMESTAMP WITH TIME ZONE NOT NULL,
    resource_id VARCHAR(255),
    resource_type VARCHAR(50),
    account_id VARCHAR(50) NOT NULL,
    region VARCHAR(50) NOT NULL,
    raw_event JSONB,
    processed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_events_event_time (event_time),
    INDEX idx_events_resource (resource_type, resource_id),
    INDEX idx_events_account (account_id)
);

-- Rules metadata table
CREATE TABLE rules (
    id VARCHAR(50) PRIMARY KEY,
    description TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    resource_types VARCHAR(255)[] NOT NULL,
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Insert initial rules
INSERT INTO rules (id, description, severity, resource_types) VALUES
('S3-001', 'S3 bucket allows public read access', 'HIGH', ARRAY['s3']),
('S3-002', 'S3 bucket has no encryption', 'MEDIUM', ARRAY['s3']),
('EC2-001', 'Security group allows SSH from 0.0.0.0/0', 'HIGH', ARRAY['ec2', 'security-group']),
('EC2-002', 'Security group allows RDP from 0.0.0.0/0', 'HIGH', ARRAY['ec2', 'security-group']),
('IAM-001', 'IAM user has no MFA enabled', 'HIGH', ARRAY['iam']),
('IAM-002', 'IAM policy allows full administrative privileges', 'HIGH', ARRAY['iam']);

-- Create audit logs table
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    audit_type VARCHAR(50) NOT NULL,
    account_id VARCHAR(50),
    start_time TIMESTAMP WITH TIME ZONE NOT NULL,
    end_time TIMESTAMP WITH TIME ZONE,
    status VARCHAR(20) NOT NULL CHECK (status IN ('RUNNING', 'COMPLETED', 'FAILED')),
    findings_count INTEGER DEFAULT 0,
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
