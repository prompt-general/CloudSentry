-- Migration 001: Add Cloud Provider Support
-- This migration adds multi-cloud support to the CloudSentry database
-- Author: CloudSentry Team
-- Created: 2024-01-15

-- Add cloud_provider column to findings and events tables
ALTER TABLE findings ADD COLUMN IF NOT EXISTS cloud_provider VARCHAR(20) DEFAULT 'aws';
ALTER TABLE events ADD COLUMN IF NOT EXISTS cloud_provider VARCHAR(20) DEFAULT 'aws';

-- Add indexes for cloud provider queries
CREATE INDEX IF NOT EXISTS idx_findings_cloud_provider ON findings(cloud_provider);
CREATE INDEX IF NOT EXISTS idx_events_cloud_provider ON events(cloud_provider);

-- Add Azure-specific columns to findings
ALTER TABLE findings ADD COLUMN IF NOT EXISTS resource_group VARCHAR(100);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS subscription_id VARCHAR(100);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(100);

-- Add Azure-specific columns to events
ALTER TABLE events ADD COLUMN IF NOT EXISTS resource_group VARCHAR(100);
ALTER TABLE events ADD COLUMN IF NOT EXISTS subscription_id VARCHAR(100);
ALTER TABLE events ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(100);

-- Add composite indexes for Azure-specific queries
CREATE INDEX IF NOT EXISTS idx_findings_azure_subscription ON findings(cloud_provider, subscription_id);
CREATE INDEX IF NOT EXISTS idx_findings_azure_resource_group ON findings(cloud_provider, resource_group);
CREATE INDEX IF NOT EXISTS idx_events_azure_subscription ON events(cloud_provider, subscription_id);
CREATE INDEX IF NOT EXISTS idx_events_azure_resource_group ON events(cloud_provider, resource_group);

-- Update existing records to have cloud_provider = 'aws'
UPDATE findings SET cloud_provider = 'aws' WHERE cloud_provider IS NULL;
UPDATE events SET cloud_provider = 'aws' WHERE cloud_provider IS NULL;

-- Add constraints for cloud provider values
ALTER TABLE findings ADD CONSTRAINT chk_findings_cloud_provider 
    CHECK (cloud_provider IN ('aws', 'azure', 'gcp', 'aws', 'azure', 'gcp'));

ALTER TABLE events ADD CONSTRAINT chk_events_cloud_provider 
    CHECK (cloud_provider IN ('aws', 'azure', 'gcp', 'aws', 'azure', 'gcp'));

-- Add comments for documentation
COMMENT ON COLUMN findings.cloud_provider IS 'Cloud provider (aws, azure, gcp)';
COMMENT ON COLUMN events.cloud_provider IS 'Cloud provider (aws, azure, gcp)';
COMMENT ON COLUMN findings.resource_group IS 'Azure resource group name';
COMMENT ON COLUMN findings.subscription_id IS 'Azure subscription ID';
COMMENT ON COLUMN findings.tenant_id IS 'Azure tenant ID';
COMMENT ON COLUMN events.resource_group IS 'Azure resource group name';
COMMENT ON COLUMN events.subscription_id IS 'Azure subscription ID';
COMMENT ON COLUMN events.tenant_id IS 'Azure tenant ID';

-- Create a migration tracking table
CREATE TABLE IF NOT EXISTS schema_migrations (
    id SERIAL PRIMARY KEY,
    migration_name VARCHAR(100) NOT NULL UNIQUE,
    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    description TEXT
);

-- Record this migration
INSERT INTO schema_migrations (migration_name, description) 
VALUES ('001_add_cloud_provider', 'Add multi-cloud support with Azure-specific columns')
ON CONFLICT (migration_name) DO NOTHING;

-- Migration completion log
DO $$
BEGIN
    RAISE NOTICE 'Migration 001_add_cloud_provider completed successfully';
    RAISE NOTICE 'Added cloud_provider support to findings and events tables';
    RAISE NOTICE 'Added Azure-specific columns: resource_group, subscription_id, tenant_id';
    RAISE NOTICE 'Created indexes for optimized cloud provider queries';
END $$;
