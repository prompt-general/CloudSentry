-- Add GCP-specific fields to database schema
-- Migration: 002_add_gcp_fields.sql

-- Add GCP-specific columns to findings table
ALTER TABLE findings 
ADD COLUMN IF NOT EXISTS project_id VARCHAR(100);

-- Add GCP-specific columns to events table  
ALTER TABLE events 
ADD COLUMN IF NOT EXISTS project_id VARCHAR(100);

-- Add indexes for GCP project queries to improve performance
CREATE INDEX IF NOT EXISTS idx_findings_project ON findings(project_id);
CREATE INDEX IF NOT EXISTS idx_events_project ON events(project_id);

-- Update existing GCP records to use project_id from account_id
-- This ensures data consistency for existing GCP records
UPDATE findings 
SET project_id = account_id 
WHERE cloud_provider = 'gcp' AND project_id IS NULL;

UPDATE events 
SET project_id = account_id 
WHERE cloud_provider = 'gcp' AND project_id IS NULL;

-- Add comment to document the migration
COMMENT ON COLUMN findings.project_id IS 'GCP project identifier for GCP resources';
COMMENT ON COLUMN events.project_id IS 'GCP project identifier for GCP resources';
