-- Security Events Table for Digital Twin III
-- Run this in Supabase SQL Editor: https://supabase.com/dashboard/project/glvoevxtyufucvykwnsb/sql

-- Drop if exists (for clean re-runs)
DROP TABLE IF EXISTS security_events CASCADE;

-- Create the security_events table
CREATE TABLE security_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_type TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
  source_ip TEXT,
  user_agent TEXT,
  endpoint TEXT NOT NULL,
  payload TEXT,
  threat_type TEXT,
  action TEXT NOT NULL CHECK (action IN ('ALLOW', 'BLOCK', 'CHALLENGE', 'LOG_ONLY')),
  timestamp TIMESTAMPTZ DEFAULT NOW(),
  session_id TEXT,
  user_id UUID,
  metadata JSONB,
  
  -- Valid event types
  CONSTRAINT valid_event_type CHECK (event_type IN (
    'THREAT_DETECTED', 'THREAT_BLOCKED', 'LOGIN_ATTEMPT', 
    'ACCESS_DENIED', 'RATE_LIMITED', 'BOT_DETECTED', 'ARCJET_DECISION'
  ))
);

-- Indexes for performance
CREATE INDEX idx_security_events_timestamp ON security_events(timestamp DESC);
CREATE INDEX idx_security_events_severity ON security_events(severity);
CREATE INDEX idx_security_events_type ON security_events(event_type);
CREATE INDEX idx_security_events_source_ip ON security_events(source_ip);
CREATE INDEX idx_security_events_action ON security_events(action);

-- Enable Row Level Security
ALTER TABLE security_events ENABLE ROW LEVEL SECURITY;

-- Allow anyone to read (for dashboard)
CREATE POLICY "Anyone can read security events" ON security_events
  FOR SELECT
  USING (true);

-- Allow service role to insert
CREATE POLICY "Service role can insert security events" ON security_events
  FOR INSERT
  WITH CHECK (true);

-- Allow service role to update
CREATE POLICY "Service role can update security events" ON security_events
  FOR UPDATE
  USING (true);

-- Insert a test event to verify the table works
INSERT INTO security_events (
  event_type,
  severity,
  source_ip,
  endpoint,
  threat_type,
  action,
  metadata
) VALUES (
  'THREAT_DETECTED',
  'LOW',
  '127.0.0.1',
  '/api/test',
  'TEST_EVENT',
  'LOG_ONLY',
  '{"message": "Table created successfully", "test": true}'::jsonb
);

-- Verify the table
SELECT * FROM security_events;
