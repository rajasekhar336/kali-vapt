-- VAPT Platform Database Schema
-- Initial database setup for VAPT Web UI

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Scans table
CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    target_domain VARCHAR(255) NOT NULL,
    scan_type VARCHAR(50) DEFAULT 'full',
    status VARCHAR(50) DEFAULT 'pending',
    started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE,
    created_by VARCHAR(100),
    config JSONB,
    metadata JSONB
);

-- Vulnerabilities table
CREATE TABLE vulnerabilities (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
    tool_name VARCHAR(100) NOT NULL,
    title VARCHAR(255) NOT NULL,
    severity VARCHAR(20) CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    issue_type VARCHAR(100),
    endpoint VARCHAR(500),
    description TEXT,
    raw_output TEXT,
    evidence JSONB,
    cvss_score DECIMAL(3,1),
    cve_id VARCHAR(20),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    INDEX (scan_id),
    INDEX (severity),
    INDEX (tool_name),
    INDEX (issue_type)
);

-- AI Remediations table (cached)
CREATE TABLE ai_remediations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    vulnerability_id UUID REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    remediation TEXT NOT NULL,
    confidence VARCHAR(20),
    references TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(vulnerability_id)
);

-- Reports table
CREATE TABLE reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
    report_type VARCHAR(50) DEFAULT 'full',
    format VARCHAR(20) CHECK (format IN ('pdf', 'docx', 'json', 'csv')),
    file_path VARCHAR(500),
    file_size BIGINT,
    generated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE,
    download_count INTEGER DEFAULT 0
);

-- Tool executions table
CREATE TABLE tool_executions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
    tool_name VARCHAR(100) NOT NULL,
    command TEXT,
    status VARCHAR(50) DEFAULT 'pending',
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    exit_code INTEGER,
    stdout_path VARCHAR(500),
    stderr_path VARCHAR(500),
    metadata JSONB
);

-- Users table (basic authentication)
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'user',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_login TIMESTAMP WITH TIME ZONE
);

-- Settings table
CREATE TABLE settings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    key VARCHAR(100) UNIQUE NOT NULL,
    value JSONB,
    description TEXT,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Insert default settings
INSERT INTO settings (key, value, description) VALUES
('ai_timeout', '120', 'AI service timeout in seconds'),
('max_concurrent_scans', '3', 'Maximum concurrent scans'),
('default_scan_timeout', '3600', 'Default scan timeout in seconds'),
('report_retention_days', '30', 'Days to retain reports');

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_scan_severity ON vulnerabilities(scan_id, severity);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_tool_severity ON vulnerabilities(tool_name, severity);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_ai_remediations_vulnerability ON ai_remediations(vulnerability_id);

-- Create view for vulnerability statistics
CREATE VIEW vulnerability_stats AS
SELECT 
    s.id as scan_id,
    s.target_domain,
    s.status as scan_status,
    COUNT(v.id) as total_vulnerabilities,
    COUNT(CASE WHEN v.severity = 'critical' THEN 1 END) as critical_count,
    COUNT(CASE WHEN v.severity = 'high' THEN 1 END) as high_count,
    COUNT(CASE WHEN v.severity = 'medium' THEN 1 END) as medium_count,
    COUNT(CASE WHEN v.severity = 'low' THEN 1 END) as low_count,
    COUNT(CASE WHEN v.severity = 'info' THEN 1 END) as info_count,
    s.started_at,
    s.completed_at
FROM scans s
LEFT JOIN vulnerabilities v ON s.id = v.scan_id
GROUP BY s.id, s.target_domain, s.status, s.started_at, s.completed_at;
