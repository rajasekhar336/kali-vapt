// ============================================
// Core Types - Aligned with Database Schema
// ============================================

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type ValidationStatus = 'pending' | 'validated' | 'false_positive' | 'needs_review';
export type ScanStatus = 'queued' | 'scanning' | 'completed' | 'failed';
export type RiskStatus = 'open' | 'mitigated' | 'accepted';
export type AppRole = 'admin' | 'analyst' | 'viewer';

export type ScanPhase = 
  | 'reconnaissance' 
  | 'crawling' 
  | 'vulnerability_detection' 
  | 'exploitation_checks' 
  | 'report_preparation'
  | 'completed';

export type OWASPCategory = 
  | 'A01:2021-Broken Access Control'
  | 'A02:2021-Cryptographic Failures'
  | 'A03:2021-Injection'
  | 'A04:2021-Insecure Design'
  | 'A05:2021-Security Misconfiguration'
  | 'A06:2021-Vulnerable Components'
  | 'A07:2021-Auth Failures'
  | 'A08:2021-Data Integrity Failures'
  | 'A09:2021-Logging Failures'
  | 'A10:2021-SSRF';

// ============================================
// User & Auth
// ============================================

export interface User {
  id: string;
  email: string;
  username: string;
  role: AppRole;
}

export interface Profile {
  id: string;
  user_id: string;
  username: string;
  full_name: string | null;
  avatar_url: string | null;
  created_at: string;
  updated_at: string;
}

// ============================================
// Domain & Scan
// ============================================

export interface Domain {
  id: string;
  user_id: string;
  domain_name: string;
  scan_status: ScanStatus;
  current_phase: string | null;
  phase_progress: number | null;
  security_score: number | null;
  created_at: string;
  updated_at: string;
}

export interface DomainSummary extends Domain {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  validated: number;
  falsePositives: number;
  needsReview: number;
  pending: number;
}

export interface Scan {
  id: string;
  domain_id: string;
  status: ScanStatus;
  current_phase: string | null;
  tools_used: string[] | null;
  started_at: string;
  completed_at: string | null;
  findings_count: number | null;
}

export interface ScanProgress {
  scanId: string;
  status: ScanStatus;
  currentPhase: ScanPhase;
  phaseProgress: number;
  phases: {
    name: ScanPhase;
    status: 'pending' | 'in_progress' | 'completed';
    startedAt?: string;
    completedAt?: string;
  }[];
  estimatedTimeRemaining?: number;
}

export interface ScanHistoryEntry {
  id: string;
  scanTimestamp: string;
  status: ScanStatus;
  duration: number;
  findingsCount: number;
  securityScore: number;
}

// ============================================
// Finding & Vulnerability
// ============================================

export interface Finding {
  id: string;
  domain_id: string;
  scan_id: string | null;
  title: string;
  description: string | null;
  severity: Severity;
  validation_status: ValidationStatus;
  risk_status: RiskStatus;
  cvss_score: number | null;
  cwe_id: string | null;
  owasp_category: string | null;
  affected_url: string | null;
  evidence: string | null;
  remediation: string | null;
  tool: string | null;
  notes: string | null;
  created_at: string;
  updated_at: string;
}

// ============================================
// Analytics & Charts
// ============================================

export interface ReportSummary {
  total: number;
  validated: number;
  falsePositives: number;
  needsReview: number;
  pending: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface SeverityDistribution {
  severity: Severity;
  count: number;
  percentage: number;
}

export interface ValidationDistribution {
  status: ValidationStatus;
  count: number;
}

export interface FindingsTrend {
  date: string;
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface OWASPDistribution {
  category: string;
  shortName: string;
  count: number;
  severity: Severity;
}

export interface RiskHeatmapCell {
  likelihood: 'low' | 'medium' | 'high';
  impact: 'low' | 'medium' | 'high';
  count: number;
  severity: Severity;
}

export interface DomainChartData {
  securityScore: number;
  severityDistribution: SeverityDistribution[];
  validationDistribution: ValidationDistribution[];
  findingsTrend: FindingsTrend[];
  owaspDistribution: OWASPDistribution[];
  riskHeatmap: RiskHeatmapCell[];
}

// ============================================
// API Request/Response Types
// ============================================

export interface CreateDomainRequest {
  domainName: string;
}

export interface CreateDomainResponse {
  success: boolean;
  domain?: Domain;
  message?: string;
}

export interface StartScanRequest {
  domainId: string;
}

export interface StartScanResponse {
  success: boolean;
  scan?: Scan;
  message?: string;
}

export interface ValidateFindingRequest {
  findingId: string;
  status: ValidationStatus;
  notes?: string;
}

export interface BatchValidateRequest {
  findingIds: string[];
  status: ValidationStatus;
}

export interface UpdateRiskStatusRequest {
  findingId: string;
  riskStatus: RiskStatus;
}

export interface GenerateReportRequest {
  domainId: string;
  includeValidated: boolean;
  includeFalsePositives: boolean;
  includeNeedsReview: boolean;
  format: 'pdf' | 'docx';
}

export interface GenerateReportResponse {
  success: boolean;
  reportUrl?: string;
  message?: string;
}
