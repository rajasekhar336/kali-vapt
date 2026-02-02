/**
 * API Service Layer - VAPT Security Platform
 * 
 * This module provides database operations using Lovable Cloud (PostgreSQL).
 * All operations use the Supabase client for secure, authenticated access.
 */

import { supabase } from '@/integrations/supabase/client';
import type { Database } from '@/integrations/supabase/types';
import { logError, ErrorMessages } from '@/lib/logger';

// Type aliases for database tables
type Domain = Database['public']['Tables']['domains']['Row'];
type DomainInsert = Database['public']['Tables']['domains']['Insert'];
type Finding = Database['public']['Tables']['findings']['Row'];
type FindingUpdate = Database['public']['Tables']['findings']['Update'];
type Scan = Database['public']['Tables']['scans']['Row'];

// Extended types for API responses
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

// ============================================
// DOMAIN OPERATIONS
// ============================================

export async function getDomains(): Promise<DomainSummary[]> {
  const { data: domains, error } = await supabase
    .from('domains')
    .select('*')
    .order('created_at', { ascending: false });

  if (error) {
    logError('Failed to fetch domains', error);
    throw error;
  }

  // Fetch findings counts for each domain
  const domainSummaries = await Promise.all(
    (domains || []).map(async (domain) => {
      const { data: findings } = await supabase
        .from('findings')
        .select('severity, validation_status')
        .eq('domain_id', domain.id);

      const findingsList = findings || [];
      const validFindings = findingsList.filter(f => f.validation_status !== 'false_positive');

      return {
        ...domain,
        total: findingsList.length,
        critical: validFindings.filter(f => f.severity === 'critical').length,
        high: validFindings.filter(f => f.severity === 'high').length,
        medium: validFindings.filter(f => f.severity === 'medium').length,
        low: validFindings.filter(f => f.severity === 'low').length,
        validated: findingsList.filter(f => f.validation_status === 'validated').length,
        falsePositives: findingsList.filter(f => f.validation_status === 'false_positive').length,
        needsReview: findingsList.filter(f => f.validation_status === 'needs_review').length,
        pending: findingsList.filter(f => f.validation_status === 'pending').length,
      };
    })
  );

  return domainSummaries;
}

export async function getDomain(domainId: string): Promise<Domain | null> {
  const { data, error } = await supabase
    .from('domains')
    .select('*')
    .eq('id', domainId)
    .single();

  if (error) {
    if (error.code === 'PGRST116') return null;
    logError('Failed to fetch domain', error);
    throw error;
  }

  return data;
}

export async function createDomain(domainName: string): Promise<{ success: boolean; domain?: Domain; message?: string }> {
  const { data: { user } } = await supabase.auth.getUser();
  
  if (!user) {
    return { success: false, message: 'Not authenticated' };
  }

  const { data, error } = await supabase
    .from('domains')
    .insert({
      user_id: user.id,
      domain_name: domainName,
      scan_status: 'queued',
    })
    .select()
    .single();

  if (error) {
    logError('Failed to create domain', error);
    return { success: false, message: error.message };
  }

  return { success: true, domain: data };
}

export async function deleteDomain(domainId: string): Promise<{ success: boolean; message?: string }> {
  const { error } = await supabase
    .from('domains')
    .delete()
    .eq('id', domainId);

  if (error) {
    logError('Failed to delete domain', error);
    return { success: false, message: error.message };
  }

  return { success: true };
}

// ============================================
// FINDINGS OPERATIONS
// ============================================

export async function getDomainFindings(domainId: string): Promise<Finding[]> {
  const { data, error } = await supabase
    .from('findings')
    .select('*')
    .eq('domain_id', domainId)
    .order('created_at', { ascending: false });

  if (error) {
    logError('Failed to fetch findings', error);
    throw error;
  }

  return data || [];
}

export async function updateFinding(
  findingId: string,
  updates: FindingUpdate
): Promise<Finding> {
  const { data, error } = await supabase
    .from('findings')
    .update(updates)
    .eq('id', findingId)
    .select()
    .single();

  if (error) {
    logError('Failed to update finding', error);
    throw error;
  }

  return data;
}

export async function validateFinding(
  domainId: string,
  findingId: string,
  status: 'pending' | 'validated' | 'false_positive' | 'needs_review',
  notes?: string
): Promise<Finding> {
  const updates: FindingUpdate = { validation_status: status };
  if (notes !== undefined) {
    updates.notes = notes;
  }

  return updateFinding(findingId, updates);
}

export async function batchValidateFindings(
  domainId: string,
  findingIds: string[],
  status: 'pending' | 'validated' | 'false_positive' | 'needs_review'
): Promise<Finding[]> {
  const { data, error } = await supabase
    .from('findings')
    .update({ validation_status: status })
    .in('id', findingIds)
    .select();

  if (error) {
    logError('Failed to batch update findings', error);
    throw error;
  }

  return data || [];
}

export async function updateFindingNotes(
  domainId: string,
  findingId: string,
  notes: string
): Promise<Finding> {
  return updateFinding(findingId, { notes });
}

export async function updateRiskStatus(
  domainId: string,
  findingId: string,
  riskStatus: 'open' | 'mitigated' | 'accepted'
): Promise<Finding> {
  return updateFinding(findingId, { risk_status: riskStatus });
}

// ============================================
// SCAN OPERATIONS
// ============================================

export async function startScan(domainId: string): Promise<{ success: boolean; scan?: Scan; message?: string }> {
  // Update domain status
  const { error: domainError } = await supabase
    .from('domains')
    .update({
      scan_status: 'scanning',
      current_phase: 'reconnaissance',
      phase_progress: 0,
    })
    .eq('id', domainId);

  if (domainError) {
    logError('Failed to update domain for scan', domainError);
    return { success: false, message: domainError.message };
  }

  // Create scan record
  const { data: scan, error: scanError } = await supabase
    .from('scans')
    .insert({
      domain_id: domainId,
      status: 'scanning',
      current_phase: 'reconnaissance',
      tools_used: ['SQLMap', 'XSSer', 'Nikto', 'Nuclei', 'Burp Suite', 'OWASP ZAP'],
    })
    .select()
    .single();

  if (scanError) {
    logError('Failed to create scan', scanError);
    return { success: false, message: scanError.message };
  }

  return { success: true, scan };
}

export async function getScanHistory(domainId: string): Promise<Scan[]> {
  const { data, error } = await supabase
    .from('scans')
    .select('*')
    .eq('domain_id', domainId)
    .order('started_at', { ascending: false });

  if (error) {
    logError('Failed to fetch scan history', error);
    throw error;
  }

  return data || [];
}

// ============================================
// ANALYTICS
// ============================================

export async function getDomainSummary(domainId: string): Promise<ReportSummary> {
  const { data: findings, error } = await supabase
    .from('findings')
    .select('severity, validation_status')
    .eq('domain_id', domainId);

  if (error) {
    logError('Failed to fetch domain summary', error);
    throw error;
  }

  const findingsList = findings || [];
  const validFindings = findingsList.filter(f => f.validation_status !== 'false_positive');

  return {
    total: findingsList.length,
    validated: findingsList.filter(f => f.validation_status === 'validated').length,
    falsePositives: findingsList.filter(f => f.validation_status === 'false_positive').length,
    needsReview: findingsList.filter(f => f.validation_status === 'needs_review').length,
    pending: findingsList.filter(f => f.validation_status === 'pending').length,
    critical: validFindings.filter(f => f.severity === 'critical').length,
    high: validFindings.filter(f => f.severity === 'high').length,
    medium: validFindings.filter(f => f.severity === 'medium').length,
    low: validFindings.filter(f => f.severity === 'low').length,
  };
}

export async function getDomainScore(domainId: string): Promise<number> {
  const summary = await getDomainSummary(domainId);
  
  // Calculate security score (100 = perfect, 0 = critical issues)
  const weights = { critical: 40, high: 25, medium: 10, low: 5 };
  const totalDeduction = 
    summary.critical * weights.critical +
    summary.high * weights.high +
    summary.medium * weights.medium +
    summary.low * weights.low;
  
  return Math.max(0, 100 - totalDeduction);
}

export async function getDomainTools(domainId: string): Promise<string[]> {
  const { data, error } = await supabase
    .from('findings')
    .select('tool')
    .eq('domain_id', domainId);

  if (error) {
    logError('Failed to fetch domain tools', error);
    throw error;
  }

  const tools = new Set((data || []).map(f => f.tool).filter(Boolean));
  return Array.from(tools) as string[];
}
