import { useState, useEffect, useMemo, useCallback } from 'react';
import { Finding, ValidationStatus, ReportSummary, Severity } from '@/types/finding';
import * as api from '@/services/api';
import { logError, ErrorMessages } from '@/lib/logger';

export interface Filters {
  severity: Severity | 'all';
  tool: string;
  search: string;
}

export function useDomainFindings(domainId: string) {
  const [allFindings, setAllFindings] = useState<Finding[]>([]);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [filters, setFilters] = useState<Filters>({
    severity: 'all',
    tool: 'all',
    search: '',
  });
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Fetch findings for domain
  useEffect(() => {
    async function fetchFindings() {
      if (!domainId) return;
      
      setIsLoading(true);
      setError(null);
      
      try {
        const findings = await api.getDomainFindings(domainId);
        setAllFindings(findings);
      } catch (err) {
        setError(ErrorMessages.LOAD_FINDINGS_FAILED);
        logError(ErrorMessages.LOAD_FINDINGS_FAILED, err, { domainId });
      } finally {
        setIsLoading(false);
      }
    }

    fetchFindings();
    setSelectedIds(new Set());
  }, [domainId]);

  // Extract unique tools for filter dropdown
  const tools = useMemo(() => {
    const toolSet = new Set(allFindings.map((f) => f.tool).filter(Boolean));
    return Array.from(toolSet).sort() as string[];
  }, [allFindings]);

  // Apply filters
  const findings = useMemo(() => {
    return allFindings.filter((finding) => {
      if (filters.severity !== 'all' && finding.severity !== filters.severity) {
        return false;
      }
      if (filters.tool !== 'all' && finding.tool !== filters.tool) {
        return false;
      }
      if (filters.search) {
        const searchLower = filters.search.toLowerCase();
        const matchesUrl = finding.affected_url?.toLowerCase().includes(searchLower) || false;
        const matchesTitle = finding.title?.toLowerCase().includes(searchLower) || false;
        const matchesDescription = finding.description?.toLowerCase().includes(searchLower) || false;
        if (!matchesUrl && !matchesTitle && !matchesDescription) {
          return false;
        }
      }
      return true;
    });
  }, [allFindings, filters]);

  // Calculate summary
  const summary: ReportSummary = useMemo(() => {
    return {
      total: allFindings.length,
      validated: allFindings.filter((f) => f.validation_status === 'validated').length,
      falsePositives: allFindings.filter((f) => f.validation_status === 'false_positive').length,
      needsReview: allFindings.filter((f) => f.validation_status === 'needs_review').length,
      pending: allFindings.filter((f) => f.validation_status === 'pending').length,
      critical: allFindings.filter((f) => f.severity === 'critical' && f.validation_status !== 'false_positive').length,
      high: allFindings.filter((f) => f.severity === 'high' && f.validation_status !== 'false_positive').length,
      medium: allFindings.filter((f) => f.severity === 'medium' && f.validation_status !== 'false_positive').length,
      low: allFindings.filter((f) => f.severity === 'low' && f.validation_status !== 'false_positive').length,
    };
  }, [allFindings]);

  // Update single finding status
  const updateFindingStatus = useCallback(
    async (findingId: string, status: ValidationStatus) => {
      try {
        const updatedFinding = await api.validateFinding(domainId, findingId, status);
        setAllFindings((prev) =>
          prev.map((f) => (f.id === findingId ? updatedFinding : f))
        );
      } catch (err) {
        logError(ErrorMessages.UPDATE_STATUS_FAILED, err, { domainId, findingId, status });
        throw err;
      }
    },
    [domainId]
  );

  // Update finding notes
  const updateFindingNotes = useCallback(
    async (findingId: string, notes: string) => {
      try {
        const updatedFinding = await api.updateFindingNotes(domainId, findingId, notes);
        setAllFindings((prev) =>
          prev.map((f) => (f.id === findingId ? updatedFinding : f))
        );
      } catch (err) {
        logError(ErrorMessages.UPDATE_NOTES_FAILED, err, { domainId, findingId });
        throw err;
      }
    },
    [domainId]
  );

  // Batch update status
  const batchUpdateStatus = useCallback(
    async (findingIds: string[], status: ValidationStatus) => {
      try {
        const updatedFindings = await api.batchValidateFindings(domainId, findingIds, status);
        const updatedMap = new Map(updatedFindings.map((f) => [f.id, f]));
        setAllFindings((prev) =>
          prev.map((f) => updatedMap.get(f.id) || f)
        );
        setSelectedIds(new Set());
      } catch (err) {
        logError(ErrorMessages.BATCH_UPDATE_FAILED, err, { domainId, findingIds, status });
        throw err;
      }
    },
    [domainId]
  );

  // Selection handlers
  const toggleSelection = useCallback((findingId: string) => {
    setSelectedIds((prev) => {
      const newSet = new Set(prev);
      if (newSet.has(findingId)) {
        newSet.delete(findingId);
      } else {
        newSet.add(findingId);
      }
      return newSet;
    });
  }, []);

  const selectAll = useCallback(() => {
    setSelectedIds(new Set(findings.map((f) => f.id)));
  }, [findings]);

  const clearSelection = useCallback(() => {
    setSelectedIds(new Set());
  }, []);

  const refetch = useCallback(async () => {
    if (!domainId) return;
    const findings = await api.getDomainFindings(domainId);
    setAllFindings(findings);
  }, [domainId]);

  return {
    findings,
    allFindings,
    selectedIds,
    filters,
    tools,
    summary,
    isLoading,
    error,
    setFilters,
    updateFindingStatus,
    updateFindingNotes,
    batchUpdateStatus,
    toggleSelection,
    selectAll,
    clearSelection,
    refetch,
  };
}
