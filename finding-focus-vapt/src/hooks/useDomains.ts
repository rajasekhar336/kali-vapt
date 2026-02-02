import { useState, useEffect, useCallback } from 'react';
import { DomainSummary } from '@/types/finding';
import * as api from '@/services/api';

export function useDomains() {
  const [domains, setDomains] = useState<DomainSummary[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchDomains = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    
    try {
      const data = await api.getDomains();
      setDomains(data);
    } catch (err) {
      setError('Failed to load domains');
      console.error('Error fetching domains:', err);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchDomains();
  }, [fetchDomains]);

  const createDomain = useCallback(async (domainName: string) => {
    try {
      const response = await api.createDomain(domainName);
      if (response.success) {
        await fetchDomains();
      }
      return response;
    } catch (err) {
      console.error('Error creating domain:', err);
      throw err;
    }
  }, [fetchDomains]);

  const startScan = useCallback(async (domainId: string) => {
    try {
      const response = await api.startScan(domainId);
      if (response.success) {
        await fetchDomains();
      }
      return response;
    } catch (err) {
      console.error('Error starting scan:', err);
      throw err;
    }
  }, [fetchDomains]);

  return {
    domains,
    isLoading,
    error,
    refetch: fetchDomains,
    createDomain,
    startScan,
  };
}
