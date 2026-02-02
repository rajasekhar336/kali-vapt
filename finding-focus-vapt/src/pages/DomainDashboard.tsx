import { useParams, useNavigate } from 'react-router-dom';
import { ArrowLeft, Globe, Loader2, AlertTriangle } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { DashboardHeader } from '@/components/dashboard/DashboardHeader';
import { FindingsFilters } from '@/components/dashboard/FindingsFilters';
import { BatchActions } from '@/components/dashboard/BatchActions';
import { FindingsTable } from '@/components/dashboard/FindingsTable';
import { DomainReportSummary } from '@/components/dashboard/DomainReportSummary';
import { useDomainFindings } from '@/hooks/useDomainFindings';
import { useState, useEffect } from 'react';
import * as api from '@/services/api';

export default function DomainDashboard() {
  const { domainId } = useParams<{ domainId: string }>();
  const navigate = useNavigate();
  const [domainName, setDomainName] = useState<string>('');
  
  const {
    findings,
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
  } = useDomainFindings(domainId || '');

  useEffect(() => {
    async function fetchDomainName() {
      if (domainId) {
        const domain = await api.getDomain(domainId);
        if (domain) {
          setDomainName(domain.domain_name);
        }
      }
    }
    fetchDomainName();
  }, [domainId]);

  if (!domainId) {
    return (
      <div className="min-h-screen bg-background">
        <DashboardHeader />
        <main className="container mx-auto px-4 py-12 text-center">
          <AlertTriangle className="w-12 h-12 mx-auto mb-4 text-destructive" />
          <p className="text-destructive">Invalid domain ID</p>
          <Button 
            variant="outline" 
            className="mt-4"
            onClick={() => navigate('/domains')}
          >
            Back to Domains
          </Button>
        </main>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background">
      <DashboardHeader />
      
      <main className="container mx-auto px-4 py-6 space-y-6">
        {/* Domain Context Header */}
        <div className="flex flex-col sm:flex-row sm:items-center gap-4">
          <Button
            variant="ghost"
            size="sm"
            className="gap-2 w-fit"
            onClick={() => navigate('/domains')}
          >
            <ArrowLeft className="w-4 h-4" />
            All Domains
          </Button>
          
          <div className="flex items-center gap-3 glass-panel rounded-lg px-4 py-2">
            <Globe className="w-5 h-5 text-primary" />
            <div>
              <span className="text-xs text-muted-foreground uppercase tracking-wider">Target Domain</span>
              <h2 className="font-semibold text-foreground text-lg">{domainName || domainId}</h2>
            </div>
          </div>
        </div>

        {isLoading ? (
          <div className="flex items-center justify-center gap-3 text-muted-foreground py-12">
            <Loader2 className="w-6 h-6 animate-spin" />
            <span>Loading findings...</span>
          </div>
        ) : error ? (
          <div className="text-center text-destructive py-12">
            <AlertTriangle className="w-12 h-12 mx-auto mb-4" />
            <p>{error}</p>
          </div>
        ) : (
          <>
            <DomainReportSummary 
              summary={summary} 
              domainId={domainId}
              domainName={domainName}
            />
            
            <FindingsFilters
              filters={filters}
              tools={tools}
              onFiltersChange={setFilters}
            />
            
            <BatchActions
              selectedCount={selectedIds.size}
              onBatchAction={(status) => batchUpdateStatus(Array.from(selectedIds), status)}
              onClearSelection={clearSelection}
            />
            
            <FindingsTable
              findings={findings}
              selectedIds={selectedIds}
              onToggleSelection={toggleSelection}
              onSelectAll={selectAll}
              onUpdateStatus={updateFindingStatus}
              onUpdateNotes={updateFindingNotes}
            />
          </>
        )}
      </main>
    </div>
  );
}
