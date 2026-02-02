import { useNavigate } from 'react-router-dom';
import { Globe, Shield, AlertTriangle, CheckCircle2, XCircle, Clock, ChevronRight, Loader2 } from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { DashboardHeader } from '@/components/dashboard/DashboardHeader';
import { useDomains } from '@/hooks/useDomains';
import { format } from 'date-fns';

export default function Domains() {
  const navigate = useNavigate();
  const { domains, isLoading, error } = useDomains();

  const getSeverityColor = (summary: { total: number; validated: number; falsePositives: number; needsReview: number; pending: number }) => {
    const pendingCritical = summary.pending > 0 || summary.needsReview > 0;
    if (pendingCritical) return 'border-l-status-needs-review';
    if (summary.validated === summary.total && summary.total > 0) return 'border-l-status-validated';
    return 'border-l-muted';
  };

  if (isLoading) {
    return (
      <div className="min-h-screen bg-background">
        <DashboardHeader />
        <main className="container mx-auto px-4 py-12">
          <div className="flex items-center justify-center gap-3 text-muted-foreground">
            <Loader2 className="w-6 h-6 animate-spin" />
            <span>Loading domains...</span>
          </div>
        </main>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen bg-background">
        <DashboardHeader />
        <main className="container mx-auto px-4 py-12">
          <div className="text-center text-destructive">
            <AlertTriangle className="w-12 h-12 mx-auto mb-4" />
            <p>{error}</p>
          </div>
        </main>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background">
      <DashboardHeader />
      
      <main className="container mx-auto px-4 py-6">
        <div className="mb-6">
          <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
            <Globe className="w-7 h-7 text-primary" />
            Target Domains
          </h1>
          <p className="text-muted-foreground mt-1">
            Select a domain to view and validate scan findings
          </p>
        </div>

        {domains.length === 0 ? (
          <Card className="glass-panel">
            <CardContent className="py-12 text-center">
              <Shield className="w-16 h-16 mx-auto mb-4 text-muted-foreground" />
              <h3 className="text-lg font-medium text-foreground mb-2">No Domains Scanned</h3>
              <p className="text-muted-foreground">
                No scan results are available yet. Run a security scan to populate findings.
              </p>
            </CardContent>
          </Card>
        ) : (
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            {domains.map((domain) => (
              <Card 
                key={domain.id}
                className={`glass-panel border-l-4 ${getSeverityColor(domain)} hover:bg-accent/5 transition-colors cursor-pointer group`}
                onClick={() => navigate(`/domains/${domain.id}`)}
              >
                <CardContent className="p-5">
                  <div className="flex items-start justify-between mb-4">
                    <div className="flex-1 min-w-0">
                      <h3 className="font-semibold text-foreground truncate text-lg">
                        {domain.domain_name}
                      </h3>
                      <p className="text-xs text-muted-foreground mt-1">
                        Created: {format(new Date(domain.created_at), 'MMM dd, yyyy HH:mm')}
                      </p>
                    </div>
                    <ChevronRight className="w-5 h-5 text-muted-foreground group-hover:text-primary transition-colors flex-shrink-0" />
                  </div>

                  <div className="flex items-center gap-2 mb-4">
                    <Badge variant="outline" className="text-xs">
                      {domain.total} findings
                    </Badge>
                    {domain.pending > 0 && (
                      <Badge variant="outline" className="text-xs border-status-pending text-status-pending">
                        {domain.pending} pending
                      </Badge>
                    )}
                  </div>

                  <div className="grid grid-cols-4 gap-2 text-center">
                    <div className="flex flex-col items-center p-2 rounded bg-status-validated-bg/30">
                      <CheckCircle2 className="w-4 h-4 text-status-validated mb-1" />
                      <span className="text-sm font-semibold text-foreground">{domain.validated}</span>
                      <span className="text-[10px] text-muted-foreground">Valid</span>
                    </div>
                    <div className="flex flex-col items-center p-2 rounded bg-status-false-positive-bg/30">
                      <XCircle className="w-4 h-4 text-status-false-positive mb-1" />
                      <span className="text-sm font-semibold text-foreground">{domain.falsePositives}</span>
                      <span className="text-[10px] text-muted-foreground">False+</span>
                    </div>
                    <div className="flex flex-col items-center p-2 rounded bg-status-needs-review-bg/30">
                      <AlertTriangle className="w-4 h-4 text-status-needs-review mb-1" />
                      <span className="text-sm font-semibold text-foreground">{domain.needsReview}</span>
                      <span className="text-[10px] text-muted-foreground">Review</span>
                    </div>
                    <div className="flex flex-col items-center p-2 rounded bg-muted/30">
                      <Clock className="w-4 h-4 text-status-pending mb-1" />
                      <span className="text-sm font-semibold text-foreground">{domain.pending}</span>
                      <span className="text-[10px] text-muted-foreground">Pending</span>
                    </div>
                  </div>

                  <Button 
                    className="w-full mt-4 gap-2"
                    variant="outline"
                    onClick={(e) => {
                      e.stopPropagation();
                      navigate(`/domains/${domain.id}`);
                    }}
                  >
                    View Findings
                    <ChevronRight className="w-4 h-4" />
                  </Button>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </main>
    </div>
  );
}
