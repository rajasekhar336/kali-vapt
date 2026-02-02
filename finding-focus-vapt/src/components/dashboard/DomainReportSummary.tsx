import { useState } from 'react';
import { FileText, Shield, CheckCircle2, XCircle, AlertTriangle, Clock, Loader2 } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { useToast } from '@/hooks/use-toast';
import { ReportSummary as ReportSummaryType } from '@/types/finding';

interface DomainReportSummaryProps {
  summary: ReportSummaryType;
  domainId: string;
  domainName: string;
}

export function DomainReportSummary({ summary, domainId, domainName }: DomainReportSummaryProps) {
  const { toast } = useToast();
  const [isGenerating, setIsGenerating] = useState(false);

  const handleGenerateReport = async () => {
    if (summary.needsReview > 0) {
      toast({
        title: "Review Required",
        description: `${summary.needsReview} finding(s) still need review before generating the final report.`,
        variant: "destructive",
      });
      return;
    }

    setIsGenerating(true);
    try {
      // TODO: Implement report generation when backend is ready
      toast({
        title: "Report Generation",
        description: `Report generation for ${domainName} will be available soon.`,
      });
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to generate report. Please try again.",
        variant: "destructive",
      });
    } finally {
      setIsGenerating(false);
    }
  };

  const stats = [
    {
      label: 'Total Findings',
      value: summary.total,
      icon: Shield,
      className: 'text-foreground',
      bgClass: 'bg-muted/50',
    },
    {
      label: 'Validated',
      value: summary.validated,
      icon: CheckCircle2,
      className: 'text-status-validated',
      bgClass: 'bg-status-validated-bg',
    },
    {
      label: 'False Positives',
      value: summary.falsePositives,
      icon: XCircle,
      className: 'text-status-false-positive',
      bgClass: 'bg-status-false-positive-bg',
    },
    {
      label: 'Needs Review',
      value: summary.needsReview,
      icon: AlertTriangle,
      className: 'text-status-needs-review',
      bgClass: 'bg-status-needs-review-bg',
    },
    {
      label: 'Pending',
      value: summary.pending,
      icon: Clock,
      className: 'text-status-pending',
      bgClass: 'bg-muted/30',
    },
  ];

  const completionPercentage = summary.total > 0 
    ? Math.round(((summary.validated + summary.falsePositives) / summary.total) * 100)
    : 0;

  return (
    <Card className="glass-panel">
      <CardHeader className="pb-4">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <CardTitle className="text-lg font-semibold flex items-center gap-2">
            <FileText className="w-5 h-5 text-primary" />
            Domain Report Summary
          </CardTitle>
          <div className="flex items-center gap-4">
            <div className="text-sm text-muted-foreground">
              <span className="font-medium text-foreground">{completionPercentage}%</span> complete
            </div>
            <Button
              onClick={handleGenerateReport}
              disabled={isGenerating || summary.total === 0}
              className="gap-2"
            >
              {isGenerating ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Generating...
                </>
              ) : (
                <>
                  <FileText className="w-4 h-4" />
                  Generate Final Report
                </>
              )}
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
          {stats.map((stat) => (
            <div
              key={stat.label}
              className={`flex flex-col items-center p-4 rounded-lg ${stat.bgClass}`}
            >
              <stat.icon className={`w-6 h-6 mb-2 ${stat.className}`} />
              <span className={`text-2xl font-bold ${stat.className}`}>
                {stat.value}
              </span>
              <span className="text-xs text-muted-foreground text-center mt-1">
                {stat.label}
              </span>
            </div>
          ))}
        </div>

        {summary.needsReview > 0 && (
          <div className="mt-4 p-3 rounded-lg bg-status-needs-review-bg border border-status-needs-review/20">
            <p className="text-sm text-status-needs-review flex items-center gap-2">
              <AlertTriangle className="w-4 h-4" />
              {summary.needsReview} finding(s) require review before final report can be generated.
            </p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
