import { ReportSummary as ReportSummaryType } from '@/types/finding';
import { Button } from '@/components/ui/button';
import { FileText, CheckCircle2, XCircle, AlertTriangle, Clock, Shield } from 'lucide-react';
import { toast } from 'sonner';

interface ReportSummaryProps {
  summary: ReportSummaryType;
}

export function ReportSummary({ summary }: ReportSummaryProps) {
  const handleGenerateReport = () => {
    // In production, this would call the backend API
    toast.success('Report generation started', {
      description: 'The final security report is being generated.',
    });
  };

  const stats = [
    {
      label: 'Total Findings',
      value: summary.total,
      icon: Shield,
      color: 'text-primary',
      bgColor: 'bg-primary/10',
    },
    {
      label: 'Validated',
      value: summary.validated,
      icon: CheckCircle2,
      color: 'text-status-validated',
      bgColor: 'bg-status-validated-bg',
    },
    {
      label: 'False Positives',
      value: summary.falsePositives,
      icon: XCircle,
      color: 'text-status-false-positive',
      bgColor: 'bg-status-false-positive-bg',
    },
    {
      label: 'Needs Review',
      value: summary.needsReview,
      icon: AlertTriangle,
      color: 'text-status-needs-review',
      bgColor: 'bg-status-needs-review-bg',
    },
    {
      label: 'Pending',
      value: summary.pending,
      icon: Clock,
      color: 'text-status-pending',
      bgColor: 'bg-status-pending-bg',
    },
  ];

  return (
    <div className="glass-panel rounded-lg p-6 animate-fade-in">
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-6">
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-4 flex-1">
          {stats.map((stat) => (
            <div key={stat.label} className="flex items-center gap-3">
              <div className={`p-2.5 rounded-lg ${stat.bgColor}`}>
                <stat.icon className={`w-5 h-5 ${stat.color}`} />
              </div>
              <div>
                <p className="text-2xl font-bold text-foreground">{stat.value}</p>
                <p className="text-xs text-muted-foreground">{stat.label}</p>
              </div>
            </div>
          ))}
        </div>
        
        <Button
          className="gap-2 bg-primary hover:bg-primary/90 text-primary-foreground font-medium px-6"
          onClick={handleGenerateReport}
        >
          <FileText className="w-4 h-4" />
          Generate Final Report
        </Button>
      </div>
    </div>
  );
}
