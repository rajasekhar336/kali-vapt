import { ValidationStatus } from '@/types/finding';
import { cn } from '@/lib/utils';
import { CheckCircle2, XCircle, AlertTriangle, Clock } from 'lucide-react';

interface StatusBadgeProps {
  status: ValidationStatus;
}

const statusConfig = {
  validated: {
    label: 'Validated',
    icon: CheckCircle2,
    className: 'text-status-validated bg-status-validated-bg',
  },
  false_positive: {
    label: 'False Positive',
    icon: XCircle,
    className: 'text-status-false-positive bg-status-false-positive-bg',
  },
  needs_review: {
    label: 'Needs Review',
    icon: AlertTriangle,
    className: 'text-status-needs-review bg-status-needs-review-bg',
  },
  pending: {
    label: 'Pending',
    icon: Clock,
    className: 'text-status-pending bg-status-pending-bg',
  },
};

export function StatusBadge({ status }: StatusBadgeProps) {
  const config = statusConfig[status];
  const Icon = config.icon;

  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium',
        config.className
      )}
    >
      <Icon className="w-3.5 h-3.5" />
      {config.label}
    </span>
  );
}
