import { Severity } from '@/types/finding';
import { cn } from '@/lib/utils';

interface SeverityBadgeProps {
  severity: Severity;
}

export function SeverityBadge({ severity }: SeverityBadgeProps) {
  return (
    <span
      className={cn(
        'severity-badge',
        severity === 'critical' && 'severity-critical',
        severity === 'high' && 'severity-high',
        severity === 'medium' && 'severity-medium',
        severity === 'low' && 'severity-low'
      )}
    >
      {severity}
    </span>
  );
}
