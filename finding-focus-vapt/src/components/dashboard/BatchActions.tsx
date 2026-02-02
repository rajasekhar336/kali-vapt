import { Button } from '@/components/ui/button';
import { CheckCircle2, XCircle, AlertTriangle, X } from 'lucide-react';
import { ValidationStatus } from '@/types/finding';

interface BatchActionsProps {
  selectedCount: number;
  onBatchAction: (status: ValidationStatus) => void;
  onClearSelection: () => void;
}

export function BatchActions({ selectedCount, onBatchAction, onClearSelection }: BatchActionsProps) {
  if (selectedCount === 0) return null;

  return (
    <div className="glass-panel rounded-lg p-4 flex flex-wrap items-center gap-3 animate-fade-in">
      <span className="text-sm font-medium text-foreground">
        {selectedCount} finding{selectedCount !== 1 ? 's' : ''} selected
      </span>
      
      <div className="flex items-center gap-2 flex-wrap">
        <Button
          size="sm"
          variant="outline"
          className="gap-1.5 border-status-validated text-status-validated hover:bg-status-validated-bg"
          onClick={() => onBatchAction('validated')}
        >
          <CheckCircle2 className="w-4 h-4" />
          Validate Selected
        </Button>
        
        <Button
          size="sm"
          variant="outline"
          className="gap-1.5 border-status-false-positive text-status-false-positive hover:bg-status-false-positive-bg"
          onClick={() => onBatchAction('false_positive')}
        >
          <XCircle className="w-4 h-4" />
          Mark False Positive
        </Button>
        
        <Button
          size="sm"
          variant="outline"
          className="gap-1.5 border-status-needs-review text-status-needs-review hover:bg-status-needs-review-bg"
          onClick={() => onBatchAction('needs_review')}
        >
          <AlertTriangle className="w-4 h-4" />
          Needs Review
        </Button>
        
        <Button
          size="sm"
          variant="ghost"
          className="gap-1.5 text-muted-foreground hover:text-foreground"
          onClick={onClearSelection}
        >
          <X className="w-4 h-4" />
          Clear
        </Button>
      </div>
    </div>
  );
}
