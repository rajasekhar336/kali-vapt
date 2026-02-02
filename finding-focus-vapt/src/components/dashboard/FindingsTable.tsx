import { useState } from 'react';
import { Finding, ValidationStatus } from '@/types/finding';
import { SeverityBadge } from './SeverityBadge';
import { StatusBadge } from './StatusBadge';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Input } from '@/components/ui/input';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from '@/components/ui/tooltip';
import { CheckCircle2, XCircle, AlertTriangle, Edit2, Check, X } from 'lucide-react';
import { cn } from '@/lib/utils';
import { format } from 'date-fns';

interface FindingsTableProps {
  findings: Finding[];
  selectedIds: Set<string>;
  onToggleSelection: (id: string) => void;
  onSelectAll: () => void;
  onUpdateStatus: (id: string, status: ValidationStatus) => void;
  onUpdateNotes: (id: string, notes: string) => void;
}

export function FindingsTable({
  findings,
  selectedIds,
  onToggleSelection,
  onSelectAll,
  onUpdateStatus,
  onUpdateNotes,
}: FindingsTableProps) {
  const [editingNoteId, setEditingNoteId] = useState<string | null>(null);
  const [noteValue, setNoteValue] = useState('');

  const allSelected = findings.length > 0 && findings.every((f) => selectedIds.has(f.id));
  const someSelected = findings.some((f) => selectedIds.has(f.id));

  const startEditingNote = (finding: Finding) => {
    setEditingNoteId(finding.id);
    setNoteValue(finding.notes || '');
  };

  const saveNote = (id: string) => {
    onUpdateNotes(id, noteValue);
    setEditingNoteId(null);
    setNoteValue('');
  };

  const cancelEditNote = () => {
    setEditingNoteId(null);
    setNoteValue('');
  };

  const getRowStatusClass = (status: ValidationStatus) => {
    switch (status) {
      case 'validated':
        return 'status-row-validated';
      case 'false_positive':
        return 'status-row-false-positive';
      case 'needs_review':
        return 'status-row-needs-review';
      default:
        return 'status-row-pending';
    }
  };

  return (
    <div className="glass-panel rounded-lg overflow-hidden animate-fade-in">
      <div className="overflow-x-auto">
        <Table>
          <TableHeader>
            <TableRow className="border-border hover:bg-transparent">
              <TableHead className="w-12">
                <Checkbox
                  checked={allSelected}
                  onCheckedChange={onSelectAll}
                  aria-label="Select all"
                  className={cn(someSelected && !allSelected && 'data-[state=checked]:bg-muted')}
                />
              </TableHead>
              <TableHead className="font-semibold">Tool</TableHead>
              <TableHead className="font-semibold">Title</TableHead>
              <TableHead className="font-semibold">URL</TableHead>
              <TableHead className="font-semibold">Severity</TableHead>
              <TableHead className="font-semibold">CVSS</TableHead>
              <TableHead className="font-semibold">Status</TableHead>
              <TableHead className="font-semibold">Notes</TableHead>
              <TableHead className="font-semibold text-center">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {findings.map((finding) => (
              <TableRow
                key={finding.id}
                className={cn(
                  'border-border transition-colors',
                  getRowStatusClass(finding.validation_status)
                )}
              >
                <TableCell>
                  <Checkbox
                    checked={selectedIds.has(finding.id)}
                    onCheckedChange={() => onToggleSelection(finding.id)}
                    aria-label={`Select finding ${finding.id}`}
                  />
                </TableCell>
                <TableCell className="font-mono text-sm">{finding.tool || '—'}</TableCell>
                <TableCell>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <span className="font-medium text-sm cursor-help max-w-48 truncate block">
                        {finding.title}
                      </span>
                    </TooltipTrigger>
                    <TooltipContent side="top" className="max-w-md">
                      <p className="text-sm">{finding.description || finding.title}</p>
                    </TooltipContent>
                  </Tooltip>
                </TableCell>
                <TableCell>
                  {finding.affected_url ? (
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <span className="font-mono text-xs text-primary cursor-help max-w-32 truncate block">
                          {finding.affected_url}
                        </span>
                      </TooltipTrigger>
                      <TooltipContent side="top" className="max-w-md">
                        <code className="text-xs break-all">{finding.affected_url}</code>
                      </TooltipContent>
                    </Tooltip>
                  ) : (
                    <span className="text-muted-foreground">—</span>
                  )}
                </TableCell>
                <TableCell>
                  <SeverityBadge severity={finding.severity} />
                </TableCell>
                <TableCell className="text-sm">
                  {finding.cvss_score !== null ? (
                    <span className="font-mono">{finding.cvss_score.toFixed(1)}</span>
                  ) : (
                    <span className="text-muted-foreground">—</span>
                  )}
                </TableCell>
                <TableCell>
                  <StatusBadge status={finding.validation_status} />
                </TableCell>
                <TableCell className="min-w-48">
                  {editingNoteId === finding.id ? (
                    <div className="flex items-center gap-1">
                      <Input
                        value={noteValue}
                        onChange={(e) => setNoteValue(e.target.value)}
                        className="h-7 text-xs bg-muted"
                        autoFocus
                        onKeyDown={(e) => {
                          if (e.key === 'Enter') saveNote(finding.id);
                          if (e.key === 'Escape') cancelEditNote();
                        }}
                      />
                      <Button size="icon" variant="ghost" className="h-7 w-7" onClick={() => saveNote(finding.id)}>
                        <Check className="w-3 h-3 text-status-validated" />
                      </Button>
                      <Button size="icon" variant="ghost" className="h-7 w-7" onClick={cancelEditNote}>
                        <X className="w-3 h-3 text-muted-foreground" />
                      </Button>
                    </div>
                  ) : (
                    <div className="flex items-center gap-2 group">
                      <span className="text-xs text-muted-foreground truncate max-w-32">
                        {finding.notes || '—'}
                      </span>
                      <Button
                        size="icon"
                        variant="ghost"
                        className="h-6 w-6 opacity-0 group-hover:opacity-100 transition-opacity"
                        onClick={() => startEditingNote(finding)}
                      >
                        <Edit2 className="w-3 h-3" />
                      </Button>
                    </div>
                  )}
                </TableCell>
                <TableCell>
                  <div className="flex items-center justify-center gap-1">
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <Button
                          size="icon"
                          variant="ghost"
                          className="h-8 w-8 hover:bg-status-validated-bg hover:text-status-validated"
                          onClick={() => onUpdateStatus(finding.id, 'validated')}
                        >
                          <CheckCircle2 className="w-4 h-4" />
                        </Button>
                      </TooltipTrigger>
                      <TooltipContent>Validate</TooltipContent>
                    </Tooltip>
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <Button
                          size="icon"
                          variant="ghost"
                          className="h-8 w-8 hover:bg-status-false-positive-bg hover:text-status-false-positive"
                          onClick={() => onUpdateStatus(finding.id, 'false_positive')}
                        >
                          <XCircle className="w-4 h-4" />
                        </Button>
                      </TooltipTrigger>
                      <TooltipContent>False Positive</TooltipContent>
                    </Tooltip>
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <Button
                          size="icon"
                          variant="ghost"
                          className="h-8 w-8 hover:bg-status-needs-review-bg hover:text-status-needs-review"
                          onClick={() => onUpdateStatus(finding.id, 'needs_review')}
                        >
                          <AlertTriangle className="w-4 h-4" />
                        </Button>
                      </TooltipTrigger>
                      <TooltipContent>Needs Review</TooltipContent>
                    </Tooltip>
                  </div>
                </TableCell>
              </TableRow>
            ))}
            {findings.length === 0 && (
              <TableRow>
                <TableCell colSpan={9} className="text-center py-12 text-muted-foreground">
                  No findings match your filters
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
