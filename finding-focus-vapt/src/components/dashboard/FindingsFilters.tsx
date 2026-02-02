import { Severity } from '@/types/finding';
import { Input } from '@/components/ui/input';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Search, Filter } from 'lucide-react';

interface Filters {
  severity: Severity | 'all';
  tool: string;
  search: string;
}

interface FindingsFiltersProps {
  filters: Filters;
  tools: string[];
  onFiltersChange: (filters: Filters) => void;
}

export function FindingsFilters({ filters, tools, onFiltersChange }: FindingsFiltersProps) {
  return (
    <div className="glass-panel rounded-lg p-4 animate-fade-in">
      <div className="flex items-center gap-2 mb-4">
        <Filter className="w-4 h-4 text-muted-foreground" />
        <span className="text-sm font-medium text-foreground">Filters</span>
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input
            placeholder="Search URL or Payload..."
            value={filters.search}
            onChange={(e) => onFiltersChange({ ...filters, search: e.target.value })}
            className="pl-9 bg-muted/50 border-border focus:ring-primary"
          />
        </div>

        <Select
          value={filters.severity}
          onValueChange={(value) =>
            onFiltersChange({ ...filters, severity: value as Severity | 'all' })
          }
        >
          <SelectTrigger className="bg-muted/50 border-border">
            <SelectValue placeholder="Severity" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Severities</SelectItem>
            <SelectItem value="critical">Critical</SelectItem>
            <SelectItem value="high">High</SelectItem>
            <SelectItem value="medium">Medium</SelectItem>
            <SelectItem value="low">Low</SelectItem>
          </SelectContent>
        </Select>

        <Select
          value={filters.tool}
          onValueChange={(value) => onFiltersChange({ ...filters, tool: value })}
        >
          <SelectTrigger className="bg-muted/50 border-border">
            <SelectValue placeholder="Tool" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Tools</SelectItem>
            {tools.map((tool) => (
              <SelectItem key={tool} value={tool}>
                {tool}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
    </div>
  );
}
