import React, { useState, useMemo } from 'react';
import { SecurityIssue, Severity, VulnerabilityCategory } from '../types';
import { ShieldAlert, AlertOctagon, AlertTriangle, Info, Search, Filter, Check, Wrench, ChevronRight, FileCode, CheckCircle2, ShieldCheck } from 'lucide-react';

interface VulnerabilitiesListProps {
  issues: SecurityIssue[];
  selectedIssue: SecurityIssue | null;
  onSelectIssue: (issue: SecurityIssue) => void;
  onApplyFix: (issueId: string) => void;
}

export const VulnerabilitiesList: React.FC<VulnerabilitiesListProps> = ({
  issues,
  selectedIssue,
  onSelectIssue,
  onApplyFix,
}) => {
  const [severityFilter, setSeverityFilter] = useState<Severity | 'ALL'>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');

  const SEVERITY_WEIGHT: Record<string, number> = {
    CRITICAL: 0,
    HIGH: 1,
    MEDIUM: 2,
    LOW: 3,
    INFORMATIONAL: 4,
    INFO: 4,
  };

  const filteredIssues = useMemo(() => {
    return issues
      .filter((issue) => {
        if (severityFilter !== 'ALL' && issue.severity !== severityFilter) return false;
        if (categoryFilter !== 'ALL' && issue.category !== categoryFilter) return false;
        if (searchQuery.trim()) {
          const q = searchQuery.toLowerCase();
          const matchTitle = issue.title.toLowerCase().includes(q);
          const matchDesc = issue.description.toLowerCase().includes(q);
          const matchFile = issue.filePath.toLowerCase().includes(q);
          const matchCwe = issue.cwe?.toLowerCase().includes(q) || false;
          return matchTitle || matchDesc || matchFile || matchCwe;
        }
        return true;
      })
      .sort((a, b) => {
        const weightA = SEVERITY_WEIGHT[a.severity] ?? 99;
        const weightB = SEVERITY_WEIGHT[b.severity] ?? 99;
        if (weightA !== weightB) return weightA - weightB;
        if (a.filePath !== b.filePath) return a.filePath.localeCompare(b.filePath);
        return a.startLine - b.startLine;
      });
  }, [issues, severityFilter, categoryFilter, searchQuery]);

  const getSeverityBadge = (severity: Severity) => {
    switch (severity) {
      case 'CRITICAL':
        return (
          <span className="flex items-center gap-1 px-2 py-0.5 rounded-md bg-red-950/60 text-red-400 border border-red-800 text-[11px] font-bold">
            <AlertOctagon className="w-3 h-3" />
            CRITICAL
          </span>
        );
      case 'HIGH':
        return (
          <span className="flex items-center gap-1 px-2 py-0.5 rounded-md bg-orange-950/60 text-orange-400 border border-orange-800 text-[11px] font-bold">
            <AlertTriangle className="w-3 h-3" />
            HIGH
          </span>
        );
      case 'MEDIUM':
        return (
          <span className="flex items-center gap-1 px-2 py-0.5 rounded-md bg-yellow-950/60 text-yellow-400 border border-yellow-800 text-[11px] font-bold">
            <AlertTriangle className="w-3 h-3" />
            MEDIUM
          </span>
        );
      case 'LOW':
        return (
          <span className="flex items-center gap-1 px-2 py-0.5 rounded-md bg-blue-950/60 text-blue-400 border border-blue-800 text-[11px] font-bold">
            <Info className="w-3 h-3" />
            LOW
          </span>
        );
      default:
        return (
          <span className="flex items-center gap-1 px-2 py-0.5 rounded-md bg-slate-800 text-slate-400 border border-slate-700 text-[11px] font-bold">
            INFO
          </span>
        );
    }
  };

  const uniqueCategories = Array.from(new Set(issues.map(i => i.category)));

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4 lg:p-5 shadow-lg flex flex-col h-full">
      {/* Header & Controls */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 pb-4 border-b border-slate-800 mb-4">
        <div>
          <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
            <span>Security Findings & Remediation</span>
            <span className="px-2 py-0.5 text-xs font-semibold rounded-full bg-slate-800 text-slate-300">
              {filteredIssues.length} / {issues.length}
            </span>
          </h3>
        </div>

        {/* Search input */}
        <div className="relative w-full sm:w-64">
          <div className="absolute inset-y-0 left-0 pl-2.5 flex items-center pointer-events-none text-slate-500">
            <Search className="w-3.5 h-3.5" />
          </div>
          <input
            id="input-search-issues"
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Filter by keyword, file, CWE..."
            className="w-full pl-8 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded-xl text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500"
          />
        </div>
      </div>

      {/* Severity Filter Tabs */}
      <div className="flex flex-wrap items-center gap-1.5 mb-4 text-xs">
        {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map(sev => {
          const count = sev === 'ALL' ? issues.length : issues.filter(i => i.severity === sev).length;
          return (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              className={`px-2.5 py-1 rounded-lg font-medium transition-colors cursor-pointer flex items-center gap-1.5 ${
                severityFilter === sev
                  ? 'bg-blue-600 text-white font-semibold shadow-sm'
                  : 'bg-slate-950 text-slate-400 hover:text-slate-200 border border-slate-800/80'
              }`}
            >
              <span>{sev}</span>
              <span className={`text-[10px] px-1.5 py-0.2 rounded-full ${severityFilter === sev ? 'bg-blue-700 text-white' : 'bg-slate-800 text-slate-400'}`}>
                {count}
              </span>
            </button>
          );
        })}

        {uniqueCategories.length > 1 && (
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="ml-auto px-2.5 py-1 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-300 focus:outline-none focus:border-blue-500 cursor-pointer"
          >
            <option value="ALL">All Categories</option>
            {uniqueCategories.map(cat => (
              <option key={cat} value={cat}>{cat.replace(/_/g, ' ')}</option>
            ))}
          </select>
        )}
      </div>

      {/* Issue Items List */}
      <div className="space-y-2.5 overflow-y-auto max-h-[600px] pr-1">
        {issues.length === 0 ? (
          <div className="text-center py-12 px-4 bg-emerald-950/20 rounded-xl border border-emerald-800/40">
            <CheckCircle2 className="w-10 h-10 text-emerald-400 mx-auto mb-2.5" />
            <h4 className="text-sm font-bold text-emerald-300 mb-1">Clean Target — No Vulnerabilities Detected</h4>
            <p className="text-xs text-slate-400 max-w-sm mx-auto leading-relaxed">
              Deterministic static analysis and pattern scanning identified zero exposed secrets, known CVE advisories, or security flaws in audited files.
            </p>
          </div>
        ) : filteredIssues.length === 0 ? (
          <div className="text-center py-12 bg-slate-950/40 rounded-xl border border-slate-800/60">
            <ShieldAlert className="w-8 h-8 text-slate-600 mx-auto mb-2" />
            <p className="text-xs text-slate-400 font-medium">No security issues matching the current filters.</p>
          </div>
        ) : (
          filteredIssues.map((issue) => {
            const isSelected = selectedIssue?.id === issue.id;

            return (
              <div
                key={issue.id}
                onClick={() => onSelectIssue(issue)}
                className={`p-3.5 rounded-xl border transition-all cursor-pointer relative ${
                  isSelected
                    ? 'bg-slate-800/90 border-blue-500 shadow-md ring-1 ring-blue-500/20'
                    : 'bg-slate-950/50 hover:bg-slate-800/60 border-slate-800/80 hover:border-slate-700'
                }`}
              >
                <div className="flex items-start justify-between gap-2 mb-1.5">
                  <div className="flex flex-wrap items-center gap-2">
                    {getSeverityBadge(issue.severity)}
                    {issue.cvssScore && (
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                        CVSS {issue.cvssScore}
                      </span>
                    )}
                    {issue.applied && (
                      <span className="flex items-center gap-1 text-[10px] font-semibold px-2 py-0.5 rounded-full bg-emerald-950 text-emerald-400 border border-emerald-800">
                        <Check className="w-3 h-3" /> Fix Applied
                      </span>
                    )}
                  </div>

                  <span className="text-[11px] font-mono text-slate-400 flex items-center gap-1 shrink-0">
                    <FileCode className="w-3 h-3 text-slate-500" />
                    <span>{issue.filePath}:{issue.startLine}</span>
                  </span>
                </div>

                <h4 className="text-sm font-semibold text-slate-200 mb-1 leading-snug">
                  {issue.title}
                </h4>

                <p className="text-xs text-slate-400 line-clamp-2 leading-relaxed mb-2.5">
                  {issue.description}
                </p>

                <div className="flex items-center justify-between pt-2 border-t border-slate-800/60 text-xs">
                  <span className="text-[11px] text-slate-500 font-mono truncate max-w-[200px]">
                    {issue.cwe || issue.category}
                  </span>

                  <div className="flex items-center gap-2">
                    {issue.fixedSnippet && !issue.applied && (
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          onApplyFix(issue.id);
                        }}
                        className="flex items-center gap-1 px-2 py-0.5 rounded bg-blue-600/20 hover:bg-blue-600 text-blue-300 hover:text-white border border-blue-500/40 text-[11px] font-medium transition-colors cursor-pointer"
                      >
                        <Wrench className="w-3 h-3" />
                        <span>Apply Patch</span>
                      </button>
                    )}
                    <span className="text-slate-400 hover:text-white flex items-center gap-0.5 text-xs">
                      Details <ChevronRight className="w-3.5 h-3.5" />
                    </span>
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
