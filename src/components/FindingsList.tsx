import React, { useState, useMemo } from 'react';
import { SecurityFinding, Severity, FindingCategory } from '../types';
import {
  AlertOctagon,
  AlertTriangle,
  Info,
  Key,
  Code,
  Package,
  Settings,
  Search,
  CheckCircle2,
  ExternalLink,
  ChevronRight,
  ShieldCheck,
  FileCode,
} from 'lucide-react';

interface FindingsListProps {
  findings: SecurityFinding[];
  onSelectFinding: (finding: SecurityFinding) => void;
  selectedFindingId: string | null;
}

export const FindingsList: React.FC<FindingsListProps> = ({
  findings,
  onSelectFinding,
  selectedFindingId,
}) => {
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');

  const filteredFindings = useMemo(() => {
    return findings.filter((f) => {
      if (severityFilter !== 'ALL' && f.severity !== severityFilter) return false;
      if (categoryFilter !== 'ALL' && f.category !== categoryFilter) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchTitle = f.title.toLowerCase().includes(q);
        const matchFile = f.filePath.toLowerCase().includes(q);
        const matchCwe = f.cwe ? f.cwe.toLowerCase().includes(q) : false;
        const matchDesc = f.description.toLowerCase().includes(q);
        if (!matchTitle && !matchFile && !matchCwe && !matchDesc) return false;
      }
      return true;
    });
  }, [findings, severityFilter, categoryFilter, searchQuery]);

  const getSeverityBadge = (severity: Severity) => {
    switch (severity) {
      case 'CRITICAL':
        return 'bg-red-950/80 text-red-300 border-red-800';
      case 'HIGH':
        return 'bg-orange-950/80 text-orange-300 border-orange-800';
      case 'MEDIUM':
        return 'bg-yellow-950/80 text-yellow-300 border-yellow-800';
      case 'LOW':
        return 'bg-blue-950/80 text-blue-300 border-blue-800';
      case 'INFORMATIONAL':
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  const getCategoryIcon = (category: FindingCategory) => {
    switch (category) {
      case 'SECRETS':
        return <Key className="w-3.5 h-3.5 text-amber-400" />;
      case 'CODE_PATTERNS':
        return <Code className="w-3.5 h-3.5 text-red-400" />;
      case 'DEPENDENCIES':
        return <Package className="w-3.5 h-3.5 text-blue-400" />;
      case 'CONFIGURATION':
        return <Settings className="w-3.5 h-3.5 text-purple-400" />;
    }
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-lg">
      {/* Header and Filter Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 mb-4">
        <div>
          <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider flex items-center gap-2">
            <span>Security Findings Audit</span>
            <span className="px-2 py-0.5 rounded-full text-xs font-mono bg-slate-800 text-slate-300">
              {filteredFindings.length} of {findings.length}
            </span>
          </h3>
          <p className="text-xs text-slate-400">
            Click any finding to inspect code snippet, impact, and production-ready remediation.
          </p>
        </div>

        {/* Search Field */}
        <div className="relative w-full md:w-64">
          <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-3" />
          <input
            id="search-findings-input"
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search findings, CWE, files..."
            className="w-full pl-9 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded-xl text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500"
          />
        </div>
      </div>

      {/* Filter Chips */}
      <div className="flex flex-wrap items-center gap-2 mb-4 pt-2 border-t border-slate-800/80 text-xs">
        {/* Severity Filters */}
        <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800">
          {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map((sev) => (
            <button
              key={sev}
              id={`filter-sev-${sev.toLowerCase()}`}
              onClick={() => setSeverityFilter(sev)}
              className={`px-2.5 py-1 rounded font-medium transition-colors cursor-pointer ${
                severityFilter === sev
                  ? 'bg-blue-600 text-white'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {sev === 'ALL' ? 'All Severities' : sev}
            </button>
          ))}
        </div>

        {/* Category Filters */}
        <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800">
          {(
            [
              { id: 'ALL', label: 'All Categories' },
              { id: 'SECRETS', label: 'Secrets' },
              { id: 'CODE_PATTERNS', label: 'Code SAST' },
              { id: 'DEPENDENCIES', label: 'Dependencies' },
              { id: 'CONFIGURATION', label: 'IaC & Config' },
            ] as const
          ).map((cat) => (
            <button
              key={cat.id}
              id={`filter-cat-${cat.id.toLowerCase()}`}
              onClick={() => setCategoryFilter(cat.id)}
              className={`px-2.5 py-1 rounded font-medium transition-colors cursor-pointer ${
                categoryFilter === cat.id
                  ? 'bg-blue-600 text-white'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {cat.label}
            </button>
          ))}
        </div>
      </div>

      {/* Findings List */}
      {filteredFindings.length === 0 ? (
        <div className="text-center py-12 border border-dashed border-slate-800 rounded-xl bg-slate-950/40">
          <ShieldCheck className="w-10 h-10 text-emerald-400 mx-auto mb-2" />
          <h4 className="text-sm font-semibold text-slate-200">No Security Findings Detected</h4>
          <p className="text-xs text-slate-400 max-w-sm mx-auto mt-1">
            {findings.length === 0
              ? 'Analyzed code meets security standards with no hardcoded credentials or dangerous patterns.'
              : 'No findings match the selected severity and category filters.'}
          </p>
        </div>
      ) : (
        <div className="space-y-2.5">
          {filteredFindings.map((finding) => {
            const isSelected = selectedFindingId === finding.id;
            return (
              <div
                key={finding.id}
                id={`finding-card-${finding.id}`}
                onClick={() => onSelectFinding(finding)}
                className={`p-3.5 rounded-xl border transition-all cursor-pointer flex flex-col sm:flex-row sm:items-center justify-between gap-3 ${
                  isSelected
                    ? 'bg-blue-950/30 border-blue-500 shadow-md ring-1 ring-blue-500/50'
                    : 'bg-slate-950/80 border-slate-800 hover:border-slate-700 hover:bg-slate-950'
                }`}
              >
                <div className="flex items-start gap-3">
                  <div className="mt-0.5 shrink-0">{getCategoryIcon(finding.category)}</div>
                  <div>
                    <div className="flex flex-wrap items-center gap-2 mb-1">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getSeverityBadge(
                          finding.severity
                        )}`}
                      >
                        {finding.severity}
                      </span>
                      <h4 className="text-xs sm:text-sm font-semibold text-slate-100">
                        {finding.title}
                      </h4>
                      {finding.category === 'SECRETS' && (
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-amber-950 text-amber-300 border border-amber-800">
                          Redacted
                        </span>
                      )}
                    </div>

                    <p className="text-xs text-slate-400 line-clamp-1 mb-1.5">
                      {finding.description}
                    </p>

                    <div className="flex flex-wrap items-center gap-3 text-[11px] text-slate-500 font-mono">
                      <span className="flex items-center gap-1 text-slate-400">
                        <FileCode className="w-3 h-3 text-slate-500" />
                        <span>
                          {finding.filePath}:{finding.startLine}
                        </span>
                      </span>
                      {finding.cwe && <span className="text-slate-500">{finding.cwe}</span>}
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0 self-end sm:self-center">
                  <span className="text-xs font-medium text-blue-400 hover:text-blue-300 flex items-center gap-1">
                    <span>Inspect</span>
                    <ChevronRight className="w-4 h-4" />
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
