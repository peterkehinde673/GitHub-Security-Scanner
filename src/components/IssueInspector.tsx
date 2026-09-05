import React from 'react';
import { SecurityIssue } from '../types';
import { ShieldAlert, AlertOctagon, AlertTriangle, Info, CheckCircle2, Wrench, Sparkles, ExternalLink, Copy, Check, FileCode } from 'lucide-react';

interface IssueInspectorProps {
  issue: SecurityIssue | null;
  onApplyFix: (issueId: string) => void;
  onAskAi: (issue: SecurityIssue) => void;
  onClose: () => void;
}

export const IssueInspector: React.FC<IssueInspectorProps> = ({
  issue,
  onApplyFix,
  onAskAi,
  onClose,
}) => {
  const [copied, setCopied] = React.useState(false);

  if (!issue) {
    return (
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-lg h-full flex flex-col items-center justify-center text-center">
        <ShieldAlert className="w-12 h-12 text-slate-700 mb-3" />
        <h4 className="text-sm font-semibold text-slate-300">Select a Security Finding</h4>
        <p className="text-xs text-slate-500 max-w-xs mt-1">
          Click on any vulnerability or secret finding in the list to view its CVSS breakdown, code diff, and automated AI fix.
        </p>
      </div>
    );
  }

  const handleCopyFix = () => {
    if (issue.fixedSnippet) {
      navigator.clipboard.writeText(issue.fixedSnippet);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-lg flex flex-col h-full overflow-y-auto">
      {/* Header */}
      <div className="flex items-start justify-between gap-3 pb-4 border-b border-slate-800 mb-4">
        <div>
          <div className="flex flex-wrap items-center gap-2 mb-2">
            <span
              className={`px-2 py-0.5 rounded text-xs font-bold ${
                issue.severity === 'CRITICAL'
                  ? 'bg-red-950 text-red-400 border border-red-800'
                  : issue.severity === 'HIGH'
                  ? 'bg-orange-950 text-orange-400 border border-orange-800'
                  : issue.severity === 'MEDIUM'
                  ? 'bg-yellow-950 text-yellow-400 border border-yellow-800'
                  : 'bg-blue-950 text-blue-400 border border-blue-800'
              }`}
            >
              {issue.severity} SEVERITY
            </span>
            {issue.cvssScore && (
              <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-950 text-slate-300 border border-slate-800">
                CVSS Score: {issue.cvssScore}
              </span>
            )}
            <span className="text-xs font-mono text-slate-400 bg-slate-950 px-2 py-0.5 rounded border border-slate-800 flex items-center gap-1">
              <FileCode className="w-3.5 h-3.5 text-blue-400" />
              <span>{issue.filePath}:{issue.startLine}</span>
            </span>
          </div>
          <h3 className="text-lg font-bold text-slate-100 leading-tight">
            {issue.title}
          </h3>
          {issue.cwe && (
            <p className="text-xs font-mono text-blue-400 mt-1">{issue.cwe}</p>
          )}
        </div>

        <button
          onClick={onClose}
          className="text-slate-400 hover:text-white text-xs px-2 py-1 rounded bg-slate-800/80 hover:bg-slate-700 cursor-pointer"
        >
          ✕
        </button>
      </div>

      {/* Description & Impact */}
      <div className="space-y-4 mb-5 text-xs text-slate-300">
        <div>
          <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1.5">
            Vulnerability Details
          </h4>
          <p className="leading-relaxed bg-slate-950/60 p-3 rounded-xl border border-slate-800/80">
            {issue.description}
          </p>
        </div>

        {issue.impact && (
          <div>
            <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1.5">
              Exploitation Impact
            </h4>
            <p className="leading-relaxed bg-red-950/20 text-red-300 p-3 rounded-xl border border-red-900/30">
              {issue.impact}
            </p>
          </div>
        )}

        {/* Vulnerable vs Fixed Code Diff */}
        <div>
          <div className="flex items-center justify-between mb-1.5">
            <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
              Code Remediation Diff
            </h4>
            {issue.fixedSnippet && (
              <button
                onClick={handleCopyFix}
                className="flex items-center gap-1 text-[11px] text-slate-400 hover:text-slate-200 cursor-pointer"
              >
                {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                <span>{copied ? 'Copied' : 'Copy Fixed Code'}</span>
              </button>
            )}
          </div>

          <div className="space-y-2">
            {/* Vulnerable block */}
            {issue.vulnerableSnippet && (
              <div className="bg-red-950/30 border border-red-900/50 rounded-xl p-3 font-mono text-xs text-red-200 overflow-x-auto">
                <div className="text-[10px] font-bold text-red-400 uppercase mb-1 flex items-center gap-1">
                  <span>- Vulnerable Code (Line {issue.startLine})</span>
                </div>
                <pre className="whitespace-pre-wrap">{issue.vulnerableSnippet}</pre>
              </div>
            )}

            {/* Proposed Hardened Fix block */}
            {issue.fixedSnippet && (
              <div className="bg-emerald-950/30 border border-emerald-900/50 rounded-xl p-3 font-mono text-xs text-emerald-200 overflow-x-auto">
                <div className="text-[10px] font-bold text-emerald-400 uppercase mb-1 flex items-center gap-1">
                  <span>+ Hardened Replacement Code</span>
                </div>
                <pre className="whitespace-pre-wrap">{issue.fixedSnippet}</pre>
              </div>
            )}
          </div>

          {issue.patchExplanation && (
            <p className="text-[11px] text-slate-400 italic mt-2">
              {issue.patchExplanation}
            </p>
          )}
        </div>

        {/* Step by Step Recommendation */}
        <div>
          <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1.5">
            Remediation Guide
          </h4>
          <div className="bg-slate-950/60 p-3 rounded-xl border border-slate-800/80 leading-relaxed text-slate-300">
            {issue.recommendation}
          </div>
        </div>
      </div>

      {/* Action Footer */}
      <div className="pt-4 border-t border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-3 mt-auto">
        <button
          onClick={() => onAskAi(issue)}
          className="w-full sm:w-auto flex items-center justify-center gap-1.5 px-4 py-2 bg-purple-950/70 hover:bg-purple-900 text-purple-300 border border-purple-700/60 rounded-xl text-xs font-semibold transition-colors cursor-pointer"
        >
          <Sparkles className="w-4 h-4 text-purple-400" />
          <span>Ask AI Copilot for Hardening Help</span>
        </button>

        {issue.fixedSnippet && (
          <button
            onClick={() => onApplyFix(issue.id)}
            disabled={issue.applied}
            className={`w-full sm:w-auto flex items-center justify-center gap-1.5 px-4 py-2 rounded-xl text-xs font-semibold transition-all cursor-pointer ${
              issue.applied
                ? 'bg-emerald-950 text-emerald-300 border border-emerald-800 cursor-default'
                : 'bg-blue-600 hover:bg-blue-500 text-white shadow-lg shadow-blue-600/20'
            }`}
          >
            {issue.applied ? (
              <>
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                <span>Patch Applied</span>
              </>
            ) : (
              <>
                <Wrench className="w-4 h-4" />
                <span>Apply 1-Click Code Patch</span>
              </>
            )}
          </button>
        )}
      </div>
    </div>
  );
};
