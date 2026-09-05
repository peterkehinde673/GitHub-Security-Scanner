import React, { useState } from 'react';
import { SecurityFinding } from '../types';
import {
  X,
  ShieldAlert,
  CheckCircle2,
  Copy,
  Check,
  Sparkles,
  ExternalLink,
  Code2,
  AlertTriangle,
  Lightbulb,
} from 'lucide-react';

interface FindingDetailModalProps {
  finding: SecurityFinding | null;
  onClose: () => void;
  onAskAi: (finding: SecurityFinding) => void;
}

export const FindingDetailModal: React.FC<FindingDetailModalProps> = ({
  finding,
  onClose,
  onAskAi,
}) => {
  const [copiedSnippet, setCopiedSnippet] = useState(false);
  const [copiedFix, setCopiedFix] = useState(false);

  if (!finding) return null;

  const handleCopy = (text: string, isFix: boolean) => {
    navigator.clipboard.writeText(text);
    if (isFix) {
      setCopiedFix(true);
      setTimeout(() => setCopiedFix(false), 2000);
    } else {
      setCopiedSnippet(true);
      setTimeout(() => setCopiedSnippet(false), 2000);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4 overflow-y-auto">
      <div className="bg-slate-900 border border-slate-700/80 rounded-2xl max-w-3xl w-full shadow-2xl overflow-hidden my-8">
        {/* Header */}
        <div className="p-5 border-b border-slate-800 flex items-start justify-between gap-4 bg-slate-950/60">
          <div>
            <div className="flex flex-wrap items-center gap-2 mb-2">
              <span
                className={`px-2.5 py-0.5 rounded text-xs font-bold border ${
                  finding.severity === 'CRITICAL'
                    ? 'bg-red-950 text-red-300 border-red-800'
                    : finding.severity === 'HIGH'
                    ? 'bg-orange-950 text-orange-300 border-orange-800'
                    : finding.severity === 'MEDIUM'
                    ? 'bg-yellow-950 text-yellow-300 border-yellow-800'
                    : 'bg-blue-950 text-blue-300 border-blue-800'
                }`}
              >
                {finding.severity}
              </span>
              <span className="text-xs font-mono text-slate-400 bg-slate-800 px-2 py-0.5 rounded">
                {finding.category}
              </span>
              {finding.cwe && (
                <span className="text-xs font-mono text-slate-400">{finding.cwe}</span>
              )}
            </div>
            <h3 className="text-base sm:text-lg font-bold text-slate-100">{finding.title}</h3>
            <p className="text-xs font-mono text-slate-400 mt-1">
              File: <strong className="text-slate-200">{finding.filePath}</strong> (Lines{' '}
              {finding.startLine}–{finding.endLine})
            </p>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg bg-slate-800 text-slate-400 hover:text-slate-200 hover:bg-slate-700 transition-colors cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="p-5 space-y-4 max-h-[70vh] overflow-y-auto">
          {/* Description */}
          <div>
            <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-1">
              Description
            </h4>
            <p className="text-xs sm:text-sm text-slate-300 leading-relaxed bg-slate-950 p-3 rounded-xl border border-slate-800">
              {finding.description}
            </p>
          </div>

          {/* Security Impact */}
          <div>
            <h4 className="text-xs font-bold text-red-400 uppercase tracking-wider mb-1 flex items-center gap-1.5">
              <AlertTriangle className="w-3.5 h-3.5" />
              <span>Exploitation & Business Impact</span>
            </h4>
            <p className="text-xs sm:text-sm text-red-200 leading-relaxed bg-red-950/30 p-3 rounded-xl border border-red-900/40">
              {finding.impact}
            </p>
          </div>

          {/* Vulnerable Code Snippet */}
          {finding.snippet && (
            <div>
              <div className="flex items-center justify-between mb-1">
                <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                  <Code2 className="w-3.5 h-3.5 text-red-400" />
                  <span>Vulnerable Code Snippet</span>
                </h4>
                <button
                  onClick={() => handleCopy(finding.snippet || '', false)}
                  className="flex items-center gap-1 text-[11px] text-slate-400 hover:text-slate-200 cursor-pointer"
                >
                  {copiedSnippet ? (
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                  ) : (
                    <Copy className="w-3.5 h-3.5" />
                  )}
                  <span>{copiedSnippet ? 'Copied' : 'Copy'}</span>
                </button>
              </div>
              <pre className="p-3 bg-slate-950 rounded-xl border border-red-900/40 text-xs font-mono text-red-300 overflow-x-auto whitespace-pre-wrap">
                {finding.snippet}
              </pre>
            </div>
          )}

          {/* Remediation & Secure Code Snippet */}
          <div>
            <div className="flex items-center justify-between mb-1">
              <h4 className="text-xs font-bold text-emerald-400 uppercase tracking-wider flex items-center gap-1.5">
                <Lightbulb className="w-3.5 h-3.5 text-emerald-400" />
                <span>Remediation Recommendation</span>
              </h4>
              {finding.remediationSnippet && (
                <button
                  onClick={() => handleCopy(finding.remediationSnippet || '', true)}
                  className="flex items-center gap-1 text-[11px] text-emerald-400 hover:text-emerald-300 cursor-pointer"
                >
                  {copiedFix ? (
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                  ) : (
                    <Copy className="w-3.5 h-3.5" />
                  )}
                  <span>{copiedFix ? 'Copied Secure Fix' : 'Copy Fix'}</span>
                </button>
              )}
            </div>
            <div className="bg-emerald-950/20 border border-emerald-900/40 rounded-xl p-3 space-y-2">
              <p className="text-xs sm:text-sm text-emerald-200 leading-relaxed">
                {finding.recommendation}
              </p>
              {finding.remediationSnippet && (
                <pre className="p-2.5 bg-slate-950 rounded-lg border border-emerald-800/60 text-xs font-mono text-emerald-300 overflow-x-auto whitespace-pre-wrap">
                  {finding.remediationSnippet}
                </pre>
              )}
            </div>
          </div>
        </div>

        {/* Footer Actions */}
        <div className="p-4 bg-slate-950 border-t border-slate-800 flex items-center justify-between gap-3">
          <button
            onClick={() => onAskAi(finding)}
            className="flex items-center gap-2 px-4 py-2 rounded-xl bg-purple-900/60 hover:bg-purple-800 text-purple-200 text-xs font-semibold border border-purple-700 transition-colors cursor-pointer"
          >
            <Sparkles className="w-4 h-4 text-purple-400" />
            <span>Ask AI Copilot to Explain & Fix</span>
          </button>

          <button
            onClick={onClose}
            className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold border border-slate-700 transition-colors cursor-pointer"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
