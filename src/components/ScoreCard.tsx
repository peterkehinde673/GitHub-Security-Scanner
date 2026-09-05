import React, { useState } from 'react';
import { ScanResult } from '../types';
import { ShieldCheck, AlertOctagon, AlertTriangle, Info, CheckCircle2, ChevronDown, ChevronUp, Calculator, Key, Code, Package, Settings } from 'lucide-react';

interface ScoreCardProps {
  scanResult: ScanResult;
}

export const ScoreCard: React.FC<ScoreCardProps> = ({ scanResult }) => {
  const [showMathDetails, setShowMathDetails] = useState(false);
  const { metrics, summary } = scanResult;

  const getScoreColor = (score: number) => {
    if (score >= 90) return 'text-emerald-400 border-emerald-500/40 bg-emerald-950/20';
    if (score >= 70) return 'text-yellow-400 border-yellow-500/40 bg-yellow-950/20';
    if (score >= 50) return 'text-orange-400 border-orange-500/40 bg-orange-950/20';
    return 'text-red-400 border-red-500/40 bg-red-950/20';
  };

  const getGradeBadge = (grade: string) => {
    switch (grade) {
      case 'A+':
      case 'A':
        return 'bg-emerald-950 text-emerald-300 border-emerald-800';
      case 'B':
        return 'bg-yellow-950 text-yellow-300 border-yellow-800';
      case 'C':
        return 'bg-orange-950 text-orange-300 border-orange-800';
      default:
        return 'bg-red-950 text-red-300 border-red-800';
    }
  };

  const infoCount = metrics.informationalCount ?? metrics.infoCount ?? 0;
  const totalFindings = metrics.totalFindings ?? metrics.totalIssues ?? 0;
  const verdict = metrics.verdict || (metrics.score >= 80 ? 'EXCELLENT' : metrics.score >= 60 ? 'NEEDS_ATTENTION' : 'CRITICAL_RISK');

  return (
    <div className="space-y-4 mb-6">
      {/* Top Overview Bento Grid */}
      <div className="grid grid-cols-1 md:grid-cols-12 gap-4">
        {/* Score & Verdict Card */}
        <div className="md:col-span-4 bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-lg flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
              Security Score
            </span>
            <span
              className={`px-2.5 py-0.5 rounded-full text-xs font-bold border ${getGradeBadge(
                metrics.grade
              )}`}
            >
              Grade {metrics.grade}
            </span>
          </div>

          <div className="my-4 flex items-baseline gap-3">
            <span className="text-5xl font-extrabold tracking-tight text-white">
              {metrics.score}
            </span>
            <span className="text-slate-500 text-sm font-semibold">/ 100</span>
          </div>

          <div className="space-y-2">
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-400">Verdict:</span>
              <span className="font-bold text-slate-200">{verdict.replace(/_/g, ' ')}</span>
            </div>
            <div className="w-full bg-slate-950 rounded-full h-2 overflow-hidden border border-slate-800">
              <div
                className={`h-full transition-all duration-500 ${
                  metrics.score >= 85
                    ? 'bg-emerald-500'
                    : metrics.score >= 70
                    ? 'bg-yellow-500'
                    : metrics.score >= 50
                    ? 'bg-orange-500'
                    : 'bg-red-500'
                }`}
                style={{ width: `${metrics.score}%` }}
              />
            </div>
          </div>
        </div>

        {/* Severity Metrics Counts */}
        <div className="md:col-span-8 bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-lg flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                Vulnerability Severity Breakdown
              </span>
              <span className="text-xs text-slate-500 font-mono">
                {totalFindings} Findings in {metrics.filesAnalyzed} Files
              </span>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              {/* Critical */}
              <div className="p-3 rounded-xl bg-red-950/30 border border-red-900/40">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-bold text-red-400">CRITICAL</span>
                  <AlertOctagon className="w-4 h-4 text-red-400" />
                </div>
                <div className="text-2xl font-black text-red-300">{metrics.criticalCount}</div>
                <div className="text-[10px] text-red-400/80 mt-0.5">-25 pts each</div>
              </div>

              {/* High */}
              <div className="p-3 rounded-xl bg-orange-950/30 border border-orange-900/40">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-bold text-orange-400">HIGH</span>
                  <AlertTriangle className="w-4 h-4 text-orange-400" />
                </div>
                <div className="text-2xl font-black text-orange-300">{metrics.highCount}</div>
                <div className="text-[10px] text-orange-400/80 mt-0.5">-12 pts each</div>
              </div>

              {/* Medium */}
              <div className="p-3 rounded-xl bg-yellow-950/30 border border-yellow-900/40">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-bold text-yellow-400">MEDIUM</span>
                  <Info className="w-4 h-4 text-yellow-400" />
                </div>
                <div className="text-2xl font-black text-yellow-300">{metrics.mediumCount}</div>
                <div className="text-[10px] text-yellow-400/80 mt-0.5">-5 pts each</div>
              </div>

              {/* Low / Info */}
              <div className="p-3 rounded-xl bg-slate-800/50 border border-slate-700/50">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-bold text-slate-300">LOW / INFO</span>
                  <ShieldCheck className="w-4 h-4 text-slate-400" />
                </div>
                <div className="text-2xl font-black text-slate-200">
                  {metrics.lowCount + infoCount}
                </div>
                <div className="text-[10px] text-slate-400 mt-0.5">-1 pt each</div>
              </div>
            </div>
          </div>

          {/* Category Quick Tags */}
          <div className="flex flex-wrap items-center gap-3 pt-3 mt-3 border-t border-slate-800/80 text-xs text-slate-400">
            <span className="text-[11px] uppercase font-semibold text-slate-500">Categories:</span>
            <div className="flex items-center gap-1.5 bg-slate-950 px-2 py-1 rounded-md border border-slate-800">
              <Key className="w-3 h-3 text-red-400" />
              <span>Secrets: {metrics.categoryBreakdown?.secrets ?? metrics.criticalCount}</span>
            </div>
            <div className="flex items-center gap-1.5 bg-slate-950 px-2 py-1 rounded-md border border-slate-800">
              <Code className="w-3 h-3 text-orange-400" />
              <span>Code Patterns: {metrics.categoryBreakdown?.codePatterns ?? metrics.highCount}</span>
            </div>
            <div className="flex items-center gap-1.5 bg-slate-950 px-2 py-1 rounded-md border border-slate-800">
              <Package className="w-3 h-3 text-yellow-400" />
              <span>Dependencies: {metrics.categoryBreakdown?.dependencies ?? 0}</span>
            </div>
            <div className="flex items-center gap-1.5 bg-slate-950 px-2 py-1 rounded-md border border-slate-800">
              <Settings className="w-3 h-3 text-blue-400" />
              <span>Configuration: {metrics.categoryBreakdown?.configuration ?? 0}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Deductions Math Dropdown */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
        <button
          onClick={() => setShowMathDetails(!showMathDetails)}
          className="w-full px-4 py-2.5 flex items-center justify-between text-xs font-semibold text-slate-300 hover:bg-slate-800/50 transition-colors cursor-pointer"
        >
          <div className="flex items-center gap-2">
            <Calculator className="w-4 h-4 text-blue-400" />
            <span>Deterministic Scoring Breakdown & Mathematical Deductions</span>
          </div>
          {showMathDetails ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
        </button>

        {showMathDetails && (
          <div className="p-4 bg-slate-950 border-t border-slate-800 space-y-2 text-xs">
            <p className="text-slate-400 mb-2">
              Formula: <code className="text-blue-300 font-mono">Score = max(0, 100 - Σ(Rule Deductions))</code>
            </p>
            {metrics.scoreDeductions && metrics.scoreDeductions.length > 0 ? (
              <div className="space-y-1.5">
                {metrics.scoreDeductions.map((d, i) => (
                  <div
                    key={i}
                    className="flex items-center justify-between py-1 px-2.5 rounded-md bg-slate-900 border border-slate-800"
                  >
                    <span className="text-slate-300 font-mono text-[11px]">{d.reason}</span>
                    <span className="text-red-400 font-bold font-mono">-{d.points} pts</span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-slate-500 italic">
                Base calculations based on {metrics.criticalCount} Critical, {metrics.highCount} High, {metrics.mediumCount} Medium findings.
              </div>
            )}
          </div>
        )}
      </div>

      {/* Summary Box */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-lg">
        <h3 className="text-sm font-bold text-slate-200 mb-2">Executive Summary</h3>
        <p className="text-xs text-slate-300 leading-relaxed mb-4">
          {summary?.executiveOverview || scanResult.executiveSummary}
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-3 border-t border-slate-800">
          <div>
            <h4 className="text-xs font-bold text-amber-400 mb-2 flex items-center gap-1.5">
              <AlertTriangle className="w-3.5 h-3.5" />
              Primary Risk Vectors
            </h4>
            <ul className="space-y-1">
              {(summary?.primaryRiskVectors || scanResult.keyRisks).map((risk, i) => (
                <li key={i} className="text-xs text-slate-400 flex items-start gap-1.5">
                  <span className="text-amber-500">•</span>
                  <span>{risk}</span>
                </li>
              ))}
            </ul>
          </div>

          <div>
            <h4 className="text-xs font-bold text-emerald-400 mb-2 flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5" />
              Remediation Roadmap
            </h4>
            <ul className="space-y-1">
              {(summary?.remediationPriorities || scanResult.immediateActions).map((act, i) => (
                <li key={i} className="text-xs text-slate-400 flex items-start gap-1.5">
                  <span className="text-emerald-500">•</span>
                  <span>{act}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
};
