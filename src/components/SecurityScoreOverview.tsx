import React from 'react';
import { SecurityScanMetrics, ScanResult } from '../types';
import { ShieldAlert, ShieldCheck, AlertOctagon, AlertTriangle, Info, CheckCircle2, Clock, FileCode, Check } from 'lucide-react';

interface SecurityScoreOverviewProps {
  scanResult: ScanResult;
}

export const SecurityScoreOverview: React.FC<SecurityScoreOverviewProps> = ({ scanResult }) => {
  const { metrics, executiveSummary, keyRisks, immediateActions } = scanResult;

  const getGradeColor = (grade: string) => {
    switch (grade) {
      case 'A+':
      case 'A':
        return 'text-emerald-400 border-emerald-500/40 bg-emerald-950/30';
      case 'B':
        return 'text-blue-400 border-blue-500/40 bg-blue-950/30';
      case 'C':
        return 'text-yellow-400 border-yellow-500/40 bg-yellow-950/30';
      case 'D':
        return 'text-orange-400 border-orange-500/40 bg-orange-950/30';
      default:
        return 'text-red-400 border-red-500/40 bg-red-950/30';
    }
  };

  const getScoreColor = (score: number) => {
    if (score >= 85) return 'from-emerald-500 to-teal-500';
    if (score >= 70) return 'from-blue-500 to-cyan-500';
    if (score >= 50) return 'from-yellow-500 to-amber-500';
    return 'from-red-500 to-rose-600';
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 mb-6">
      {/* Score and Grade Card */}
      <div className="lg:col-span-4 bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-lg flex flex-col justify-between">
        <div>
          <div className="flex items-center justify-between mb-4">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              Security Posture Score
            </span>
            <div className={`px-2.5 py-1 text-sm font-extrabold rounded-lg border ${getGradeColor(metrics.grade)}`}>
              Grade {metrics.grade}
            </div>
          </div>

          <div className="flex items-end gap-3 mb-4">
            <span className="text-5xl font-black text-slate-100 tracking-tight">
              {metrics.score}
            </span>
            <span className="text-slate-500 text-sm font-semibold pb-1.5">/ 100</span>
          </div>

          {/* Progress Bar */}
          <div className="w-full bg-slate-950 h-2.5 rounded-full overflow-hidden border border-slate-800 mb-5">
            <div
              className={`h-full bg-gradient-to-r ${getScoreColor(metrics.score)} transition-all duration-700 ease-out`}
              style={{ width: `${metrics.score}%` }}
            />
          </div>

          {/* Severity Counters Grid */}
          <div className="grid grid-cols-4 gap-2 text-center">
            <div className="bg-red-950/30 border border-red-900/40 rounded-xl p-2">
              <div className="text-lg font-bold text-red-400">{metrics.criticalCount}</div>
              <div className="text-[10px] font-semibold text-red-300 uppercase">Critical</div>
            </div>
            <div className="bg-orange-950/30 border border-orange-900/40 rounded-xl p-2">
              <div className="text-lg font-bold text-orange-400">{metrics.highCount}</div>
              <div className="text-[10px] font-semibold text-orange-300 uppercase">High</div>
            </div>
            <div className="bg-yellow-950/30 border border-yellow-900/40 rounded-xl p-2">
              <div className="text-lg font-bold text-yellow-400">{metrics.mediumCount}</div>
              <div className="text-[10px] font-semibold text-yellow-300 uppercase">Med</div>
            </div>
            <div className="bg-blue-950/30 border border-blue-900/40 rounded-xl p-2">
              <div className="text-lg font-bold text-blue-400">{metrics.lowCount}</div>
              <div className="text-[10px] font-semibold text-blue-300 uppercase">Low</div>
            </div>
          </div>
        </div>

        {/* Scan Meta */}
        <div className="flex items-center justify-between text-[11px] text-slate-500 pt-4 mt-4 border-t border-slate-800">
          <div className="flex items-center gap-1">
            <FileCode className="w-3.5 h-3.5" />
            <span>{metrics.filesAnalyzed} files ({metrics.linesAnalyzed} lines)</span>
          </div>
          <div className="flex items-center gap-1">
            <Clock className="w-3.5 h-3.5" />
            <span>{(metrics.scanDurationMs / 1000).toFixed(2)}s</span>
          </div>
        </div>
      </div>

      {/* Executive Summary & Key Risks */}
      <div className="lg:col-span-8 bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-lg flex flex-col justify-between">
        <div>
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-blue-400" />
              <span>Executive Security Assessment</span>
            </h2>
            <span className="text-xs text-slate-400 font-mono">
              Target: {scanResult.targetName}
            </span>
          </div>

          <p className="text-xs sm:text-sm text-slate-300 leading-relaxed bg-slate-950/60 p-3.5 rounded-xl border border-slate-800/80 mb-4">
            {executiveSummary}
          </p>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {/* Key Risks */}
            <div className="bg-slate-950/40 border border-slate-800/80 rounded-xl p-3">
              <h4 className="text-xs font-semibold text-slate-300 mb-2 flex items-center gap-1.5">
                <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                <span>Primary Risk Vectors</span>
              </h4>
              {keyRisks.length === 0 ? (
                <p className="text-xs text-emerald-400/90 italic flex items-center gap-1.5 py-1">
                  <ShieldCheck className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                  <span>No high-risk vectors or critical vulnerabilities detected.</span>
                </p>
              ) : (
                <ul className="space-y-1.5">
                  {keyRisks.slice(0, 3).map((risk, i) => (
                    <li key={i} className="text-xs text-slate-400 flex items-start gap-1.5">
                      <span className="text-amber-500 font-bold">•</span>
                      <span>{risk}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            {/* Immediate Actions */}
            <div className="bg-slate-950/40 border border-slate-800/80 rounded-xl p-3">
              <h4 className="text-xs font-semibold text-slate-300 mb-2 flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                <span>Remediation Roadmap</span>
              </h4>
              <ul className="space-y-1.5">
                {immediateActions.slice(0, 3).map((action, i) => (
                  <li key={i} className="text-xs text-slate-400 flex items-start gap-1.5">
                    <span className="text-emerald-500 font-bold">•</span>
                    <span>{action}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>

        {/* Scan Coverage & Audit Status */}
        <div className="flex items-center justify-between text-xs text-slate-400 pt-3 mt-3 border-t border-slate-800">
          <span>Scan Coverage:</span>
          <div className="flex items-center gap-2">
            <span className="font-semibold text-slate-200">
              {scanResult.coverage?.isComplete !== false ? 'Complete Audit' : 'Targeted Audit'} (
              {scanResult.coverage?.filesScanned ?? metrics.filesAnalyzed} files scanned)
            </span>
            <div className="w-24 bg-slate-950 h-2 rounded-full overflow-hidden border border-slate-800">
              <div
                className={`h-full ${
                  scanResult.coverage?.isComplete !== false ? 'bg-emerald-500 w-full' : 'bg-amber-500 w-3/4'
                }`}
              />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
