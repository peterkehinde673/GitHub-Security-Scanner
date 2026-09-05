import React from 'react';
import { Shield, FileText, Sparkles, RefreshCw, Github } from 'lucide-react';
import { ScanResult } from '../types';

interface HeaderProps {
  scanResult: ScanResult | null;
  isScanning: boolean;
  onOpenReportModal: () => void;
  onOpenAiChat: () => void;
  onResetScan: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  scanResult,
  isScanning,
  onOpenReportModal,
  onOpenAiChat,
  onResetScan,
}) => {
  return (
    <header className="bg-slate-900 border-b border-slate-800 sticky top-0 z-40">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        {/* Logo & Product Name */}
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-blue-600/20 border border-blue-500/40 flex items-center justify-center text-blue-400">
            <Shield className="w-5 h-5 text-blue-400" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-base font-bold text-slate-100 tracking-tight">
                GitHub Security Scanner
              </h1>
              <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-blue-950 text-blue-300 border border-blue-800">
                MVP v1.0
              </span>
            </div>
            <p className="text-xs text-slate-400 hidden sm:block">
              Deterministic SAST, Secret Detection & Dependency Audit
            </p>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2 sm:gap-3">
          {scanResult && (
            <>
              {/* Score pill */}
              <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-slate-950 border border-slate-800 text-xs">
                <span className="text-slate-400">Score:</span>
                <span
                  className={`font-bold ${
                    scanResult.metrics.score >= 90
                      ? 'text-emerald-400'
                      : scanResult.metrics.score >= 70
                      ? 'text-yellow-400'
                      : scanResult.metrics.score >= 50
                      ? 'text-orange-400'
                      : 'text-red-400'
                  }`}
                >
                  {scanResult.metrics.score}/100 ({scanResult.metrics.grade})
                </span>
              </div>

              {/* Export Report Button */}
              <button
                id="btn-export-report"
                onClick={onOpenReportModal}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold border border-slate-700 transition-colors cursor-pointer"
              >
                <FileText className="w-3.5 h-3.5 text-blue-400" />
                <span className="hidden sm:inline">Export Audit Report</span>
              </button>
            </>
          )}

          {/* AI Security Copilot Button */}
          <button
            id="btn-open-ai-chat"
            onClick={onOpenAiChat}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-purple-950/60 hover:bg-purple-900/80 text-purple-300 text-xs font-semibold border border-purple-800/80 transition-colors cursor-pointer"
          >
            <Sparkles className="w-3.5 h-3.5 text-purple-400" />
            <span className="hidden sm:inline">AI Copilot</span>
          </button>
        </div>
      </div>
    </header>
  );
};
