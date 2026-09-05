import React, { useState } from 'react';
import { ScanResult } from '../types';
import { X, Download, Copy, Check, FileJson, FileText } from 'lucide-react';

interface ExportReportModalProps {
  scanResult: ScanResult | null;
  onClose: () => void;
}

export const ExportReportModal: React.FC<ExportReportModalProps> = ({ scanResult, onClose }) => {
  const [format, setFormat] = useState<'markdown' | 'json'>('markdown');
  const [copied, setCopied] = useState(false);

  if (!scanResult) return null;

  const generateMarkdown = () => {
    const summary = scanResult.summary || {
      executiveOverview: scanResult.executiveSummary,
      primaryRiskVectors: scanResult.keyRisks,
      remediationPriorities: scanResult.immediateActions,
    };
    const findingsList = scanResult.findings || scanResult.issues || [];
    const infoCount = scanResult.metrics.informationalCount ?? scanResult.metrics.infoCount ?? 0;
    const totalCount = scanResult.metrics.totalFindings ?? scanResult.metrics.totalIssues ?? findingsList.length;

    return `# Security Assessment Report: ${scanResult.targetName}
**Generated:** ${scanResult.timestamp}
**Target URL:** ${scanResult.targetUrl || 'N/A'}
**Overall Score:** ${scanResult.metrics.score}/100 (Grade: ${scanResult.metrics.grade}) - ${scanResult.metrics.verdict || 'AUDITED'}

---

## Executive Overview
${summary.executiveOverview}

### Primary Risks
${summary.primaryRiskVectors.map((r) => `- ${r}`).join('\n')}

### Recommended Immediate Actions
${summary.remediationPriorities.map((a) => `- ${a}`).join('\n')}

---

## Summary Metrics
- **Critical Findings:** ${scanResult.metrics.criticalCount}
- **High Findings:** ${scanResult.metrics.highCount}
- **Medium Findings:** ${scanResult.metrics.mediumCount}
- **Low / Informational Findings:** ${scanResult.metrics.lowCount + infoCount}
- **Total Findings:** ${totalCount}
- **Files Analyzed:** ${scanResult.metrics.filesAnalyzed}
- **Lines Analyzed:** ${scanResult.metrics.linesAnalyzed}
- **Scan Duration:** ${scanResult.metrics.scanDurationMs}ms

---

## Detailed Findings

${findingsList
  .map(
    (f, idx) => `### ${idx + 1}. [${f.severity}] ${f.title}
- **File:** \`${f.filePath}\` (Lines ${f.startLine}-${f.endLine})
- **Category:** ${f.category}
${f.cwe ? `- **CWE:** ${f.cwe}` : ''}
- **Description:** ${f.description}
- **Impact:** ${f.impact || 'Security risk to application confidentiality/integrity'}
- **Recommendation:** ${f.recommendation}

${f.snippet || f.vulnerableSnippet ? `\`\`\`\n${f.snippet || f.vulnerableSnippet}\n\`\`\`` : ''}
`
  )
  .join('\n\n')}
`;
  };

  const generateJson = () => {
    return JSON.stringify(scanResult, null, 2);
  };

  const handleDownload = () => {
    const content = format === 'markdown' ? generateMarkdown() : generateJson();
    const mimeType = format === 'markdown' ? 'text/markdown' : 'application/json';
    const ext = format === 'markdown' ? 'md' : 'json';
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `security-audit-${scanResult.targetName.replace(/[^a-zA-Z0-9]/g, '_')}.${ext}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleCopy = () => {
    const content = format === 'markdown' ? generateMarkdown() : generateJson();
    navigator.clipboard.writeText(content);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const previewContent = format === 'markdown' ? generateMarkdown() : generateJson();

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-4xl max-h-[90vh] flex flex-col shadow-2xl">
        <div className="flex items-center justify-between p-5 border-b border-slate-800">
          <div>
            <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
              <FileText className="w-5 h-5 text-blue-400" />
              Export Security Audit Report
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Comprehensive report for compliance, security teams, and engineering tickets.
            </p>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="flex items-center justify-between px-5 py-3 bg-slate-950 border-b border-slate-800">
          <div className="flex gap-2">
            <button
              onClick={() => setFormat('markdown')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                format === 'markdown'
                  ? 'bg-blue-600 text-white'
                  : 'bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800'
              }`}
            >
              <FileText className="w-3.5 h-3.5" />
              Markdown (.md)
            </button>
            <button
              onClick={() => setFormat('json')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                format === 'json'
                  ? 'bg-blue-600 text-white'
                  : 'bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800'
              }`}
            >
              <FileJson className="w-3.5 h-3.5" />
              JSON (.json)
            </button>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleCopy}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition-colors cursor-pointer"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              {copied ? 'Copied' : 'Copy'}
            </button>
            <button
              onClick={handleDownload}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium transition-colors cursor-pointer shadow-sm"
            >
              <Download className="w-3.5 h-3.5" />
              Download
            </button>
          </div>
        </div>

        <div className="flex-1 p-5 overflow-auto bg-slate-950/80 font-mono text-xs text-slate-300 whitespace-pre leading-relaxed border-b border-slate-800 selection:bg-blue-600 selection:text-white">
          {previewContent}
        </div>

        <div className="p-4 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold transition-colors cursor-pointer"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
